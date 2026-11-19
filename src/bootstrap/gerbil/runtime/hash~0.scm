(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/hash::timestamp 1795039814)
  (begin
    (define UnboundKeyError::t
      (let ((__tmp172641 (list Error::t)))
        (declare (not safe))
        (make-class-type
         'UnboundKeyError::t
         'UnboundKeyError
         __tmp172641
         '()
         '()
         ':init!)))
    (define UnboundKeyError?
      (let ()
        (declare (not safe))
        (__make-class-predicate UnboundKeyError::t)))
    (define make-UnboundKeyError
      (lambda _%$args171253%_
        (apply make-instance UnboundKeyError::t _%$args171253%_)))
    (define UnboundKeyError-message
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor UnboundKeyError::t 'message)))
    (define UnboundKeyError-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor UnboundKeyError::t 'irritants)))
    (define UnboundKeyError-where
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor UnboundKeyError::t 'where)))
    (define UnboundKeyError-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor UnboundKeyError::t 'continuation)))
    (define UnboundKeyError-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator UnboundKeyError::t 'message)))
    (define UnboundKeyError-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator UnboundKeyError::t 'irritants)))
    (define UnboundKeyError-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator UnboundKeyError::t 'where)))
    (define UnboundKeyError-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator UnboundKeyError::t 'continuation)))
    (define &UnboundKeyError-message
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor UnboundKeyError::t 'message)))
    (define &UnboundKeyError-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor UnboundKeyError::t 'irritants)))
    (define &UnboundKeyError-where
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor UnboundKeyError::t 'where)))
    (define &UnboundKeyError-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         UnboundKeyError::t
         'continuation)))
    (define &UnboundKeyError-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator UnboundKeyError::t 'message)))
    (define &UnboundKeyError-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator UnboundKeyError::t 'irritants)))
    (define &UnboundKeyError-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator UnboundKeyError::t 'where)))
    (define &UnboundKeyError-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         UnboundKeyError::t
         'continuation)))
    (define UnboundKeyError:::init! Error:::init!)
    (let ()
      (declare (not safe))
      (__bind-method!__%
       UnboundKeyError::t
       ':init!
       UnboundKeyError:::init!
       '#f))
    (define raise-unbound-key-error
      (lambda (_%where171127%_ _%message171128%_ . _%irritants171129%_)
        (let ((__tmp172642
               (let ((__obj172633
                      (let ()
                        (declare (not safe))
                        (##structure UnboundKeyError::t '#f '#f '#f '#f))))
                 (let ()
                   (declare (not safe))
                   (UnboundKeyError:::init!
                    __obj172633
                    _%message171128%_
                    'where:
                    _%where171127%_
                    'irritants:
                    _%irritants171129%_))
                 __obj172633)))
          (declare (not safe))
          (raise __tmp172642))))
    (define unbound-key-error? UnboundKeyError?)
    (define HashTable::t
      (let ((__tmp172643 (cons interface-instance::t '())))
        (declare (not safe))
        (make-class-type
         'HashTable::t
         'HashTable
         __tmp172643
         '(clear! copy delete! for-each length new ref set! update!)
         '((final: . #t) (struct: . #t))
         '#f)))
    (define HashTable::interface
      (let ((__obj172635
             (let ()
               (declare (not safe))
               (##structure interface-descriptor::t '#f '#f '#f))))
        (let ()
          (declare (not safe))
          (interface-descriptor:::init!
           __obj172635
           HashTable::t
           '((HashTable::clear! clear!)
             (HashTable::copy copy)
             (HashTable::delete! delete!)
             (HashTable::for-each for-each)
             (HashTable::length length)
             (HashTable::new new)
             (HashTable::ref ref)
             (HashTable::set! set!)
             (HashTable::update! update!))))
        __obj172635))
    (let ()
      (declare (not safe))
      (__class-type-properties-put!
       HashTable::t
       'interface-descriptor:
       HashTable::interface))
    (define make-HashTable
      (lambda (_%obj171125%_)
        (let ()
          (declare (not safe))
          (cast HashTable::interface _%obj171125%_))))
    (define try-HashTable
      (lambda (_%obj171123%_)
        (let ()
          (declare (not safe))
          (try-cast HashTable::interface _%obj171123%_))))
    (define HashTable?
      (lambda (_%obj171121%_)
        (let ((__tmp172644
               (let () (declare (not safe)) (##type-id HashTable::t))))
          (declare (not safe))
          (##structure-direct-instance-of? _%obj171121%_ __tmp172644))))
    (define is-HashTable?
      (lambda (_%obj171118%_)
        (if (let ()
              (declare (not safe))
              (satisfies? HashTable::interface _%obj171118%_))
            '#t
            '#f)))
    (define __HashTable-clear!
      (lambda (_%self154741171101%_)
        (let ((_%self154741171103%_ _%self154741171101%_))
          (declare (not safe))
          (let ((_%object171110171115%_
                 (##unchecked-structure-ref
                  _%self154741171103%_
                  '1
                  '#f
                  'clear!))
                (_%method171111171116%_
                 (##unchecked-structure-ref
                  _%self154741171103%_
                  '2
                  '#f
                  'clear!)))
            (_%method171111171116%_ _%object171110171115%_)))))
    (define ::HashTable-clear!
      (lambda (_%self154742171074%_)
        (let* ((_%self154742171076%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self154742171074%_)))
               (_%self154742171078%_ _%self154742171076%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object171086171091%_
                       (##unchecked-structure-ref
                        _%self154742171078%_
                        '1
                        '#f
                        'clear!))
                      (_%method171087171092%_
                       (##unchecked-structure-ref
                        _%self154742171078%_
                        '2
                        '#f
                        'clear!)))
                  (_%method171087171092%_ _%object171086171091%_)))
              (let ()
                (declare (not safe))
                (let ((_%object171093171098%_
                       (##unchecked-structure-ref
                        _%self154742171078%_
                        '1
                        '#f
                        'clear!))
                      (_%method171094171099%_
                       (##unchecked-structure-ref
                        _%self154742171078%_
                        '2
                        '#f
                        'clear!)))
                  (_%method171094171099%_ _%object171093171098%_)))))))
    (define __HashTable-copy
      (lambda (_%self154986171057%_)
        (let ((_%self154986171059%_ _%self154986171057%_))
          (declare (not safe))
          (let ((_%object171066171071%_
                 (##unchecked-structure-ref _%self154986171059%_ '1 '#f 'copy))
                (_%method171067171072%_
                 (##unchecked-structure-ref
                  _%self154986171059%_
                  '3
                  '#f
                  'copy)))
            (_%method171067171072%_ _%object171066171071%_)))))
    (define ::HashTable-copy
      (lambda (_%self154987171030%_)
        (let* ((_%self154987171032%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self154987171030%_)))
               (_%self154987171034%_ _%self154987171032%_))
          (if __DEBUG
              (let ((__tmp172645
                     (let ()
                       (declare (not safe))
                       (let ((_%object171042171047%_
                              (##unchecked-structure-ref
                               _%self154987171034%_
                               '1
                               '#f
                               'copy))
                             (_%method171043171048%_
                              (##unchecked-structure-ref
                               _%self154987171034%_
                               '3
                               '#f
                               'copy)))
                         (_%method171043171048%_ _%object171042171047%_)))))
                (declare (not safe))
                (cast HashTable::interface __tmp172645))
              (let ()
                (declare (not safe))
                (let ((_%object171049171054%_
                       (##unchecked-structure-ref
                        _%self154987171034%_
                        '1
                        '#f
                        'copy))
                      (_%method171050171055%_
                       (##unchecked-structure-ref
                        _%self154987171034%_
                        '3
                        '#f
                        'copy)))
                  (_%method171050171055%_ _%object171049171054%_)))))))
    (define __HashTable-delete!
      (lambda (_%self155230171012%_ _%key171013%_)
        (let ((_%self155230171015%_ _%self155230171012%_))
          (declare (not safe))
          (let ((_%object171022171027%_
                 (##unchecked-structure-ref
                  _%self155230171015%_
                  '1
                  '#f
                  'delete!))
                (_%method171023171028%_
                 (##unchecked-structure-ref
                  _%self155230171015%_
                  '4
                  '#f
                  'delete!)))
            (_%method171023171028%_ _%object171022171027%_ _%key171013%_)))))
    (define ::HashTable-delete!
      (lambda (_%self155231170984%_ _%key170985%_)
        (let* ((_%self155231170987%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self155231170984%_)))
               (_%self155231170989%_ _%self155231170987%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170997171002%_
                       (##unchecked-structure-ref
                        _%self155231170989%_
                        '1
                        '#f
                        'delete!))
                      (_%method170998171003%_
                       (##unchecked-structure-ref
                        _%self155231170989%_
                        '4
                        '#f
                        'delete!)))
                  (_%method170998171003%_
                   _%object170997171002%_
                   _%key170985%_)))
              (let ()
                (declare (not safe))
                (let ((_%object171004171009%_
                       (##unchecked-structure-ref
                        _%self155231170989%_
                        '1
                        '#f
                        'delete!))
                      (_%method171005171010%_
                       (##unchecked-structure-ref
                        _%self155231170989%_
                        '4
                        '#f
                        'delete!)))
                  (_%method171005171010%_
                   _%object171004171009%_
                   _%key170985%_)))))))
    (define __HashTable-for-each
      (lambda (_%self155474170958%_ _%proc170959%_)
        (let* ((_%self155474170961%_ _%self155474170958%_)
               (_%proc170968%_ _%proc170959%_))
          (declare (not safe))
          (let ((_%object170976170981%_
                 (##unchecked-structure-ref
                  _%self155474170961%_
                  '1
                  '#f
                  'for-each))
                (_%method170977170982%_
                 (##unchecked-structure-ref
                  _%self155474170961%_
                  '5
                  '#f
                  'for-each)))
            (_%method170977170982%_ _%object170976170981%_ _%proc170968%_)))))
    (define ::HashTable-for-each
      (lambda (_%self155475170920%_ _%proc170921%_)
        (let* ((_%self155475170923%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self155475170920%_)))
               (_%self155475170925%_ _%self155475170923%_))
          (if (procedure? _%proc170921%_)
              (let ((_%proc170934%_ _%proc170921%_))
                (if __DEBUG
                    (let ()
                      (declare (not safe))
                      (let ((_%object170943170948%_
                             (##unchecked-structure-ref
                              _%self155475170925%_
                              '1
                              '#f
                              'for-each))
                            (_%method170944170949%_
                             (##unchecked-structure-ref
                              _%self155475170925%_
                              '5
                              '#f
                              'for-each)))
                        (_%method170944170949%_
                         _%object170943170948%_
                         _%proc170934%_)))
                    (let ()
                      (declare (not safe))
                      (let ((_%object170950170955%_
                             (##unchecked-structure-ref
                              _%self155475170925%_
                              '1
                              '#f
                              'for-each))
                            (_%method170951170956%_
                             (##unchecked-structure-ref
                              _%self155475170925%_
                              '5
                              '#f
                              'for-each)))
                        (_%method170951170956%_
                         _%object170950170955%_
                         _%proc170934%_)))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 '"\"gerbil/runtime/hash.ss\"@30.14-30.18"
                 'contract:
                 'procedure?
                 'value:
                 _%proc170921%_)
                '#!void)))))
    (define __HashTable-length
      (lambda (_%self155718170903%_)
        (let ((_%self155718170905%_ _%self155718170903%_))
          (declare (not safe))
          (let ((_%object170912170917%_
                 (##unchecked-structure-ref
                  _%self155718170905%_
                  '1
                  '#f
                  'length))
                (_%method170913170918%_
                 (##unchecked-structure-ref
                  _%self155718170905%_
                  '6
                  '#f
                  'length)))
            (_%method170913170918%_ _%object170912170917%_)))))
    (define ::HashTable-length
      (lambda (_%self155719170873%_)
        (let* ((_%self155719170875%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self155719170873%_)))
               (_%self155719170877%_ _%self155719170875%_))
          (if __DEBUG
              (let ((_%val170893%_
                     (let ()
                       (declare (not safe))
                       (let ((_%object170885170890%_
                              (##unchecked-structure-ref
                               _%self155719170877%_
                               '1
                               '#f
                               'length))
                             (_%method170886170891%_
                              (##unchecked-structure-ref
                               _%self155719170877%_
                               '6
                               '#f
                               'length)))
                         (_%method170886170891%_ _%object170885170890%_)))))
                (if (fixnum? _%val170893%_)
                    _%val170893%_
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/hash
                       'contract:
                       '(fixnum? val)
                       'value:
                       _%val170893%_)
                      '#!void)))
              (let ()
                (declare (not safe))
                (let ((_%object170895170900%_
                       (##unchecked-structure-ref
                        _%self155719170877%_
                        '1
                        '#f
                        'length))
                      (_%method170896170901%_
                       (##unchecked-structure-ref
                        _%self155719170877%_
                        '6
                        '#f
                        'length)))
                  (_%method170896170901%_ _%object170895170900%_)))))))
    (define __HashTable-new__%
      (lambda (_%self155962170837%_ _%size-hint170838%_)
        (let* ((_%self155962170840%_ _%self155962170837%_)
               (_%size-hint170847%_ _%size-hint170838%_))
          (declare (not safe))
          (let ((_%object170855170860%_
                 (##unchecked-structure-ref _%self155962170840%_ '1 '#f 'new))
                (_%method170856170861%_
                 (##unchecked-structure-ref _%self155962170840%_ '7 '#f 'new)))
            (_%method170856170861%_
             _%object170855170860%_
             _%size-hint170847%_)))))
    (define __HashTable-new__0
      (lambda (_%self155962170866%_)
        (let ((_%size-hint170868%_ '#f))
          (__HashTable-new__% _%self155962170866%_ _%size-hint170868%_))))
    (define __HashTable-new
      (lambda _g172646_
        (let ((_g172647_ (let () (declare (not safe)) (##length _g172646_))))
          (cond ((let () (declare (not safe)) (##fx= _g172647_ 1))
                 (apply __HashTable-new__0 _g172646_))
                ((let () (declare (not safe)) (##fx= _g172647_ 2))
                 (apply __HashTable-new__% _g172646_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __HashTable-new
                  _g172646_))))))
    (define ::HashTable-new__%
      (lambda (_%self155963170782%_ _%size-hint170783%_)
        (let* ((_%self155963170785%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self155963170782%_)))
               (_%self155963170787%_ _%self155963170785%_))
          (if (or (not _%size-hint170783%_) (fixnum? _%size-hint170783%_))
              (let ((_%size-hint170802%_ _%size-hint170783%_))
                (if __DEBUG
                    (let ((__tmp172648
                           (let ()
                             (declare (not safe))
                             (let ((_%object170811170816%_
                                    (##unchecked-structure-ref
                                     _%self155963170787%_
                                     '1
                                     '#f
                                     'new))
                                   (_%method170812170817%_
                                    (##unchecked-structure-ref
                                     _%self155963170787%_
                                     '7
                                     '#f
                                     'new)))
                               (_%method170812170817%_
                                _%object170811170816%_
                                _%size-hint170802%_)))))
                      (declare (not safe))
                      (cast HashTable::interface __tmp172648))
                    (let ()
                      (declare (not safe))
                      (let ((_%object170818170823%_
                             (##unchecked-structure-ref
                              _%self155963170787%_
                              '1
                              '#f
                              'new))
                            (_%method170819170824%_
                             (##unchecked-structure-ref
                              _%self155963170787%_
                              '7
                              '#f
                              'new)))
                        (_%method170819170824%_
                         _%object170818170823%_
                         _%size-hint170802%_)))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 '"\"gerbil/runtime/hash.ss\"@32.9-32.18"
                 'contract:
                 '(? (or not fixnum?))
                 'value:
                 _%size-hint170783%_)
                '#!void)))))
    (define ::HashTable-new__0
      (lambda (_%self155963170829%_)
        (let ((_%size-hint170831%_ '#f))
          (::HashTable-new__% _%self155963170829%_ _%size-hint170831%_))))
    (define ::HashTable-new
      (lambda _g172649_
        (let ((_g172650_ (let () (declare (not safe)) (##length _g172649_))))
          (cond ((let () (declare (not safe)) (##fx= _g172650_ 1))
                 (apply ::HashTable-new__0 _g172649_))
                ((let () (declare (not safe)) (##fx= _g172650_ 2))
                 (apply ::HashTable-new__% _g172649_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  ::HashTable-new
                  _g172649_))))))
    (define __HashTable-ref
      (lambda (_%self156206170762%_ _%key170763%_ _%default170764%_)
        (let ((_%self156206170766%_ _%self156206170762%_))
          (declare (not safe))
          (let ((_%object170773170778%_
                 (##unchecked-structure-ref _%self156206170766%_ '1 '#f 'ref))
                (_%method170774170779%_
                 (##unchecked-structure-ref _%self156206170766%_ '8 '#f 'ref)))
            (_%method170774170779%_
             _%object170773170778%_
             _%key170763%_
             _%default170764%_)))))
    (define ::HashTable-ref
      (lambda (_%self156207170733%_ _%key170734%_ _%default170735%_)
        (let* ((_%self156207170737%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self156207170733%_)))
               (_%self156207170739%_ _%self156207170737%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170747170752%_
                       (##unchecked-structure-ref
                        _%self156207170739%_
                        '1
                        '#f
                        'ref))
                      (_%method170748170753%_
                       (##unchecked-structure-ref
                        _%self156207170739%_
                        '8
                        '#f
                        'ref)))
                  (_%method170748170753%_
                   _%object170747170752%_
                   _%key170734%_
                   _%default170735%_)))
              (let ()
                (declare (not safe))
                (let ((_%object170754170759%_
                       (##unchecked-structure-ref
                        _%self156207170739%_
                        '1
                        '#f
                        'ref))
                      (_%method170755170760%_
                       (##unchecked-structure-ref
                        _%self156207170739%_
                        '8
                        '#f
                        'ref)))
                  (_%method170755170760%_
                   _%object170754170759%_
                   _%key170734%_
                   _%default170735%_)))))))
    (define __HashTable-set!
      (lambda (_%self156450170714%_ _%key170715%_ _%value170716%_)
        (let ((_%self156450170718%_ _%self156450170714%_))
          (declare (not safe))
          (let ((_%object170725170730%_
                 (##unchecked-structure-ref _%self156450170718%_ '1 '#f 'set!))
                (_%method170726170731%_
                 (##unchecked-structure-ref
                  _%self156450170718%_
                  '9
                  '#f
                  'set!)))
            (_%method170726170731%_
             _%object170725170730%_
             _%key170715%_
             _%value170716%_)))))
    (define ::HashTable-set!
      (lambda (_%self156451170685%_ _%key170686%_ _%value170687%_)
        (let* ((_%self156451170689%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self156451170685%_)))
               (_%self156451170691%_ _%self156451170689%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170699170704%_
                       (##unchecked-structure-ref
                        _%self156451170691%_
                        '1
                        '#f
                        'set!))
                      (_%method170700170705%_
                       (##unchecked-structure-ref
                        _%self156451170691%_
                        '9
                        '#f
                        'set!)))
                  (_%method170700170705%_
                   _%object170699170704%_
                   _%key170686%_
                   _%value170687%_)))
              (let ()
                (declare (not safe))
                (let ((_%object170706170711%_
                       (##unchecked-structure-ref
                        _%self156451170691%_
                        '1
                        '#f
                        'set!))
                      (_%method170707170712%_
                       (##unchecked-structure-ref
                        _%self156451170691%_
                        '9
                        '#f
                        'set!)))
                  (_%method170707170712%_
                   _%object170706170711%_
                   _%key170686%_
                   _%value170687%_)))))))
    (define __HashTable-update!
      (lambda (_%self156694170657%_
               _%key170658%_
               _%proc170659%_
               _%default170660%_)
        (let* ((_%self156694170662%_ _%self156694170657%_)
               (_%proc170669%_ _%proc170659%_))
          (declare (not safe))
          (let ((_%object170677170682%_
                 (##unchecked-structure-ref
                  _%self156694170662%_
                  '1
                  '#f
                  'update!))
                (_%method170678170683%_
                 (##unchecked-structure-ref
                  _%self156694170662%_
                  '10
                  '#f
                  'update!)))
            (_%method170678170683%_
             _%object170677170682%_
             _%key170658%_
             _%proc170669%_
             _%default170660%_)))))
    (define ::HashTable-update!
      (lambda (_%self156695170617%_
               _%key170618%_
               _%proc170619%_
               _%default170620%_)
        (let* ((_%self156695170622%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%self156695170617%_)))
               (_%self156695170624%_ _%self156695170622%_))
          (if (procedure? _%proc170619%_)
              (let ((_%proc170633%_ _%proc170619%_))
                (if __DEBUG
                    (let ()
                      (declare (not safe))
                      (let ((_%object170642170647%_
                             (##unchecked-structure-ref
                              _%self156695170624%_
                              '1
                              '#f
                              'update!))
                            (_%method170643170648%_
                             (##unchecked-structure-ref
                              _%self156695170624%_
                              '10
                              '#f
                              'update!)))
                        (_%method170643170648%_
                         _%object170642170647%_
                         _%key170618%_
                         _%proc170633%_
                         _%default170620%_)))
                    (let ()
                      (declare (not safe))
                      (let ((_%object170649170654%_
                             (##unchecked-structure-ref
                              _%self156695170624%_
                              '1
                              '#f
                              'update!))
                            (_%method170650170655%_
                             (##unchecked-structure-ref
                              _%self156695170624%_
                              '10
                              '#f
                              'update!)))
                        (_%method170650170655%_
                         _%object170649170654%_
                         _%key170618%_
                         _%proc170633%_
                         _%default170620%_)))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 '"\"gerbil/runtime/hash.ss\"@28.17-28.21"
                 'contract:
                 'procedure?
                 'value:
                 _%proc170619%_)
                '#!void)))))
    (define Locker::t
      (let ((__tmp172651 (cons interface-instance::t '())))
        (declare (not safe))
        (make-class-type
         'Locker::t
         'Locker
         __tmp172651
         '(read-lock! read-unlock! write-lock! write-unlock!)
         '((final: . #t) (struct: . #t))
         '#f)))
    (define Locker::interface
      (let ((__obj172637
             (let ()
               (declare (not safe))
               (##structure interface-descriptor::t '#f '#f '#f))))
        (let ()
          (declare (not safe))
          (interface-descriptor:::init!
           __obj172637
           Locker::t
           '((Locker::read-lock! read-lock!)
             (Locker::read-unlock! read-unlock!)
             (Locker::write-lock! write-lock!)
             (Locker::write-unlock! write-unlock!))))
        __obj172637))
    (let ()
      (declare (not safe))
      (__class-type-properties-put!
       Locker::t
       'interface-descriptor:
       Locker::interface))
    (define make-Locker
      (lambda (_%obj170615%_)
        (let () (declare (not safe)) (cast Locker::interface _%obj170615%_))))
    (define try-Locker
      (lambda (_%obj170613%_)
        (let ()
          (declare (not safe))
          (try-cast Locker::interface _%obj170613%_))))
    (define Locker?
      (lambda (_%obj170611%_)
        (let ((__tmp172652
               (let () (declare (not safe)) (##type-id Locker::t))))
          (declare (not safe))
          (##structure-direct-instance-of? _%obj170611%_ __tmp172652))))
    (define is-Locker?
      (lambda (_%obj170608%_)
        (if (let ()
              (declare (not safe))
              (satisfies? Locker::interface _%obj170608%_))
            '#t
            '#f)))
    (define __Locker-read-lock!
      (lambda (_%self156938170591%_)
        (let ((_%self156938170593%_ _%self156938170591%_))
          (declare (not safe))
          (let ((_%object170600170605%_
                 (##unchecked-structure-ref
                  _%self156938170593%_
                  '1
                  '#f
                  'read-lock!))
                (_%method170601170606%_
                 (##unchecked-structure-ref
                  _%self156938170593%_
                  '2
                  '#f
                  'read-lock!)))
            (_%method170601170606%_ _%object170600170605%_)))))
    (define ::Locker-read-lock!
      (lambda (_%self156939170564%_)
        (let* ((_%self156939170566%_
                (let ()
                  (declare (not safe))
                  (cast Locker::interface _%self156939170564%_)))
               (_%self156939170568%_ _%self156939170566%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170576170581%_
                       (##unchecked-structure-ref
                        _%self156939170568%_
                        '1
                        '#f
                        'read-lock!))
                      (_%method170577170582%_
                       (##unchecked-structure-ref
                        _%self156939170568%_
                        '2
                        '#f
                        'read-lock!)))
                  (_%method170577170582%_ _%object170576170581%_)))
              (let ()
                (declare (not safe))
                (let ((_%object170583170588%_
                       (##unchecked-structure-ref
                        _%self156939170568%_
                        '1
                        '#f
                        'read-lock!))
                      (_%method170584170589%_
                       (##unchecked-structure-ref
                        _%self156939170568%_
                        '2
                        '#f
                        'read-lock!)))
                  (_%method170584170589%_ _%object170583170588%_)))))))
    (define __Locker-read-unlock!
      (lambda (_%self157182170547%_)
        (let ((_%self157182170549%_ _%self157182170547%_))
          (declare (not safe))
          (let ((_%object170556170561%_
                 (##unchecked-structure-ref
                  _%self157182170549%_
                  '1
                  '#f
                  'read-unlock!))
                (_%method170557170562%_
                 (##unchecked-structure-ref
                  _%self157182170549%_
                  '3
                  '#f
                  'read-unlock!)))
            (_%method170557170562%_ _%object170556170561%_)))))
    (define ::Locker-read-unlock!
      (lambda (_%self157183170520%_)
        (let* ((_%self157183170522%_
                (let ()
                  (declare (not safe))
                  (cast Locker::interface _%self157183170520%_)))
               (_%self157183170524%_ _%self157183170522%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170532170537%_
                       (##unchecked-structure-ref
                        _%self157183170524%_
                        '1
                        '#f
                        'read-unlock!))
                      (_%method170533170538%_
                       (##unchecked-structure-ref
                        _%self157183170524%_
                        '3
                        '#f
                        'read-unlock!)))
                  (_%method170533170538%_ _%object170532170537%_)))
              (let ()
                (declare (not safe))
                (let ((_%object170539170544%_
                       (##unchecked-structure-ref
                        _%self157183170524%_
                        '1
                        '#f
                        'read-unlock!))
                      (_%method170540170545%_
                       (##unchecked-structure-ref
                        _%self157183170524%_
                        '3
                        '#f
                        'read-unlock!)))
                  (_%method170540170545%_ _%object170539170544%_)))))))
    (define __Locker-write-lock!
      (lambda (_%self157426170503%_)
        (let ((_%self157426170505%_ _%self157426170503%_))
          (declare (not safe))
          (let ((_%object170512170517%_
                 (##unchecked-structure-ref
                  _%self157426170505%_
                  '1
                  '#f
                  'write-lock!))
                (_%method170513170518%_
                 (##unchecked-structure-ref
                  _%self157426170505%_
                  '4
                  '#f
                  'write-lock!)))
            (_%method170513170518%_ _%object170512170517%_)))))
    (define ::Locker-write-lock!
      (lambda (_%self157427170476%_)
        (let* ((_%self157427170478%_
                (let ()
                  (declare (not safe))
                  (cast Locker::interface _%self157427170476%_)))
               (_%self157427170480%_ _%self157427170478%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170488170493%_
                       (##unchecked-structure-ref
                        _%self157427170480%_
                        '1
                        '#f
                        'write-lock!))
                      (_%method170489170494%_
                       (##unchecked-structure-ref
                        _%self157427170480%_
                        '4
                        '#f
                        'write-lock!)))
                  (_%method170489170494%_ _%object170488170493%_)))
              (let ()
                (declare (not safe))
                (let ((_%object170495170500%_
                       (##unchecked-structure-ref
                        _%self157427170480%_
                        '1
                        '#f
                        'write-lock!))
                      (_%method170496170501%_
                       (##unchecked-structure-ref
                        _%self157427170480%_
                        '4
                        '#f
                        'write-lock!)))
                  (_%method170496170501%_ _%object170495170500%_)))))))
    (define __Locker-write-unlock!
      (lambda (_%self157670170459%_)
        (let ((_%self157670170461%_ _%self157670170459%_))
          (declare (not safe))
          (let ((_%object170468170473%_
                 (##unchecked-structure-ref
                  _%self157670170461%_
                  '1
                  '#f
                  'write-unlock!))
                (_%method170469170474%_
                 (##unchecked-structure-ref
                  _%self157670170461%_
                  '5
                  '#f
                  'write-unlock!)))
            (_%method170469170474%_ _%object170468170473%_)))))
    (define ::Locker-write-unlock!
      (lambda (_%self157671170432%_)
        (let* ((_%self157671170434%_
                (let ()
                  (declare (not safe))
                  (cast Locker::interface _%self157671170432%_)))
               (_%self157671170436%_ _%self157671170434%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object170444170449%_
                       (##unchecked-structure-ref
                        _%self157671170436%_
                        '1
                        '#f
                        'write-unlock!))
                      (_%method170445170450%_
                       (##unchecked-structure-ref
                        _%self157671170436%_
                        '5
                        '#f
                        'write-unlock!)))
                  (_%method170445170450%_ _%object170444170449%_)))
              (let ()
                (declare (not safe))
                (let ((_%object170451170456%_
                       (##unchecked-structure-ref
                        _%self157671170436%_
                        '1
                        '#f
                        'write-unlock!))
                      (_%method170452170457%_
                       (##unchecked-structure-ref
                        _%self157671170436%_
                        '5
                        '#f
                        'write-unlock!)))
                  (_%method170452170457%_ _%object170451170456%_)))))))
    (define __wrap-hash
      (lambda (_%proc170418%_)
        (let ((_%proc170421%_ _%proc170418%_))
          (lambda (_%self170430%_)
            (let ((__tmp172653
                   (let ()
                     (declare (not safe))
                     (_%proc170421%_ _%self170430%_))))
              (declare (not safe))
              (cast HashTable::interface __tmp172653))))))
    (define wrap-hash
      (lambda (_%proc170404%_)
        (if (procedure? _%proc170404%_)
            (let ((_%proc170408%_ _%proc170404%_))
              (__wrap-hash _%proc170408%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/hash.ss\"@42.18-42.22"
               'contract:
               'procedure?
               'value:
               _%proc170404%_)
              '#!void))))
    (define __wrap-hash-new
      (lambda (_%proc170378%_)
        (let* ((_%proc170381%_ _%proc170378%_)
               (_%$%opt-lambda170389170394%_
                (lambda (_%self170391%_ _%size-hint170392%_)
                  (let ((__tmp172654
                         (let ()
                           (declare (not safe))
                           (_%proc170381%_
                            _%self170391%_
                            _%size-hint170392%_))))
                    (declare (not safe))
                    (cast HashTable::interface __tmp172654)))))
          (lambda _g172655_
            (let ((_g172656_
                   (let () (declare (not safe)) (##length _g172655_))))
              (cond ((let () (declare (not safe)) (##fx= _g172656_ 1))
                     (apply (lambda (_%self170397%_)
                              (let ((_%size-hint170399%_ '#f))
                                (_%$%opt-lambda170389170394%_
                                 _%self170397%_
                                 _%size-hint170399%_)))
                            _g172655_))
                    ((let () (declare (not safe)) (##fx= _g172656_ 2))
                     (apply _%$%opt-lambda170389170394%_ _g172655_))
                    (else
                     (##raise-wrong-number-of-arguments-exception
                      'case-lambda-dispatch
                      _g172655_))))))))
    (define wrap-hash-new
      (lambda (_%proc170364%_)
        (if (procedure? _%proc170364%_)
            (let ((_%proc170368%_ _%proc170364%_))
              (__wrap-hash-new _%proc170368%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/hash.ss\"@46.22-46.26"
               'contract:
               'procedure?
               'value:
               _%proc170364%_)
              '#!void))))
    (let* ((_%klass170327%_ __table::t)
           (_%id170330%_ 'HashTable::ref)
           (_%proc170333%_ raw-table-ref)
           (_%rebind?170336%_ '#f)
           (_%id170341%_ _%id170330%_)
           (_%proc170354%_ _%proc170333%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170327%_
       _%id170341%_
       _%proc170354%_
       _%rebind?170336%_))
    (let* ((_%klass170290%_ __table::t)
           (_%id170293%_ 'HashTable::set!)
           (_%proc170296%_ raw-table-set!)
           (_%rebind?170299%_ '#f)
           (_%id170304%_ _%id170293%_)
           (_%proc170317%_ _%proc170296%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170290%_
       _%id170304%_
       _%proc170317%_
       _%rebind?170299%_))
    (let* ((_%klass170253%_ __table::t)
           (_%id170256%_ 'HashTable::update!)
           (_%proc170259%_ raw-table-update!)
           (_%rebind?170262%_ '#f)
           (_%id170267%_ _%id170256%_)
           (_%proc170280%_ _%proc170259%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170253%_
       _%id170267%_
       _%proc170280%_
       _%rebind?170262%_))
    (let* ((_%klass170216%_ __table::t)
           (_%id170219%_ 'HashTable::delete!)
           (_%proc170222%_ raw-table-delete!)
           (_%rebind?170225%_ '#f)
           (_%id170230%_ _%id170219%_)
           (_%proc170243%_ _%proc170222%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170216%_
       _%id170230%_
       _%proc170243%_
       _%rebind?170225%_))
    (let* ((_%klass170179%_ __table::t)
           (_%id170182%_ 'HashTable::for-each)
           (_%proc170185%_ raw-table-for-each)
           (_%rebind?170188%_ '#f)
           (_%id170193%_ _%id170182%_)
           (_%proc170206%_ _%proc170185%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170179%_
       _%id170193%_
       _%proc170206%_
       _%rebind?170188%_))
    (let* ((_%klass170142%_ __table::t)
           (_%id170145%_ 'HashTable::length)
           (_%proc170148%_ &raw-table-count)
           (_%rebind?170151%_ '#f)
           (_%id170156%_ _%id170145%_)
           (_%proc170169%_ _%proc170148%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170142%_
       _%id170156%_
       _%proc170169%_
       _%rebind?170151%_))
    (let* ((_%klass170090%_ __table::t)
           (_%id170093%_ 'HashTable::copy)
           (_%proc170113%_
            (let* ((_%proc170096%_ raw-table-copy)
                   (_%proc170101%_ _%proc170096%_))
              (__wrap-hash _%proc170101%_)))
           (_%rebind?170116%_ '#f)
           (_%id170121%_ _%id170093%_))
      (if (procedure? _%proc170113%_)
          (let ((_%proc170132%_ _%proc170113%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass170090%_
             _%id170121%_
             _%proc170132%_
             _%rebind?170116%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc170113%_)
            '#!void)))
    (let* ((_%klass170038%_ __table::t)
           (_%id170041%_ 'HashTable::new)
           (_%proc170061%_
            (let* ((_%proc170044%_ raw-table-new)
                   (_%proc170049%_ _%proc170044%_))
              (__wrap-hash-new _%proc170049%_)))
           (_%rebind?170064%_ '#f)
           (_%id170069%_ _%id170041%_))
      (if (procedure? _%proc170061%_)
          (let ((_%proc170080%_ _%proc170061%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass170038%_
             _%id170069%_
             _%proc170080%_
             _%rebind?170064%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc170061%_)
            '#!void)))
    (let* ((_%klass170001%_ __table::t)
           (_%id170004%_ 'HashTable::clear!)
           (_%proc170007%_ raw-table-clear!)
           (_%rebind?170010%_ '#f)
           (_%id170015%_ _%id170004%_)
           (_%proc170028%_ _%proc170007%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass170001%_
       _%id170015%_
       _%proc170028%_
       _%rebind?170010%_))
    (let* ((_%klass169964%_ __gc-table::t)
           (_%id169967%_ 'HashTable::ref)
           (_%proc169970%_ gc-table-ref)
           (_%rebind?169973%_ '#f)
           (_%id169978%_ _%id169967%_)
           (_%proc169991%_ _%proc169970%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169964%_
       _%id169978%_
       _%proc169991%_
       _%rebind?169973%_))
    (let* ((_%klass169927%_ __gc-table::t)
           (_%id169930%_ 'HashTable::set!)
           (_%proc169933%_ gc-table-set!)
           (_%rebind?169936%_ '#f)
           (_%id169941%_ _%id169930%_)
           (_%proc169954%_ _%proc169933%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169927%_
       _%id169941%_
       _%proc169954%_
       _%rebind?169936%_))
    (let* ((_%klass169890%_ __gc-table::t)
           (_%id169893%_ 'HashTable::update!)
           (_%proc169896%_ gc-table-update!)
           (_%rebind?169899%_ '#f)
           (_%id169904%_ _%id169893%_)
           (_%proc169917%_ _%proc169896%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169890%_
       _%id169904%_
       _%proc169917%_
       _%rebind?169899%_))
    (let* ((_%klass169853%_ __gc-table::t)
           (_%id169856%_ 'HashTable::delete!)
           (_%proc169859%_ gc-table-delete!)
           (_%rebind?169862%_ '#f)
           (_%id169867%_ _%id169856%_)
           (_%proc169880%_ _%proc169859%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169853%_
       _%id169867%_
       _%proc169880%_
       _%rebind?169862%_))
    (let* ((_%klass169816%_ __gc-table::t)
           (_%id169819%_ 'HashTable::for-each)
           (_%proc169822%_ gc-table-for-each)
           (_%rebind?169825%_ '#f)
           (_%id169830%_ _%id169819%_)
           (_%proc169843%_ _%proc169822%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169816%_
       _%id169830%_
       _%proc169843%_
       _%rebind?169825%_))
    (let* ((_%klass169779%_ __gc-table::t)
           (_%id169782%_ 'HashTable::length)
           (_%proc169785%_ gc-table-length)
           (_%rebind?169788%_ '#f)
           (_%id169793%_ _%id169782%_)
           (_%proc169806%_ _%proc169785%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169779%_
       _%id169793%_
       _%proc169806%_
       _%rebind?169788%_))
    (let* ((_%klass169727%_ __gc-table::t)
           (_%id169730%_ 'HashTable::copy)
           (_%proc169750%_
            (let* ((_%proc169733%_ gc-table-copy)
                   (_%proc169738%_ _%proc169733%_))
              (__wrap-hash _%proc169738%_)))
           (_%rebind?169753%_ '#f)
           (_%id169758%_ _%id169730%_))
      (if (procedure? _%proc169750%_)
          (let ((_%proc169769%_ _%proc169750%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass169727%_
             _%id169758%_
             _%proc169769%_
             _%rebind?169753%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc169750%_)
            '#!void)))
    (let* ((_%klass169675%_ __gc-table::t)
           (_%id169678%_ 'HashTable::new)
           (_%proc169698%_
            (let* ((_%proc169681%_ gc-table-new)
                   (_%proc169686%_ _%proc169681%_))
              (__wrap-hash-new _%proc169686%_)))
           (_%rebind?169701%_ '#f)
           (_%id169706%_ _%id169678%_))
      (if (procedure? _%proc169698%_)
          (let ((_%proc169717%_ _%proc169698%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass169675%_
             _%id169706%_
             _%proc169717%_
             _%rebind?169701%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc169698%_)
            '#!void)))
    (let* ((_%klass169638%_ __gc-table::t)
           (_%id169641%_ 'HashTable::clear!)
           (_%proc169644%_ gc-table-clear!)
           (_%rebind?169647%_ '#f)
           (_%id169652%_ _%id169641%_)
           (_%proc169665%_ _%proc169644%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169638%_
       _%id169652%_
       _%proc169665%_
       _%rebind?169647%_))
    (define gambit-table-update!
      (lambda (_%table169631%_
               _%key169632%_
               _%update169633%_
               _%default169634%_)
        (let ((_%result169636%_
               (table-ref _%table169631%_ _%key169632%_ _%default169634%_)))
          (table-set!
           _%table169631%_
           _%key169632%_
           (_%update169633%_ _%result169636%_)))))
    (define gambit-table-for-each
      (lambda (_%table169628%_ _%proc169629%_)
        (table-for-each _%proc169629%_ _%table169628%_)))
    (define gambit-table-clear!
      (lambda (_%table169626%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! _%table169626%_ '0 '5 '#f '#f))))
    (let* ((_%klass169589%_ (macro-type-table))
           (_%id169592%_ 'HashTable::ref)
           (_%proc169595%_ table-ref)
           (_%rebind?169598%_ '#f)
           (_%id169603%_ _%id169592%_)
           (_%proc169616%_ _%proc169595%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169589%_
       _%id169603%_
       _%proc169616%_
       _%rebind?169598%_))
    (let* ((_%klass169552%_ (macro-type-table))
           (_%id169555%_ 'HashTable::set!)
           (_%proc169558%_ table-set!)
           (_%rebind?169561%_ '#f)
           (_%id169566%_ _%id169555%_)
           (_%proc169579%_ _%proc169558%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169552%_
       _%id169566%_
       _%proc169579%_
       _%rebind?169561%_))
    (let* ((_%klass169515%_ (macro-type-table))
           (_%id169518%_ 'HashTable::update!)
           (_%proc169521%_ gambit-table-update!)
           (_%rebind?169524%_ '#f)
           (_%id169529%_ _%id169518%_)
           (_%proc169542%_ _%proc169521%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169515%_
       _%id169529%_
       _%proc169542%_
       _%rebind?169524%_))
    (let* ((_%klass169478%_ (macro-type-table))
           (_%id169481%_ 'HashTable::delete!)
           (_%proc169484%_ table-set!)
           (_%rebind?169487%_ '#f)
           (_%id169492%_ _%id169481%_)
           (_%proc169505%_ _%proc169484%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169478%_
       _%id169492%_
       _%proc169505%_
       _%rebind?169487%_))
    (let* ((_%klass169441%_ (macro-type-table))
           (_%id169444%_ 'HashTable::for-each)
           (_%proc169447%_ gambit-table-for-each)
           (_%rebind?169450%_ '#f)
           (_%id169455%_ _%id169444%_)
           (_%proc169468%_ _%proc169447%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169441%_
       _%id169455%_
       _%proc169468%_
       _%rebind?169450%_))
    (let* ((_%klass169404%_ (macro-type-table))
           (_%id169407%_ 'HashTable::length)
           (_%proc169410%_ table-length)
           (_%rebind?169413%_ '#f)
           (_%id169418%_ _%id169407%_)
           (_%proc169431%_ _%proc169410%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169404%_
       _%id169418%_
       _%proc169431%_
       _%rebind?169413%_))
    (let* ((_%klass169352%_ (macro-type-table))
           (_%id169355%_ 'HashTable::copy)
           (_%proc169375%_
            (let* ((_%proc169358%_ table-copy) (_%proc169363%_ _%proc169358%_))
              (__wrap-hash _%proc169363%_)))
           (_%rebind?169378%_ '#f)
           (_%id169383%_ _%id169355%_))
      (if (procedure? _%proc169375%_)
          (let ((_%proc169394%_ _%proc169375%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass169352%_
             _%id169383%_
             _%proc169394%_
             _%rebind?169378%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc169375%_)
            '#!void)))
    (let* ((_%klass169300%_ (macro-type-table))
           (_%id169303%_ 'HashTable::new)
           (_%proc169323%_
            (let* ((_%proc169306%_ table-new) (_%proc169311%_ _%proc169306%_))
              (__wrap-hash-new _%proc169311%_)))
           (_%rebind?169326%_ '#f)
           (_%id169331%_ _%id169303%_))
      (if (procedure? _%proc169323%_)
          (let ((_%proc169342%_ _%proc169323%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass169300%_
             _%id169331%_
             _%proc169342%_
             _%rebind?169326%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc169323%_)
            '#!void)))
    (let* ((_%klass169263%_ (macro-type-table))
           (_%id169266%_ 'HashTable::clear!)
           (_%proc169269%_ gambit-table-clear!)
           (_%rebind?169272%_ '#f)
           (_%id169277%_ _%id169266%_)
           (_%proc169290%_ _%proc169269%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169263%_
       _%id169277%_
       _%proc169290%_
       _%rebind?169272%_))
    (define hash-table::t
      (let* ((_%slots169226%_ '(table count free hash test seed lock))
             (_%slot-vector169228%_ (list->vector (cons '#f _%slots169226%_)))
             (_%slot-table169254%_
              (let ((_%slot-table169230%_
                     (let ()
                       (declare (not safe))
                       (make-symbolic-table__% '#f '0))))
                (let ((__tmp172659
                       (lambda (_%slot169232%_ _%field169233%_)
                         (let ()
                           (declare (not safe))
                           (symbolic-table-set!
                            _%slot-table169230%_
                            _%slot169232%_
                            _%field169233%_))
                         (let ((__tmp172660
                                (let ((_%sym169235%_ _%slot169232%_))
                                  (if (symbol? _%sym169235%_)
                                      (let ((_%sym169240%_ _%sym169235%_))
                                        (declare (not safe))
                                        (__symbol->keyword _%sym169240%_))
                                      (begin
                                        (raise-contract-violation-error
                                         '"contract violation"
                                         'context:
                                         'gerbil/runtime/hash
                                         'contract:
                                         'symbol?
                                         'value:
                                         _%sym169235%_)
                                        '#!void)))))
                           (declare (not safe))
                           (symbolic-table-set!
                            _%slot-table169230%_
                            __tmp172660
                            _%field169233%_))))
                      (__tmp172657
                       (let ((__tmp172658
                              (let ()
                                (declare (not safe))
                                (##length _%slots169226%_))))
                         (declare (not safe))
                         (##iota __tmp172658 '1))))
                  (declare (not safe))
                  (##for-each __tmp172659 _%slots169226%_ __tmp172657))
                _%slot-table169230%_))
             (_%flags169256%_
              (let ()
                (declare (not safe))
                (##fxior type-flag-extensible
                         type-flag-concrete
                         type-flag-id
                         class-type-flag-struct)))
             (_%fields169258%_ '#())
             (_%properties169260%_
              (cons (cons 'direct-slots: _%slots169226%_) '((struct: . #t))))
             (__tmp172661 (cons object::t (cons t::t '()))))
        (declare (not safe))
        (##structure
         class::t
         'hash-table::t
         'hash-table
         _%flags169256%_
         __table::t
         _%fields169258%_
         __tmp172661
         _%slot-vector169228%_
         _%slot-table169254%_
         _%properties169260%_
         '#f
         '#f
         '#f
         '#f)))
    (define gc-hash-table::t
      (let* ((_%slots169189%_ '(gcht immediate))
             (_%slot-vector169191%_ (list->vector (cons '#f _%slots169189%_)))
             (_%slot-table169217%_
              (let ((_%slot-table169193%_
                     (let ()
                       (declare (not safe))
                       (make-symbolic-table__% '#f '0))))
                (let ((__tmp172664
                       (lambda (_%slot169195%_ _%field169196%_)
                         (let ()
                           (declare (not safe))
                           (symbolic-table-set!
                            _%slot-table169193%_
                            _%slot169195%_
                            _%field169196%_))
                         (let ((__tmp172665
                                (let ((_%sym169198%_ _%slot169195%_))
                                  (if (symbol? _%sym169198%_)
                                      (let ((_%sym169203%_ _%sym169198%_))
                                        (declare (not safe))
                                        (__symbol->keyword _%sym169203%_))
                                      (begin
                                        (raise-contract-violation-error
                                         '"contract violation"
                                         'context:
                                         'gerbil/runtime/hash
                                         'contract:
                                         'symbol?
                                         'value:
                                         _%sym169198%_)
                                        '#!void)))))
                           (declare (not safe))
                           (symbolic-table-set!
                            _%slot-table169193%_
                            __tmp172665
                            _%field169196%_))))
                      (__tmp172662
                       (let ((__tmp172663
                              (let ()
                                (declare (not safe))
                                (##length _%slots169189%_))))
                         (declare (not safe))
                         (##iota __tmp172663 '1))))
                  (declare (not safe))
                  (##for-each __tmp172664 _%slots169189%_ __tmp172662))
                _%slot-table169193%_))
             (_%flags169219%_
              (let ()
                (declare (not safe))
                (##fxior type-flag-extensible
                         type-flag-concrete
                         type-flag-id
                         class-type-flag-struct)))
             (_%fields169221%_ '#())
             (_%properties169223%_
              (cons (cons 'direct-slots: _%slots169189%_) '((struct: . #t))))
             (__tmp172666 (cons object::t (cons t::t '()))))
        (declare (not safe))
        (##structure
         class::t
         'gc-hash-table::t
         'gc-hash-table
         _%flags169219%_
         __gc-table::t
         _%fields169221%_
         __tmp172666
         _%slot-vector169191%_
         _%slot-table169217%_
         _%properties169223%_
         '#f
         '#f
         '#f
         '#f)))
    (define locked-hash-table::t
      (let ((__tmp172668 (list))
            (__tmp172667
             (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '()))))
        (declare (not safe))
        (make-class-type
         'locked-hash-table::t
         'locked-hash-table
         __tmp172668
         '(table lock)
         __tmp172667
         '#f)))
    (define locked-hash-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate locked-hash-table::t)))
    (define make-locked-hash-table
      (lambda _%$args169186%_
        (apply make-instance locked-hash-table::t _%$args169186%_)))
    (define locked-hash-table-table
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor locked-hash-table::t 'table)))
    (define locked-hash-table-lock
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor locked-hash-table::t 'lock)))
    (define locked-hash-table-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator locked-hash-table::t 'table)))
    (define locked-hash-table-lock-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator locked-hash-table::t 'lock)))
    (define &locked-hash-table-table
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor locked-hash-table::t 'table)))
    (define &locked-hash-table-lock
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor locked-hash-table::t 'lock)))
    (define &locked-hash-table-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator locked-hash-table::t 'table)))
    (define &locked-hash-table-lock-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator locked-hash-table::t 'lock)))
    (define checked-hash-table::t
      (let ((__tmp172670 (list))
            (__tmp172669
             (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '()))))
        (declare (not safe))
        (make-class-type
         'checked-hash-table::t
         'checked-hash-table
         __tmp172670
         '(table key-check)
         __tmp172669
         '#f)))
    (define checked-hash-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate checked-hash-table::t)))
    (define make-checked-hash-table
      (lambda _%$args169183%_
        (apply make-instance checked-hash-table::t _%$args169183%_)))
    (define checked-hash-table-table
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor checked-hash-table::t 'table)))
    (define checked-hash-table-key-check
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor checked-hash-table::t 'key-check)))
    (define checked-hash-table-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator checked-hash-table::t 'table)))
    (define checked-hash-table-key-check-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator checked-hash-table::t 'key-check)))
    (define &checked-hash-table-table
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor checked-hash-table::t 'table)))
    (define &checked-hash-table-key-check
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         checked-hash-table::t
         'key-check)))
    (define &checked-hash-table-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator checked-hash-table::t 'table)))
    (define &checked-hash-table-key-check-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         checked-hash-table::t
         'key-check)))
    (define eq-hash-table::t
      (let ((__tmp172672 (list hash-table::t))
            (__tmp172671 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'eq-hash-table::t::t
         'eq-hash-table
         __tmp172672
         '()
         __tmp172671
         '#f)))
    (define eq-hash-table?
      (let () (declare (not safe)) (__make-class-predicate eq-hash-table::t)))
    (define make-eq-hash-table
      (lambda _%$args169180%_
        (apply make-instance eq-hash-table::t _%$args169180%_)))
    (define eqv-hash-table::t
      (let ((__tmp172674 (list hash-table::t))
            (__tmp172673 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'eqv-hash-table::t::t
         'eqv-hash-table
         __tmp172674
         '()
         __tmp172673
         '#f)))
    (define eqv-hash-table?
      (let () (declare (not safe)) (__make-class-predicate eqv-hash-table::t)))
    (define make-eqv-hash-table
      (lambda _%$args169177%_
        (apply make-instance eqv-hash-table::t _%$args169177%_)))
    (define symbol-hash-table::t
      (let ((__tmp172676 (list hash-table::t))
            (__tmp172675 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'symbol-hash-table::t::t
         'symbol-hash-table
         __tmp172676
         '()
         __tmp172675
         '#f)))
    (define symbol-hash-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate symbol-hash-table::t)))
    (define make-symbol-hash-table
      (lambda _%$args169174%_
        (apply make-instance symbol-hash-table::t _%$args169174%_)))
    (define string-hash-table::t
      (let ((__tmp172678 (list hash-table::t))
            (__tmp172677 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'string-hash-table::t::t
         'string-hash-table
         __tmp172678
         '()
         __tmp172677
         '#f)))
    (define string-hash-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate string-hash-table::t)))
    (define make-string-hash-table
      (lambda _%$args169171%_
        (apply make-instance string-hash-table::t _%$args169171%_)))
    (define immediate-hash-table::t
      (let ((__tmp172680 (list hash-table::t))
            (__tmp172679 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'immediate-hash-table::t::t
         'immediate-hash-table
         __tmp172680
         '()
         __tmp172679
         '#f)))
    (define immediate-hash-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate immediate-hash-table::t)))
    (define make-immediate-hash-table
      (lambda _%$args169168%_
        (apply make-instance immediate-hash-table::t _%$args169168%_)))
    (let* ((_%klass169131%_ hash-table::t)
           (_%id169134%_ 'HashTable::ref)
           (_%proc169137%_ raw-table-ref)
           (_%rebind?169140%_ '#f)
           (_%id169145%_ _%id169134%_)
           (_%proc169158%_ _%proc169137%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169131%_
       _%id169145%_
       _%proc169158%_
       _%rebind?169140%_))
    (let* ((_%klass169094%_ hash-table::t)
           (_%id169097%_ 'HashTable::set!)
           (_%proc169100%_ raw-table-set!)
           (_%rebind?169103%_ '#f)
           (_%id169108%_ _%id169097%_)
           (_%proc169121%_ _%proc169100%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169094%_
       _%id169108%_
       _%proc169121%_
       _%rebind?169103%_))
    (let* ((_%klass169057%_ hash-table::t)
           (_%id169060%_ 'HashTable::update!)
           (_%proc169063%_ raw-table-update!)
           (_%rebind?169066%_ '#f)
           (_%id169071%_ _%id169060%_)
           (_%proc169084%_ _%proc169063%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169057%_
       _%id169071%_
       _%proc169084%_
       _%rebind?169066%_))
    (let* ((_%klass169020%_ hash-table::t)
           (_%id169023%_ 'HashTable::delete!)
           (_%proc169026%_ raw-table-delete!)
           (_%rebind?169029%_ '#f)
           (_%id169034%_ _%id169023%_)
           (_%proc169047%_ _%proc169026%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass169020%_
       _%id169034%_
       _%proc169047%_
       _%rebind?169029%_))
    (let* ((_%klass168983%_ hash-table::t)
           (_%id168986%_ 'HashTable::for-each)
           (_%proc168989%_ raw-table-for-each)
           (_%rebind?168992%_ '#f)
           (_%id168997%_ _%id168986%_)
           (_%proc169010%_ _%proc168989%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168983%_
       _%id168997%_
       _%proc169010%_
       _%rebind?168992%_))
    (let* ((_%klass168946%_ hash-table::t)
           (_%id168949%_ 'HashTable::length)
           (_%proc168952%_ &raw-table-count)
           (_%rebind?168955%_ '#f)
           (_%id168960%_ _%id168949%_)
           (_%proc168973%_ _%proc168952%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168946%_
       _%id168960%_
       _%proc168973%_
       _%rebind?168955%_))
    (let* ((_%klass168894%_ hash-table::t)
           (_%id168897%_ 'HashTable::copy)
           (_%proc168917%_
            (let* ((_%proc168900%_ raw-table-copy)
                   (_%proc168905%_ _%proc168900%_))
              (__wrap-hash _%proc168905%_)))
           (_%rebind?168920%_ '#f)
           (_%id168925%_ _%id168897%_))
      (if (procedure? _%proc168917%_)
          (let ((_%proc168936%_ _%proc168917%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass168894%_
             _%id168925%_
             _%proc168936%_
             _%rebind?168920%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc168917%_)
            '#!void)))
    (let* ((_%klass168842%_ hash-table::t)
           (_%id168845%_ 'HashTable::new)
           (_%proc168865%_
            (let* ((_%proc168848%_ raw-table-new)
                   (_%proc168853%_ _%proc168848%_))
              (__wrap-hash-new _%proc168853%_)))
           (_%rebind?168868%_ '#f)
           (_%id168873%_ _%id168845%_))
      (if (procedure? _%proc168865%_)
          (let ((_%proc168884%_ _%proc168865%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass168842%_
             _%id168873%_
             _%proc168884%_
             _%rebind?168868%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc168865%_)
            '#!void)))
    (let* ((_%klass168805%_ hash-table::t)
           (_%id168808%_ 'HashTable::clear!)
           (_%proc168811%_ raw-table-clear!)
           (_%rebind?168814%_ '#f)
           (_%id168819%_ _%id168808%_)
           (_%proc168832%_ _%proc168811%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168805%_
       _%id168819%_
       _%proc168832%_
       _%rebind?168814%_))
    (let* ((_%klass168768%_ eq-hash-table::t)
           (_%id168771%_ 'HashTable::ref)
           (_%proc168774%_ eq-table-ref)
           (_%rebind?168777%_ '#f)
           (_%id168782%_ _%id168771%_)
           (_%proc168795%_ _%proc168774%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168768%_
       _%id168782%_
       _%proc168795%_
       _%rebind?168777%_))
    (let* ((_%klass168731%_ eq-hash-table::t)
           (_%id168734%_ 'HashTable::set!)
           (_%proc168737%_ eq-table-set!)
           (_%rebind?168740%_ '#f)
           (_%id168745%_ _%id168734%_)
           (_%proc168758%_ _%proc168737%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168731%_
       _%id168745%_
       _%proc168758%_
       _%rebind?168740%_))
    (let* ((_%klass168694%_ eq-hash-table::t)
           (_%id168697%_ 'HashTable::update!)
           (_%proc168700%_ eq-table-update!)
           (_%rebind?168703%_ '#f)
           (_%id168708%_ _%id168697%_)
           (_%proc168721%_ _%proc168700%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168694%_
       _%id168708%_
       _%proc168721%_
       _%rebind?168703%_))
    (let* ((_%klass168657%_ eq-hash-table::t)
           (_%id168660%_ 'HashTable::delete!)
           (_%proc168663%_ eq-table-delete!)
           (_%rebind?168666%_ '#f)
           (_%id168671%_ _%id168660%_)
           (_%proc168684%_ _%proc168663%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168657%_
       _%id168671%_
       _%proc168684%_
       _%rebind?168666%_))
    (let* ((_%klass168620%_ eqv-hash-table::t)
           (_%id168623%_ 'HashTable::ref)
           (_%proc168626%_ eqv-table-ref)
           (_%rebind?168629%_ '#f)
           (_%id168634%_ _%id168623%_)
           (_%proc168647%_ _%proc168626%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168620%_
       _%id168634%_
       _%proc168647%_
       _%rebind?168629%_))
    (let* ((_%klass168583%_ eqv-hash-table::t)
           (_%id168586%_ 'HashTable::set!)
           (_%proc168589%_ eqv-table-set!)
           (_%rebind?168592%_ '#f)
           (_%id168597%_ _%id168586%_)
           (_%proc168610%_ _%proc168589%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168583%_
       _%id168597%_
       _%proc168610%_
       _%rebind?168592%_))
    (let* ((_%klass168546%_ eqv-hash-table::t)
           (_%id168549%_ 'HashTable::update!)
           (_%proc168552%_ eqv-table-update!)
           (_%rebind?168555%_ '#f)
           (_%id168560%_ _%id168549%_)
           (_%proc168573%_ _%proc168552%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168546%_
       _%id168560%_
       _%proc168573%_
       _%rebind?168555%_))
    (let* ((_%klass168509%_ eqv-hash-table::t)
           (_%id168512%_ 'HashTable::delete!)
           (_%proc168515%_ eqv-table-delete!)
           (_%rebind?168518%_ '#f)
           (_%id168523%_ _%id168512%_)
           (_%proc168536%_ _%proc168515%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168509%_
       _%id168523%_
       _%proc168536%_
       _%rebind?168518%_))
    (let* ((_%klass168472%_ symbol-hash-table::t)
           (_%id168475%_ 'HashTable::ref)
           (_%proc168478%_ symbolic-table-ref)
           (_%rebind?168481%_ '#f)
           (_%id168486%_ _%id168475%_)
           (_%proc168499%_ _%proc168478%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168472%_
       _%id168486%_
       _%proc168499%_
       _%rebind?168481%_))
    (let* ((_%klass168435%_ symbol-hash-table::t)
           (_%id168438%_ 'HashTable::set!)
           (_%proc168441%_ symbolic-table-set!)
           (_%rebind?168444%_ '#f)
           (_%id168449%_ _%id168438%_)
           (_%proc168462%_ _%proc168441%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168435%_
       _%id168449%_
       _%proc168462%_
       _%rebind?168444%_))
    (let* ((_%klass168398%_ symbol-hash-table::t)
           (_%id168401%_ 'HashTable::update!)
           (_%proc168404%_ symbolic-table-update!)
           (_%rebind?168407%_ '#f)
           (_%id168412%_ _%id168401%_)
           (_%proc168425%_ _%proc168404%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168398%_
       _%id168412%_
       _%proc168425%_
       _%rebind?168407%_))
    (let* ((_%klass168361%_ symbol-hash-table::t)
           (_%id168364%_ 'HashTable::delete!)
           (_%proc168367%_ symbolic-table-delete!)
           (_%rebind?168370%_ '#f)
           (_%id168375%_ _%id168364%_)
           (_%proc168388%_ _%proc168367%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168361%_
       _%id168375%_
       _%proc168388%_
       _%rebind?168370%_))
    (let* ((_%klass168324%_ string-hash-table::t)
           (_%id168327%_ 'HashTable::ref)
           (_%proc168330%_ string-table-ref)
           (_%rebind?168333%_ '#f)
           (_%id168338%_ _%id168327%_)
           (_%proc168351%_ _%proc168330%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168324%_
       _%id168338%_
       _%proc168351%_
       _%rebind?168333%_))
    (let* ((_%klass168287%_ string-hash-table::t)
           (_%id168290%_ 'HashTable::set!)
           (_%proc168293%_ string-table-set!)
           (_%rebind?168296%_ '#f)
           (_%id168301%_ _%id168290%_)
           (_%proc168314%_ _%proc168293%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168287%_
       _%id168301%_
       _%proc168314%_
       _%rebind?168296%_))
    (let* ((_%klass168250%_ string-hash-table::t)
           (_%id168253%_ 'HashTable::update!)
           (_%proc168256%_ string-table-update!)
           (_%rebind?168259%_ '#f)
           (_%id168264%_ _%id168253%_)
           (_%proc168277%_ _%proc168256%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168250%_
       _%id168264%_
       _%proc168277%_
       _%rebind?168259%_))
    (let* ((_%klass168213%_ string-hash-table::t)
           (_%id168216%_ 'HashTable::delete!)
           (_%proc168219%_ string-table-delete!)
           (_%rebind?168222%_ '#f)
           (_%id168227%_ _%id168216%_)
           (_%proc168240%_ _%proc168219%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168213%_
       _%id168227%_
       _%proc168240%_
       _%rebind?168222%_))
    (let* ((_%klass168176%_ immediate-hash-table::t)
           (_%id168179%_ 'HashTable::ref)
           (_%proc168182%_ immediate-table-ref)
           (_%rebind?168185%_ '#f)
           (_%id168190%_ _%id168179%_)
           (_%proc168203%_ _%proc168182%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168176%_
       _%id168190%_
       _%proc168203%_
       _%rebind?168185%_))
    (let* ((_%klass168139%_ immediate-hash-table::t)
           (_%id168142%_ 'HashTable::set!)
           (_%proc168145%_ immediate-table-set!)
           (_%rebind?168148%_ '#f)
           (_%id168153%_ _%id168142%_)
           (_%proc168166%_ _%proc168145%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168139%_
       _%id168153%_
       _%proc168166%_
       _%rebind?168148%_))
    (let* ((_%klass168102%_ immediate-hash-table::t)
           (_%id168105%_ 'HashTable::update!)
           (_%proc168108%_ immediate-table-update!)
           (_%rebind?168111%_ '#f)
           (_%id168116%_ _%id168105%_)
           (_%proc168129%_ _%proc168108%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168102%_
       _%id168116%_
       _%proc168129%_
       _%rebind?168111%_))
    (let* ((_%klass168065%_ immediate-hash-table::t)
           (_%id168068%_ 'HashTable::delete!)
           (_%proc168071%_ immediate-table-delete!)
           (_%rebind?168074%_ '#f)
           (_%id168079%_ _%id168068%_)
           (_%proc168092%_ _%proc168071%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168065%_
       _%id168079%_
       _%proc168092%_
       _%rebind?168074%_))
    (let* ((_%klass168028%_ gc-hash-table::t)
           (_%id168031%_ 'HashTable::ref)
           (_%proc168034%_ gc-table-ref)
           (_%rebind?168037%_ '#f)
           (_%id168042%_ _%id168031%_)
           (_%proc168055%_ _%proc168034%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass168028%_
       _%id168042%_
       _%proc168055%_
       _%rebind?168037%_))
    (let* ((_%klass167991%_ gc-hash-table::t)
           (_%id167994%_ 'HashTable::set!)
           (_%proc167997%_ gc-table-set!)
           (_%rebind?168000%_ '#f)
           (_%id168005%_ _%id167994%_)
           (_%proc168018%_ _%proc167997%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass167991%_
       _%id168005%_
       _%proc168018%_
       _%rebind?168000%_))
    (let* ((_%klass167954%_ gc-hash-table::t)
           (_%id167957%_ 'HashTable::update!)
           (_%proc167960%_ gc-table-update!)
           (_%rebind?167963%_ '#f)
           (_%id167968%_ _%id167957%_)
           (_%proc167981%_ _%proc167960%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass167954%_
       _%id167968%_
       _%proc167981%_
       _%rebind?167963%_))
    (let* ((_%klass167917%_ gc-hash-table::t)
           (_%id167920%_ 'HashTable::delete!)
           (_%proc167923%_ gc-table-delete!)
           (_%rebind?167926%_ '#f)
           (_%id167931%_ _%id167920%_)
           (_%proc167944%_ _%proc167923%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass167917%_
       _%id167931%_
       _%proc167944%_
       _%rebind?167926%_))
    (let* ((_%klass167880%_ gc-hash-table::t)
           (_%id167883%_ 'HashTable::for-each)
           (_%proc167886%_ gc-table-for-each)
           (_%rebind?167889%_ '#f)
           (_%id167894%_ _%id167883%_)
           (_%proc167907%_ _%proc167886%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass167880%_
       _%id167894%_
       _%proc167907%_
       _%rebind?167889%_))
    (let* ((_%klass167843%_ gc-hash-table::t)
           (_%id167846%_ 'HashTable::length)
           (_%proc167849%_ gc-table-length)
           (_%rebind?167852%_ '#f)
           (_%id167857%_ _%id167846%_)
           (_%proc167870%_ _%proc167849%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass167843%_
       _%id167857%_
       _%proc167870%_
       _%rebind?167852%_))
    (let* ((_%klass167791%_ gc-hash-table::t)
           (_%id167794%_ 'HashTable::copy)
           (_%proc167814%_
            (let* ((_%proc167797%_ gc-table-copy)
                   (_%proc167802%_ _%proc167797%_))
              (__wrap-hash _%proc167802%_)))
           (_%rebind?167817%_ '#f)
           (_%id167822%_ _%id167794%_))
      (if (procedure? _%proc167814%_)
          (let ((_%proc167833%_ _%proc167814%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass167791%_
             _%id167822%_
             _%proc167833%_
             _%rebind?167817%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc167814%_)
            '#!void)))
    (let* ((_%klass167739%_ gc-hash-table::t)
           (_%id167742%_ 'HashTable::new)
           (_%proc167762%_
            (let* ((_%proc167745%_ gc-table-new)
                   (_%proc167750%_ _%proc167745%_))
              (__wrap-hash-new _%proc167750%_)))
           (_%rebind?167765%_ '#f)
           (_%id167770%_ _%id167742%_))
      (if (procedure? _%proc167762%_)
          (let ((_%proc167781%_ _%proc167762%_))
            (declare (not safe))
            (__bind-method!__%
             _%klass167739%_
             _%id167770%_
             _%proc167781%_
             _%rebind?167765%_))
          (begin
            (raise-contract-violation-error
             '"contract violation"
             'context:
             'gerbil/runtime/hash
             'contract:
             'procedure?
             'value:
             _%proc167762%_)
            '#!void)))
    (let* ((_%klass167702%_ gc-hash-table::t)
           (_%id167705%_ 'HashTable::clear!)
           (_%proc167708%_ gc-table-clear!)
           (_%rebind?167711%_ '#f)
           (_%id167716%_ _%id167705%_)
           (_%proc167729%_ _%proc167708%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass167702%_
       _%id167716%_
       _%proc167729%_
       _%rebind?167711%_))
    (define hash-table? HashTable?)
    (define is-hash-table? is-HashTable?)
    (define _%locked-hash-table::HashTable::ref158536%_
      (lambda (_%self167623%_ _%key167625%_ _%default167626%_)
        (let* ((_%self167629%_ _%self167623%_)
               (_%key167638%_ _%key167625%_)
               (_%default167646%_ _%default167626%_))
          (let ((_%h167655%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167629%_ '1 '#f '#f)))
                (_%l167657%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167629%_ '2 '#f '#f))))
            (let ((__tmp172683
                   (lambda ()
                     (let ((_%self156936167661%_ _%l167657%_))
                       (declare (not safe))
                       (let ((_%object167664167669%_
                              (##unchecked-structure-ref
                               _%self156936167661%_
                               '1
                               '#f
                               'read-lock!))
                             (_%method167665167670%_
                              (##unchecked-structure-ref
                               _%self156936167661%_
                               '2
                               '#f
                               'read-lock!)))
                         (_%method167665167670%_ _%object167664167669%_)))))
                  (__tmp172682
                   (lambda ()
                     (let* ((_%self156204167673%_ _%h167655%_)
                            (_%key167676%_ _%key167638%_)
                            (_%default167679%_ _%default167646%_))
                       (declare (not safe))
                       (let ((_%object167682167687%_
                              (##unchecked-structure-ref
                               _%self156204167673%_
                               '1
                               '#f
                               'ref))
                             (_%method167683167688%_
                              (##unchecked-structure-ref
                               _%self156204167673%_
                               '8
                               '#f
                               'ref)))
                         (_%method167683167688%_
                          _%object167682167687%_
                          _%key167676%_
                          _%default167679%_)))))
                  (__tmp172681
                   (lambda ()
                     (let ((_%self157180167691%_ _%l167657%_))
                       (declare (not safe))
                       (let ((_%object167694167699%_
                              (##unchecked-structure-ref
                               _%self157180167691%_
                               '1
                               '#f
                               'read-unlock!))
                             (_%method167695167700%_
                              (##unchecked-structure-ref
                               _%self157180167691%_
                               '3
                               '#f
                               'read-unlock!)))
                         (_%method167695167700%_ _%object167694167699%_))))))
              (declare (not safe))
              (##dynamic-wind __tmp172683 __tmp172682 __tmp172681))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::ref
       _%locked-hash-table::HashTable::ref158536%_
       '#f))
    (define _%locked-hash-table::HashTable::set!158538%_
      (lambda (_%self167421%_ _%key167423%_ _%value167424%_)
        (let* ((_%self167427%_ _%self167421%_)
               (_%key167436%_ _%key167423%_)
               (_%value167444%_ _%value167424%_))
          (let ((_%h167453%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167427%_ '1 '#f '#f)))
                (_%l167455%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167427%_ '2 '#f '#f))))
            (let ((__tmp172686
                   (lambda ()
                     (let ((_%self157424167459%_ _%l167455%_))
                       (declare (not safe))
                       (let ((_%object167462167467%_
                              (##unchecked-structure-ref
                               _%self157424167459%_
                               '1
                               '#f
                               'write-lock!))
                             (_%method167463167468%_
                              (##unchecked-structure-ref
                               _%self157424167459%_
                               '4
                               '#f
                               'write-lock!)))
                         (_%method167463167468%_ _%object167462167467%_)))))
                  (__tmp172685
                   (lambda ()
                     (let* ((_%self156448167471%_ _%h167453%_)
                            (_%key167474%_ _%key167436%_)
                            (_%value167477%_ _%value167444%_))
                       (declare (not safe))
                       (let ((_%object167480167485%_
                              (##unchecked-structure-ref
                               _%self156448167471%_
                               '1
                               '#f
                               'set!))
                             (_%method167481167486%_
                              (##unchecked-structure-ref
                               _%self156448167471%_
                               '9
                               '#f
                               'set!)))
                         (_%method167481167486%_
                          _%object167480167485%_
                          _%key167474%_
                          _%value167477%_)))))
                  (__tmp172684
                   (lambda ()
                     (let ((_%self157668167489%_ _%l167455%_))
                       (declare (not safe))
                       (let ((_%object167492167497%_
                              (##unchecked-structure-ref
                               _%self157668167489%_
                               '1
                               '#f
                               'write-unlock!))
                             (_%method167493167498%_
                              (##unchecked-structure-ref
                               _%self157668167489%_
                               '5
                               '#f
                               'write-unlock!)))
                         (_%method167493167498%_ _%object167492167497%_))))))
              (declare (not safe))
              (##dynamic-wind __tmp172686 __tmp172685 __tmp172684))
            '#!void))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::set!
       _%locked-hash-table::HashTable::set!158538%_
       '#f))
    (define _%locked-hash-table::HashTable::update!158540%_
      (lambda (_%self167207%_ _%key167209%_ _%update167210%_ _%default167211%_)
        (let* ((_%self167214%_ _%self167207%_)
               (_%key167223%_ _%key167209%_)
               (_%update167231%_ _%update167210%_)
               (_%default167239%_ _%default167211%_))
          (let ((_%h167248%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167214%_ '1 '#f '#f)))
                (_%l167250%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167214%_ '2 '#f '#f))))
            (let ((__tmp172689
                   (lambda ()
                     (let ((_%self157424167254%_ _%l167250%_))
                       (declare (not safe))
                       (let ((_%object167257167262%_
                              (##unchecked-structure-ref
                               _%self157424167254%_
                               '1
                               '#f
                               'write-lock!))
                             (_%method167258167263%_
                              (##unchecked-structure-ref
                               _%self157424167254%_
                               '4
                               '#f
                               'write-lock!)))
                         (_%method167258167263%_ _%object167257167262%_)))))
                  (__tmp172688
                   (lambda ()
                     (let* ((_%self156692167266%_ _%h167248%_)
                            (_%key167269%_ _%key167223%_)
                            (_%proc167272%_ _%update167231%_)
                            (_%default167275%_ _%default167239%_))
                       (declare (not safe))
                       (let ((_%object167278167283%_
                              (##unchecked-structure-ref
                               _%self156692167266%_
                               '1
                               '#f
                               'update!))
                             (_%method167279167284%_
                              (##unchecked-structure-ref
                               _%self156692167266%_
                               '10
                               '#f
                               'update!)))
                         (_%method167279167284%_
                          _%object167278167283%_
                          _%key167269%_
                          _%proc167272%_
                          _%default167275%_)))))
                  (__tmp172687
                   (lambda ()
                     (let ((_%self157668167287%_ _%l167250%_))
                       (declare (not safe))
                       (let ((_%object167290167295%_
                              (##unchecked-structure-ref
                               _%self157668167287%_
                               '1
                               '#f
                               'write-unlock!))
                             (_%method167291167296%_
                              (##unchecked-structure-ref
                               _%self157668167287%_
                               '5
                               '#f
                               'write-unlock!)))
                         (_%method167291167296%_ _%object167290167295%_))))))
              (declare (not safe))
              (##dynamic-wind __tmp172689 __tmp172688 __tmp172687))
            '#!void))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::update!
       _%locked-hash-table::HashTable::update!158540%_
       '#f))
    (define _%locked-hash-table::HashTable::delete!158542%_
      (lambda (_%self167017%_ _%key167019%_)
        (let* ((_%self167022%_ _%self167017%_) (_%key167031%_ _%key167019%_))
          (let ((_%h167040%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167022%_ '1 '#f '#f)))
                (_%l167042%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self167022%_ '2 '#f '#f))))
            (let ((__tmp172692
                   (lambda ()
                     (let ((_%self157424167046%_ _%l167042%_))
                       (declare (not safe))
                       (let ((_%object167049167054%_
                              (##unchecked-structure-ref
                               _%self157424167046%_
                               '1
                               '#f
                               'write-lock!))
                             (_%method167050167055%_
                              (##unchecked-structure-ref
                               _%self157424167046%_
                               '4
                               '#f
                               'write-lock!)))
                         (_%method167050167055%_ _%object167049167054%_)))))
                  (__tmp172691
                   (lambda ()
                     (let* ((_%self155228167058%_ _%h167040%_)
                            (_%key167061%_ _%key167031%_))
                       (declare (not safe))
                       (let ((_%object167064167069%_
                              (##unchecked-structure-ref
                               _%self155228167058%_
                               '1
                               '#f
                               'delete!))
                             (_%method167065167070%_
                              (##unchecked-structure-ref
                               _%self155228167058%_
                               '4
                               '#f
                               'delete!)))
                         (_%method167065167070%_
                          _%object167064167069%_
                          _%key167061%_)))))
                  (__tmp172690
                   (lambda ()
                     (let ((_%self157668167073%_ _%l167042%_))
                       (declare (not safe))
                       (let ((_%object167076167081%_
                              (##unchecked-structure-ref
                               _%self157668167073%_
                               '1
                               '#f
                               'write-unlock!))
                             (_%method167077167082%_
                              (##unchecked-structure-ref
                               _%self157668167073%_
                               '5
                               '#f
                               'write-unlock!)))
                         (_%method167077167082%_ _%object167076167081%_))))))
              (declare (not safe))
              (##dynamic-wind __tmp172692 __tmp172691 __tmp172690))
            '#!void))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::delete!
       _%locked-hash-table::HashTable::delete!158542%_
       '#f))
    (define _%locked-hash-table::HashTable::for-each158544%_
      (lambda (_%self166827%_ _%proc166829%_)
        (let* ((_%self166832%_ _%self166827%_) (_%proc166841%_ _%proc166829%_))
          (let ((_%h166850%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166832%_ '1 '#f '#f)))
                (_%l166852%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166832%_ '2 '#f '#f))))
            (let ((__tmp172695
                   (lambda ()
                     (let ((_%self156936166856%_ _%l166852%_))
                       (declare (not safe))
                       (let ((_%object166859166864%_
                              (##unchecked-structure-ref
                               _%self156936166856%_
                               '1
                               '#f
                               'read-lock!))
                             (_%method166860166865%_
                              (##unchecked-structure-ref
                               _%self156936166856%_
                               '2
                               '#f
                               'read-lock!)))
                         (_%method166860166865%_ _%object166859166864%_)))))
                  (__tmp172694
                   (lambda ()
                     (let* ((_%self155472166868%_ _%h166850%_)
                            (_%proc166871%_ _%proc166841%_))
                       (declare (not safe))
                       (let ((_%object166874166879%_
                              (##unchecked-structure-ref
                               _%self155472166868%_
                               '1
                               '#f
                               'for-each))
                             (_%method166875166880%_
                              (##unchecked-structure-ref
                               _%self155472166868%_
                               '5
                               '#f
                               'for-each)))
                         (_%method166875166880%_
                          _%object166874166879%_
                          _%proc166871%_)))))
                  (__tmp172693
                   (lambda ()
                     (let ((_%self157180166883%_ _%l166852%_))
                       (declare (not safe))
                       (let ((_%object166886166891%_
                              (##unchecked-structure-ref
                               _%self157180166883%_
                               '1
                               '#f
                               'read-unlock!))
                             (_%method166887166892%_
                              (##unchecked-structure-ref
                               _%self157180166883%_
                               '3
                               '#f
                               'read-unlock!)))
                         (_%method166887166892%_ _%object166886166891%_))))))
              (declare (not safe))
              (##dynamic-wind __tmp172695 __tmp172694 __tmp172693))
            '#!void))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::for-each
       _%locked-hash-table::HashTable::for-each158544%_
       '#f))
    (define _%locked-hash-table::HashTable::length158546%_
      (lambda (_%self166642%_)
        (let ((_%self166646%_ _%self166642%_))
          (let ((_%h166656%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166646%_ '1 '#f '#f)))
                (_%l166658%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166646%_ '2 '#f '#f))))
            (let* ((_%$%g166660166662%_
                    (let ((__tmp172698
                           (lambda ()
                             (let ((_%self156936166669%_ _%l166658%_))
                               (declare (not safe))
                               (let ((_%object166672166677%_
                                      (##unchecked-structure-ref
                                       _%self156936166669%_
                                       '1
                                       '#f
                                       'read-lock!))
                                     (_%method166673166678%_
                                      (##unchecked-structure-ref
                                       _%self156936166669%_
                                       '2
                                       '#f
                                       'read-lock!)))
                                 (_%method166673166678%_
                                  _%object166672166677%_)))))
                          (__tmp172697
                           (lambda ()
                             (let ((_%self155716166681%_ _%h166656%_))
                               (declare (not safe))
                               (let ((_%object166684166689%_
                                      (##unchecked-structure-ref
                                       _%self155716166681%_
                                       '1
                                       '#f
                                       'length))
                                     (_%method166685166690%_
                                      (##unchecked-structure-ref
                                       _%self155716166681%_
                                       '6
                                       '#f
                                       'length)))
                                 (_%method166685166690%_
                                  _%object166684166689%_)))))
                          (__tmp172696
                           (lambda ()
                             (let ((_%self157180166693%_ _%l166658%_))
                               (declare (not safe))
                               (let ((_%object166696166701%_
                                      (##unchecked-structure-ref
                                       _%self157180166693%_
                                       '1
                                       '#f
                                       'read-unlock!))
                                     (_%method166697166702%_
                                      (##unchecked-structure-ref
                                       _%self157180166693%_
                                       '3
                                       '#f
                                       'read-unlock!)))
                                 (_%method166697166702%_
                                  _%object166696166701%_))))))
                      (declare (not safe))
                      (##dynamic-wind __tmp172698 __tmp172697 __tmp172696)))
                   (_%val166665%_ _%$%g166660166662%_))
              (if (fixnum? _%val166665%_)
                  _%val166665%_
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/runtime/hash
                     'contract:
                     '(fixnum? val)
                     'value:
                     _%val166665%_)
                    '#!void)))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::length
       _%locked-hash-table::HashTable::length158546%_
       '#f))
    (define _%locked-hash-table::HashTable::copy158548%_
      (lambda (_%self166464%_)
        (let ((_%self166468%_ _%self166464%_))
          (let ((_%h166478%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166468%_ '1 '#f '#f)))
                (_%l166480%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166468%_ '2 '#f '#f))))
            (let ((__tmp172699
                   (let ((__tmp172702
                          (lambda ()
                            (let ((_%self156936166484%_ _%l166480%_))
                              (declare (not safe))
                              (let ((_%object166487166492%_
                                     (##unchecked-structure-ref
                                      _%self156936166484%_
                                      '1
                                      '#f
                                      'read-lock!))
                                    (_%method166488166493%_
                                     (##unchecked-structure-ref
                                      _%self156936166484%_
                                      '2
                                      '#f
                                      'read-lock!)))
                                (_%method166488166493%_
                                 _%object166487166492%_)))))
                         (__tmp172701
                          (lambda ()
                            (let ((_%self154984166496%_ _%h166478%_))
                              (declare (not safe))
                              (let ((_%object166499166504%_
                                     (##unchecked-structure-ref
                                      _%self154984166496%_
                                      '1
                                      '#f
                                      'copy))
                                    (_%method166500166505%_
                                     (##unchecked-structure-ref
                                      _%self154984166496%_
                                      '3
                                      '#f
                                      'copy)))
                                (_%method166500166505%_
                                 _%object166499166504%_)))))
                         (__tmp172700
                          (lambda ()
                            (let ((_%self157180166508%_ _%l166480%_))
                              (declare (not safe))
                              (let ((_%object166511166516%_
                                     (##unchecked-structure-ref
                                      _%self157180166508%_
                                      '1
                                      '#f
                                      'read-unlock!))
                                    (_%method166512166517%_
                                     (##unchecked-structure-ref
                                      _%self157180166508%_
                                      '3
                                      '#f
                                      'read-unlock!)))
                                (_%method166512166517%_
                                 _%object166511166516%_))))))
                     (declare (not safe))
                     (##dynamic-wind __tmp172702 __tmp172701 __tmp172700))))
              (declare (not safe))
              (cast HashTable::interface __tmp172699))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::copy
       _%locked-hash-table::HashTable::copy158548%_
       '#f))
    (define _%locked-hash-table::HashTable::new158550%_
      (lambda (_%self166266%_ _%size-hint166268%_)
        (let ((_%self166271%_ _%self166266%_))
          (if (or (not _%size-hint166268%_) (fixnum? _%size-hint166268%_))
              (let ((_%size-hint166287%_ _%size-hint166268%_))
                (let ((_%h166297%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%self166271%_
                          '1
                          '#f
                          '#f)))
                      (_%l166299%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%self166271%_
                          '2
                          '#f
                          '#f))))
                  (let ((__tmp172703
                         (let ((__tmp172706
                                (lambda ()
                                  (let ((_%self156936166303%_ _%l166299%_))
                                    (declare (not safe))
                                    (let ((_%object166306166311%_
                                           (##unchecked-structure-ref
                                            _%self156936166303%_
                                            '1
                                            '#f
                                            'read-lock!))
                                          (_%method166307166312%_
                                           (##unchecked-structure-ref
                                            _%self156936166303%_
                                            '2
                                            '#f
                                            'read-lock!)))
                                      (_%method166307166312%_
                                       _%object166306166311%_)))))
                               (__tmp172705
                                (lambda ()
                                  (let* ((_%self155960166315%_ _%h166297%_)
                                         (_%size-hint166318%_
                                          _%size-hint166287%_))
                                    (declare (not safe))
                                    (let ((_%object166321166326%_
                                           (##unchecked-structure-ref
                                            _%self155960166315%_
                                            '1
                                            '#f
                                            'new))
                                          (_%method166322166327%_
                                           (##unchecked-structure-ref
                                            _%self155960166315%_
                                            '7
                                            '#f
                                            'new)))
                                      (_%method166322166327%_
                                       _%object166321166326%_
                                       _%size-hint166318%_)))))
                               (__tmp172704
                                (lambda ()
                                  (let ((_%self157180166330%_ _%l166299%_))
                                    (declare (not safe))
                                    (let ((_%object166333166338%_
                                           (##unchecked-structure-ref
                                            _%self157180166330%_
                                            '1
                                            '#f
                                            'read-unlock!))
                                          (_%method166334166339%_
                                           (##unchecked-structure-ref
                                            _%self157180166330%_
                                            '3
                                            '#f
                                            'read-unlock!)))
                                      (_%method166334166339%_
                                       _%object166333166338%_))))))
                           (declare (not safe))
                           (##dynamic-wind
                            __tmp172706
                            __tmp172705
                            __tmp172704))))
                    (declare (not safe))
                    (cast HashTable::interface __tmp172703))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 '"\"gerbil/runtime/hash.ss\"@317.29-317.38"
                 'contract:
                 '(? (or not fixnum?))
                 'value:
                 _%size-hint166268%_)
                '#!void)))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::new
       _%locked-hash-table::HashTable::new158550%_
       '#f))
    (define _%locked-hash-table::HashTable::clear!158552%_
      (lambda (_%self166088%_)
        (let ((_%self166092%_ _%self166088%_))
          (let ((_%h166102%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166092%_ '1 '#f '#f)))
                (_%l166104%_
                 (let ()
                   (declare (not safe))
                   (##unchecked-structure-ref _%self166092%_ '2 '#f '#f))))
            (let ((__tmp172709
                   (lambda ()
                     (let ((_%self157424166108%_ _%l166104%_))
                       (declare (not safe))
                       (let ((_%object166111166116%_
                              (##unchecked-structure-ref
                               _%self157424166108%_
                               '1
                               '#f
                               'write-lock!))
                             (_%method166112166117%_
                              (##unchecked-structure-ref
                               _%self157424166108%_
                               '4
                               '#f
                               'write-lock!)))
                         (_%method166112166117%_ _%object166111166116%_)))))
                  (__tmp172708
                   (lambda ()
                     (let ((_%self154739166120%_ _%h166102%_))
                       (declare (not safe))
                       (let ((_%object166123166128%_
                              (##unchecked-structure-ref
                               _%self154739166120%_
                               '1
                               '#f
                               'clear!))
                             (_%method166124166129%_
                              (##unchecked-structure-ref
                               _%self154739166120%_
                               '2
                               '#f
                               'clear!)))
                         (_%method166124166129%_ _%object166123166128%_)))))
                  (__tmp172707
                   (lambda ()
                     (let ((_%self157668166132%_ _%l166104%_))
                       (declare (not safe))
                       (let ((_%object166135166140%_
                              (##unchecked-structure-ref
                               _%self157668166132%_
                               '1
                               '#f
                               'write-unlock!))
                             (_%method166136166141%_
                              (##unchecked-structure-ref
                               _%self157668166132%_
                               '5
                               '#f
                               'write-unlock!)))
                         (_%method166136166141%_ _%object166135166140%_))))))
              (declare (not safe))
              (##dynamic-wind __tmp172709 __tmp172708 __tmp172707))
            '#!void))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       locked-hash-table::t
       'HashTable::clear!
       _%locked-hash-table::HashTable::clear!158552%_
       '#f))
    (let* ((_%klass165928%_ (macro-type-mutex))
           (_%id165931%_ 'Locker::read-lock!)
           (_%proc165934%_ mutex-lock!)
           (_%rebind?165937%_ '#f)
           (_%id165942%_ _%id165931%_)
           (_%proc165955%_ _%proc165934%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass165928%_
       _%id165942%_
       _%proc165955%_
       _%rebind?165937%_))
    (let* ((_%klass165891%_ (macro-type-mutex))
           (_%id165894%_ 'Locker::read-unlock!)
           (_%proc165897%_ mutex-unlock!)
           (_%rebind?165900%_ '#f)
           (_%id165905%_ _%id165894%_)
           (_%proc165918%_ _%proc165897%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass165891%_
       _%id165905%_
       _%proc165918%_
       _%rebind?165900%_))
    (let* ((_%klass165854%_ (macro-type-mutex))
           (_%id165857%_ 'Locker::write-lock!)
           (_%proc165860%_ mutex-lock!)
           (_%rebind?165863%_ '#f)
           (_%id165868%_ _%id165857%_)
           (_%proc165881%_ _%proc165860%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass165854%_
       _%id165868%_
       _%proc165881%_
       _%rebind?165863%_))
    (let* ((_%klass165817%_ (macro-type-mutex))
           (_%id165820%_ 'Locker::write-unlock!)
           (_%proc165823%_ mutex-unlock!)
           (_%rebind?165826%_ '#f)
           (_%id165831%_ _%id165820%_)
           (_%proc165844%_ _%proc165823%_))
      (declare (not safe))
      (__bind-method!__%
       _%klass165817%_
       _%id165831%_
       _%proc165844%_
       _%rebind?165826%_))
    (define _%checked-hash-table::HashTable::ref158763%_
      (lambda (_%self165758%_ _%key165759%_ _%default165760%_)
        (let* ((_%self165763%_ _%self165758%_)
               (_%key165772%_ _%key165759%_)
               (_%default165780%_ _%default165760%_))
          (declare (not safe))
          (let ((_%h165791%_
                 (##unchecked-structure-ref _%self165763%_ '1 '#f '#f))
                (_%key?165793%_
                 (##unchecked-structure-ref _%self165763%_ '2 '#f '#f)))
            (if (_%key?165793%_ _%key165772%_)
                (let* ((_%self156204165800%_ _%h165791%_)
                       (_%key165803%_ _%key165772%_)
                       (_%default165806%_ _%default165780%_))
                  (declare (not safe))
                  (let ((_%object165809165814%_
                         (##unchecked-structure-ref
                          _%self156204165800%_
                          '1
                          '#f
                          'ref))
                        (_%method165810165815%_
                         (##unchecked-structure-ref
                          _%self156204165800%_
                          '8
                          '#f
                          'ref)))
                    (_%method165810165815%_
                     _%object165809165814%_
                     _%key165803%_
                     _%default165806%_)))
                (begin
                  (raise-contract-violation-error
                   '"invalid key"
                   'context:
                   '&HashTable-ref
                   'value:
                   (cons _%key165772%_ (cons _%default165780%_ '())))
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::ref
       _%checked-hash-table::HashTable::ref158763%_
       '#f))
    (define _%checked-hash-table::HashTable::set!158765%_
      (lambda (_%self165576%_ _%key165577%_ _%value165578%_)
        (let* ((_%self165581%_ _%self165576%_)
               (_%key165590%_ _%key165577%_)
               (_%value165598%_ _%value165578%_))
          (declare (not safe))
          (let ((_%h165609%_
                 (##unchecked-structure-ref _%self165581%_ '1 '#f '#f))
                (_%key?165611%_
                 (##unchecked-structure-ref _%self165581%_ '2 '#f '#f)))
            (if (_%key?165611%_ _%key165590%_)
                (let* ((_%self156448165618%_ _%h165609%_)
                       (_%key165621%_ _%key165590%_)
                       (_%value165624%_ _%value165598%_))
                  (declare (not safe))
                  (let ((_%object165627165632%_
                         (##unchecked-structure-ref
                          _%self156448165618%_
                          '1
                          '#f
                          'set!))
                        (_%method165628165633%_
                         (##unchecked-structure-ref
                          _%self156448165618%_
                          '9
                          '#f
                          'set!)))
                    (_%method165628165633%_
                     _%object165627165632%_
                     _%key165621%_
                     _%value165624%_)))
                (begin
                  (raise-contract-violation-error
                   '"invalid key"
                   'context:
                   '&HashTable-set!
                   'value:
                   (cons _%key165590%_ (cons _%value165598%_ '())))
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::set!
       _%checked-hash-table::HashTable::set!158765%_
       '#f))
    (define _%checked-hash-table::HashTable::update!158767%_
      (lambda (_%self165381%_ _%key165382%_ _%update165383%_ _%default165384%_)
        (let* ((_%self165387%_ _%self165381%_)
               (_%key165396%_ _%key165382%_)
               (_%update165404%_ _%update165383%_)
               (_%default165412%_ _%default165384%_))
          (declare (not safe))
          (let ((_%h165423%_
                 (##unchecked-structure-ref _%self165387%_ '1 '#f '#f))
                (_%key?165425%_
                 (##unchecked-structure-ref _%self165387%_ '2 '#f '#f)))
            (if (_%key?165425%_ _%key165396%_)
                (let* ((_%self156692165433%_ _%h165423%_)
                       (_%key165436%_ _%key165396%_)
                       (_%proc165439%_ _%update165404%_)
                       (_%default165442%_ _%default165412%_))
                  (declare (not safe))
                  (let ((_%object165445165450%_
                         (##unchecked-structure-ref
                          _%self156692165433%_
                          '1
                          '#f
                          'update!))
                        (_%method165446165451%_
                         (##unchecked-structure-ref
                          _%self156692165433%_
                          '10
                          '#f
                          'update!)))
                    (_%method165446165451%_
                     _%object165445165450%_
                     _%key165436%_
                     _%proc165439%_
                     _%default165442%_)))
                (begin
                  (raise-contract-violation-error
                   '"invalid key"
                   'context:
                   '&HashTable-update!
                   'value:
                   (cons _%key165396%_
                         (cons _%update165404%_ (cons _%default165412%_ '()))))
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::update!
       _%checked-hash-table::HashTable::update!158767%_
       '#f))
    (define _%checked-hash-table::HashTable::delete!158769%_
      (lambda (_%self165212%_ _%key165213%_)
        (let* ((_%self165216%_ _%self165212%_) (_%key165225%_ _%key165213%_))
          (declare (not safe))
          (let ((_%h165236%_
                 (##unchecked-structure-ref _%self165216%_ '1 '#f '#f))
                (_%key?165238%_
                 (##unchecked-structure-ref _%self165216%_ '2 '#f '#f)))
            (if (_%key?165238%_ _%key165225%_)
                (let* ((_%self155228165244%_ _%h165236%_)
                       (_%key165247%_ _%key165225%_))
                  (declare (not safe))
                  (let ((_%object165250165255%_
                         (##unchecked-structure-ref
                          _%self155228165244%_
                          '1
                          '#f
                          'delete!))
                        (_%method165251165256%_
                         (##unchecked-structure-ref
                          _%self155228165244%_
                          '4
                          '#f
                          'delete!)))
                    (_%method165251165256%_
                     _%object165250165255%_
                     _%key165247%_)))
                (begin
                  (raise-contract-violation-error
                   '"invalid key"
                   'context:
                   '&HashTable-delete!
                   'value:
                   (cons _%key165225%_ '()))
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::delete!
       _%checked-hash-table::HashTable::delete!158769%_
       '#f))
    (define _%checked-hash-table::HashTable::for-each158771%_
      (lambda (_%self165043%_ _%proc165044%_)
        (let* ((_%self165047%_ _%self165043%_) (_%proc165056%_ _%proc165044%_))
          (declare (not safe))
          (let ((_%h165067%_
                 (##unchecked-structure-ref _%self165047%_ '1 '#f '#f))
                (_%key?165069%_
                 (##unchecked-structure-ref _%self165047%_ '2 '#f '#f)))
            (if '#t
                (let* ((_%self155472165075%_ _%h165067%_)
                       (_%proc165078%_ _%proc165056%_))
                  (declare (not safe))
                  (let ((_%object165081165086%_
                         (##unchecked-structure-ref
                          _%self155472165075%_
                          '1
                          '#f
                          'for-each))
                        (_%method165082165087%_
                         (##unchecked-structure-ref
                          _%self155472165075%_
                          '5
                          '#f
                          'for-each)))
                    (_%method165082165087%_
                     _%object165081165086%_
                     _%proc165078%_)))
                (begin
                  (raise-contract-violation-error
                   '"invalid key"
                   'context:
                   '&HashTable-for-each
                   'value:
                   (cons _%proc165056%_ '()))
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::for-each
       _%checked-hash-table::HashTable::for-each158771%_
       '#f))
    (define _%checked-hash-table::HashTable::length158773%_
      (lambda (_%self164889%_)
        (let ((_%self164892%_ _%self164889%_))
          (declare (not safe))
          (let ((_%h164904%_
                 (##unchecked-structure-ref _%self164892%_ '1 '#f '#f))
                (_%key?164906%_
                 (##unchecked-structure-ref _%self164892%_ '2 '#f '#f)))
            (let ((_%self155716164909%_ _%h164904%_))
              (declare (not safe))
              (let ((_%object164912164917%_
                     (##unchecked-structure-ref
                      _%self155716164909%_
                      '1
                      '#f
                      'length))
                    (_%method164913164918%_
                     (##unchecked-structure-ref
                      _%self155716164909%_
                      '6
                      '#f
                      'length)))
                (_%method164913164918%_ _%object164912164917%_)))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::length
       _%checked-hash-table::HashTable::length158773%_
       '#f))
    (define _%checked-hash-table::HashTable::copy158775%_
      (lambda (_%self164735%_)
        (let ((_%self164738%_ _%self164735%_))
          (declare (not safe))
          (let ((_%h164750%_
                 (##unchecked-structure-ref _%self164738%_ '1 '#f '#f))
                (_%key?164752%_
                 (##unchecked-structure-ref _%self164738%_ '2 '#f '#f)))
            (let ((_%self154984164755%_ _%h164750%_))
              (declare (not safe))
              (let ((_%object164758164763%_
                     (##unchecked-structure-ref
                      _%self154984164755%_
                      '1
                      '#f
                      'copy))
                    (_%method164759164764%_
                     (##unchecked-structure-ref
                      _%self154984164755%_
                      '3
                      '#f
                      'copy)))
                (_%method164759164764%_ _%object164758164763%_)))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::copy
       _%checked-hash-table::HashTable::copy158775%_
       '#f))
    (define _%checked-hash-table::HashTable::new158777%_
      (lambda (_%self164561%_ _%size-hint164562%_)
        (let ((_%self164565%_ _%self164561%_))
          (if (or (not _%size-hint164562%_) (fixnum? _%size-hint164562%_))
              (let ((_%size-hint164581%_ _%size-hint164562%_))
                (declare (not safe))
                (let ((_%h164593%_
                       (##unchecked-structure-ref _%self164565%_ '1 '#f '#f))
                      (_%key?164595%_
                       (##unchecked-structure-ref _%self164565%_ '2 '#f '#f)))
                  (let* ((_%self155960164598%_ _%h164593%_)
                         (_%size-hint164601%_ _%size-hint164581%_))
                    (declare (not safe))
                    (let ((_%object164604164609%_
                           (##unchecked-structure-ref
                            _%self155960164598%_
                            '1
                            '#f
                            'new))
                          (_%method164605164610%_
                           (##unchecked-structure-ref
                            _%self155960164598%_
                            '7
                            '#f
                            'new)))
                      (_%method164605164610%_
                       _%object164604164609%_
                       _%size-hint164601%_)))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 '"\"gerbil/runtime/hash.ss\"@376.35-376.44"
                 'contract:
                 '(? (or not fixnum?))
                 'value:
                 _%size-hint164562%_)
                '#!void)))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::new
       _%checked-hash-table::HashTable::new158777%_
       '#f))
    (define _%checked-hash-table::HashTable::clear!158779%_
      (lambda (_%self164407%_)
        (let ((_%self164410%_ _%self164407%_))
          (declare (not safe))
          (let ((_%h164422%_
                 (##unchecked-structure-ref _%self164410%_ '1 '#f '#f))
                (_%key?164424%_
                 (##unchecked-structure-ref _%self164410%_ '2 '#f '#f)))
            (let ((_%self154739164427%_ _%h164422%_))
              (declare (not safe))
              (let ((_%object164430164435%_
                     (##unchecked-structure-ref
                      _%self154739164427%_
                      '1
                      '#f
                      'clear!))
                    (_%method164431164436%_
                     (##unchecked-structure-ref
                      _%self154739164427%_
                      '2
                      '#f
                      'clear!)))
                (_%method164431164436%_ _%object164430164435%_)))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       checked-hash-table::t
       'HashTable::clear!
       _%checked-hash-table::HashTable::clear!158779%_
       '#f))
    (define make-generic-hash-table__%
      (lambda (_%table164256%_
               _%count164257%_
               _%free164258%_
               _%hash164259%_
               _%test164260%_
               _%seed164261%_
               _%lock164262%_)
        (let ((__tmp172710
               (let () (declare (not safe)) (ensure-lock _%lock164262%_))))
          (declare (not safe))
          (##structure
           hash-table::t
           _%table164256%_
           _%count164257%_
           _%free164258%_
           _%hash164259%_
           _%test164260%_
           _%seed164261%_
           __tmp172710))))
    (define make-generic-hash-table__0
      (lambda (_%table164267%_
               _%count164268%_
               _%free164269%_
               _%hash164270%_
               _%test164271%_
               _%seed164272%_)
        (let ((_%lock164274%_ '#f))
          (make-generic-hash-table__%
           _%table164267%_
           _%count164268%_
           _%free164269%_
           _%hash164270%_
           _%test164271%_
           _%seed164272%_
           _%lock164274%_))))
    (define make-generic-hash-table
      (lambda _g172711_
        (let ((_g172712_ (let () (declare (not safe)) (##length _g172711_))))
          (cond ((let () (declare (not safe)) (##fx= _g172712_ 6))
                 (apply make-generic-hash-table__0 _g172711_))
                ((let () (declare (not safe)) (##fx= _g172712_ 7))
                 (apply make-generic-hash-table__% _g172711_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-generic-hash-table
                  _g172711_))))))
    (define make-hash-table__%
      (lambda (_%@@keywords163683%_
               _%$%size-hint163673163684%_
               _%$%seed163674163685%_
               _%$%test163675163686%_
               _%$%hash163676163687%_
               _%$%lock163677163688%_
               _%$%check163678163689%_
               _%$%weak-keys163679163690%_
               _%$%weak-values163680163691%_)
        (let* ((_%size-hint163693%_
                (if (eq? _%$%size-hint163673163684%_ absent-value)
                    '#f
                    _%$%size-hint163673163684%_))
               (_%seed163695%_
                (if (eq? _%$%seed163674163685%_ absent-value)
                    '#f
                    _%$%seed163674163685%_))
               (_%test163697%_
                (if (eq? _%$%test163675163686%_ absent-value)
                    equal?
                    _%$%test163675163686%_))
               (_%hash163699%_
                (if (eq? _%$%hash163676163687%_ absent-value)
                    '#f
                    _%$%hash163676163687%_))
               (_%lock163701%_
                (if (eq? _%$%lock163677163688%_ absent-value)
                    '#f
                    _%$%lock163677163688%_))
               (_%check163703%_
                (if (eq? _%$%check163678163689%_ absent-value)
                    '#f
                    _%$%check163678163689%_))
               (_%weak-keys163705%_
                (if (eq? _%$%weak-keys163679163690%_ absent-value)
                    '#f
                    _%$%weak-keys163679163690%_))
               (_%weak-values163707%_
                (if (eq? _%$%weak-values163680163691%_ absent-value)
                    '#f
                    _%$%weak-values163680163691%_)))
          (letrec ((_%table-seed163710%_
                    (lambda ()
                      (if (fixnum? _%seed163695%_)
                          _%seed163695%_
                          (random-integer (macro-max-fixnum32)))))
                   (_%__wrap-lock163854%_
                    (lambda (_%ht164229%_)
                      (let ((_%ht164232%_ _%ht164229%_))
                        (if _%lock163701%_
                            (let ((__tmp172713
                                   (let ((__tmp172714
                                          (let ()
                                            (declare (not safe))
                                            (cast Locker::interface
                                                  _%lock163701%_))))
                                     (declare (not safe))
                                     (##structure
                                      locked-hash-table::t
                                      _%ht164232%_
                                      __tmp172714))))
                              (declare (not safe))
                              (cast HashTable::interface __tmp172713))
                            _%ht164232%_))))
                   (_%wrap-lock163855%_
                    (lambda (_%ht164217%_)
                      (let ((_%ht164220%_ _%ht164217%_))
                        (_%__wrap-lock163854%_ _%ht164220%_))))
                   (_%__wrap-checked163977%_
                    (lambda (_%ht164204%_ _%implicit164205%_)
                      (let ((_%ht164208%_ _%ht164204%_))
                        (if _%check163703%_
                            (let ((__tmp172715
                                   (let ((__tmp172716
                                          (if (procedure? _%check163703%_)
                                              _%check163703%_
                                              _%implicit164205%_)))
                                     (declare (not safe))
                                     (##structure
                                      checked-hash-table::t
                                      _%ht164208%_
                                      __tmp172716))))
                              (declare (not safe))
                              (cast HashTable::interface __tmp172715))
                            _%ht164208%_))))
                   (_%wrap-checked163978%_
                    (lambda (_%ht164191%_ _%implicit164192%_)
                      (let ((_%ht164195%_ _%ht164191%_))
                        (_%__wrap-checked163977%_
                         _%ht164195%_
                         _%implicit164192%_))))
                   (_%make163979%_
                    (lambda (_%kons164142%_
                             _%key?164143%_
                             _%hash164144%_
                             _%test164145%_)
                      (let* ((_%size164148%_
                              (let ()
                                (declare (not safe))
                                (raw-table-size-hint->size
                                 _%size-hint163693%_)))
                             (_%table164150%_
                              (let ((__tmp172717 (macro-unused-obj)))
                                (declare (not safe))
                                (##make-vector _%size164148%_ __tmp172717)))
                             (_%ht164152%_
                              (let ((__tmp172718
                                     (_%kons164142%_
                                      _%table164150%_
                                      '0
                                      (let ()
                                        (declare (not safe))
                                        (##fxquotient _%size164148%_ '2))
                                      _%hash164144%_
                                      _%test164145%_
                                      (_%table-seed163710%_)
                                      '#f)))
                                (declare (not safe))
                                (cast HashTable::interface __tmp172718)))
                             (_%ht164174%_
                              (let* ((_%ht164155%_ _%ht164152%_)
                                     (_%ht164159%_ _%ht164155%_))
                                (_%__wrap-lock163854%_ _%ht164159%_)))
                             (_%implicit164177%_ _%key?164143%_)
                             (_%ht164181%_ _%ht164174%_))
                        (_%__wrap-checked163977%_
                         _%ht164181%_
                         _%implicit164177%_))))
                   (_%make-gc-hash-table163980%_
                    (lambda ()
                      (let* ((_%ht164107%_
                              (let ((__tmp172719
                                     (let ()
                                       (declare (not safe))
                                       (make-gc-table__1
                                        _%size-hint163693%_
                                        gc-hash-table::t))))
                                (declare (not safe))
                                (cast HashTable::interface __tmp172719)))
                             (_%ht164125%_
                              (let* ((_%ht164109%_ _%ht164107%_)
                                     (_%ht164113%_ _%ht164109%_))
                                (_%__wrap-lock163854%_ _%ht164113%_)))
                             (_%implicit164128%_ true)
                             (_%ht164132%_ _%ht164125%_))
                        (_%__wrap-checked163977%_
                         _%ht164132%_
                         _%implicit164128%_))))
                   (_%make-gambit-table163981%_
                    (lambda ()
                      (let* ((_%size164050%_
                              (let ((_%$e164047%_ _%size-hint163693%_))
                                (if _%$e164047%_
                                    _%$e164047%_
                                    (macro-absent-obj))))
                             (_%test164055%_
                              (let ((_%$e164052%_ _%test163697%_))
                                (if _%$e164052%_ _%$e164052%_ equal?)))
                             (_%hash164063%_
                              (let ((_%$e164057%_ _%hash163699%_))
                                (if _%$e164057%_
                                    _%$e164057%_
                                    (if (eq? _%test164055%_ eq?)
                                        eq?-hash
                                        (if (eq? _%test164055%_ eqv?)
                                            eqv?-hash
                                            equal?-hash)))))
                             (_%ht164065%_
                              (let ((__tmp172720
                                     (make-table
                                      'size:
                                      _%size164050%_
                                      'test:
                                      _%test164055%_
                                      'hash:
                                      _%hash164063%_
                                      'weak-keys:
                                      _%weak-keys163705%_
                                      'weak-values:
                                      _%weak-values163707%_)))
                                (declare (not safe))
                                (cast HashTable::interface __tmp172720)))
                             (_%ht164088%_
                              (let* ((_%ht164068%_ _%ht164065%_)
                                     (_%ht164072%_ _%ht164068%_))
                                (_%__wrap-lock163854%_ _%ht164072%_)))
                             (_%implicit164091%_ true)
                             (_%ht164095%_ _%ht164088%_))
                        (_%__wrap-checked163977%_
                         _%ht164095%_
                         _%implicit164091%_)))))
            (if (or _%weak-keys163705%_ _%weak-values163707%_)
                (_%make-gambit-table163981%_)
                (if (and (or (eq? _%test163697%_ eq?)
                             (eq? _%test163697%_ ##eq?))
                         (or (not _%hash163699%_)
                             (eq? _%hash163699%_ eq?-hash)
                             (eq? _%hash163699%_ eq-hash))
                         (not _%seed163695%_))
                    (_%make-gc-hash-table163980%_)
                    (if (and (or (eq? _%test163697%_ eq?)
                                 (eq? _%test163697%_ ##eq?))
                             (or (not _%hash163699%_)
                                 (eq? _%hash163699%_ eq?-hash)
                                 (eq? _%hash163699%_ eq-hash)))
                        (_%make163979%_ make-eq-hash-table true eq-hash eq?)
                        (if (and (or (eq? _%test163697%_ eqv?)
                                     (eq? _%test163697%_ ##eqv?))
                                 (or (not _%hash163699%_)
                                     (eq? _%hash163699%_ eqv?-hash)
                                     (eq? _%hash163699%_ eqv-hash)))
                            (_%make163979%_
                             make-eqv-hash-table
                             true
                             eqv-hash
                             eqv?)
                            (if (and (or (eq? _%test163697%_ eq?)
                                         (eq? _%test163697%_ ##eq?))
                                     (or (eq? _%hash163699%_ symbolic-hash)
                                         (eq? _%hash163699%_ ##symbol-hash)))
                                (_%make163979%_
                                 make-symbol-hash-table
                                 symbolic?
                                 symbolic-hash
                                 eq?)
                                (if (and (or (eq? _%test163697%_ eq?)
                                             (eq? _%test163697%_ ##eq?))
                                         (eq? _%hash163699%_ immediate-hash))
                                    (_%make163979%_
                                     make-immediate-hash-table
                                     immediate?
                                     immediate-hash
                                     eq?)
                                    (if (and (or (eq? _%test163697%_ equal?)
                                                 (eq? _%test163697%_ ##equal?)
                                                 (eq? _%test163697%_ string=?)
                                                 (eq? _%test163697%_
                                                      ##string=?))
                                             (or (eq? _%hash163699%_
                                                      string-hash)
                                                 (eq? _%hash163699%_
                                                      ##string=?-hash)))
                                        (_%make163979%_
                                         make-string-hash-table
                                         string?
                                         string-hash
                                         ##string=?)
                                        (if (and (eq? _%test163697%_ equal?)
                                                 (not _%hash163699%_))
                                            (_%make163979%_
                                             make-generic-hash-table
                                             true
                                             equal?-hash
                                             equal?)
                                            (if (procedure? _%test163697%_)
                                                (if (procedure? _%hash163699%_)
                                                    (_%make163979%_
                                                     make-generic-hash-table
                                                     true
                                                     _%hash163699%_
                                                     _%test163697%_)
                                                    (let ()
                                                      (let ()
                                                        (declare (not safe))
                                                        (error '"bad hash table hash function; expected procedure"
                                                               _%hash163699%_))
                                                      '#!void))
                                                (let ()
                                                  (let ()
                                                    (declare (not safe))
                                                    (error '"bad hash table test function; expected procedure"
                                                           _%test163697%_))
                                                  '#!void))))))))))))))
    (define make-hash-table__@
      (lambda (_%@@keywords164245%_ . _%args164246%_)
        (apply make-hash-table__%
               _%@@keywords164245%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords164245%_ 'size: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords164245%_ 'seed: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords164245%_ 'test: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords164245%_ 'hash: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords164245%_ 'lock: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords164245%_
                  'check:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords164245%_
                  'weak-keys:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords164245%_
                  'weak-values:
                  absent-value))
               _%args164246%_)))
    (define make-hash-table
      (lambda _%$%args163681164252%_
        (apply keyword-dispatch
               '#(#f
                  #f
                  weak-values:
                  #f
                  #f
                  test:
                  #f
                  #f
                  #f
                  hash:
                  #f
                  #f
                  size:
                  #f
                  #f
                  #f
                  #f
                  #f
                  #f
                  #f
                  seed:
                  #f
                  #f
                  #f
                  weak-keys:
                  #f
                  #f
                  #f
                  #f
                  #f
                  #f
                  check:
                  #f
                  #f
                  lock:
                  #f
                  #f
                  #f
                  #f
                  #f)
               make-hash-table__@
               _%$%args163681164252%_)))
    (define make-hash-table-eq
      (lambda _%args163670%_
        (apply make-hash-table 'test: eq? _%args163670%_)))
    (define make-hash-table-eqv
      (lambda _%args163668%_
        (apply make-hash-table 'test: eqv? _%args163668%_)))
    (define make-hash-table-symbolic
      (lambda _%args163666%_
        (apply make-hash-table
               'test:
               eq?
               'hash:
               symbolic-hash
               _%args163666%_)))
    (define make-hash-table-string
      (lambda _%args163664%_
        (apply make-hash-table
               'test:
               string=?
               'hash:
               string-hash
               _%args163664%_)))
    (define make-hash-table-immediate
      (lambda _%args163662%_
        (apply make-hash-table
               'test:
               eq?
               'hash:
               immediate-hash
               _%args163662%_)))
    (define list->hash-table
      (lambda (_%lst163659%_ . _%args163660%_)
        (list->hash-table!
         _%lst163659%_
         (apply make-hash-table
                'size:
                (length _%lst163659%_)
                _%args163660%_))))
    (define list->hash-table-eq
      (lambda (_%lst163656%_ . _%args163657%_)
        (list->hash-table!
         _%lst163656%_
         (apply make-hash-table-eq
                'size:
                (length _%lst163656%_)
                _%args163657%_))))
    (define list->hash-table-eqv
      (lambda (_%lst163653%_ . _%args163654%_)
        (list->hash-table!
         _%lst163653%_
         (apply make-hash-table-eqv
                'size:
                (length _%lst163653%_)
                _%args163654%_))))
    (define list->hash-table-symbolic
      (lambda (_%lst163650%_ . _%args163651%_)
        (list->hash-table!
         _%lst163650%_
         (apply make-hash-table-symbolic
                'size:
                (length _%lst163650%_)
                _%args163651%_))))
    (define list->hash-table-string
      (lambda (_%lst163647%_ . _%args163648%_)
        (list->hash-table!
         _%lst163647%_
         (apply make-hash-table-string
                'size:
                (length _%lst163647%_)
                _%args163648%_))))
    (define list->hash-table-immediate
      (lambda (_%lst163644%_ . _%args163645%_)
        (list->hash-table!
         _%lst163644%_
         (apply make-hash-table-immediate
                'size:
                (length _%lst163644%_)
                _%args163645%_))))
    (define list->hash-table!
      (lambda (_%lst163595%_ _%h163596%_)
        (for-each
         (lambda (_%el163598%_)
           (let* ((_%$%el163599163606%_ _%el163598%_)
                  (_%$%E163601163609%_
                   (lambda ()
                     (let ()
                       (declare (not safe))
                       (error '"No clause matching"
                              _%$%el163599163606%_
                              '([k . v])))
                     '#!void))
                  (_%$%K163602163632%_
                   (lambda (_%v163612%_ _%k163613%_)
                     (let* ((_%self156448163615%_ _%h163596%_)
                            (_%key163618%_ _%k163613%_)
                            (_%value163621%_ _%v163612%_))
                       (declare (not safe))
                       (let ((_%object163624163629%_
                              (##unchecked-structure-ref
                               _%self156448163615%_
                               '1
                               '#f
                               'set!))
                             (_%method163625163630%_
                              (##unchecked-structure-ref
                               _%self156448163615%_
                               '9
                               '#f
                               'set!)))
                         (_%method163625163630%_
                          _%object163624163629%_
                          _%key163618%_
                          _%value163621%_))))))
             (if (pair? _%$%el163599163606%_)
                 (let ((_%$%hd163603163635%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%el163599163606%_)))
                       (_%$%tl163604163637%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%el163599163606%_))))
                   (let* ((_%k163640%_ _%$%hd163603163635%_)
                          (_%v163642%_ _%$%tl163604163637%_))
                     (_%$%K163602163632%_ _%v163642%_ _%k163640%_)))
                 (_%$%E163601163609%_))))
         _%lst163595%_)
        _%h163596%_))
    (define plist->hash-table
      (lambda (_%lst163592%_ . _%args163593%_)
        (plist->hash-table!
         _%lst163592%_
         (apply make-hash-table
                'size:
                (length _%lst163592%_)
                _%args163593%_))))
    (define plist->hash-table-eq
      (lambda (_%lst163589%_ . _%args163590%_)
        (plist->hash-table!
         _%lst163589%_
         (apply make-hash-table-eq
                'size:
                (length _%lst163589%_)
                _%args163590%_))))
    (define plist->hash-table-eqv
      (lambda (_%lst163586%_ . _%args163587%_)
        (plist->hash-table!
         _%lst163586%_
         (apply make-hash-table-eqv
                'size:
                (length _%lst163586%_)
                _%args163587%_))))
    (define plist->hash-table-symbolic
      (lambda (_%lst163583%_ . _%args163584%_)
        (plist->hash-table!
         _%lst163583%_
         (apply make-hash-table-symbolic
                'size:
                (length _%lst163583%_)
                _%args163584%_))))
    (define plist->hash-table-string
      (lambda (_%lst163580%_ . _%args163581%_)
        (plist->hash-table!
         _%lst163580%_
         (apply make-hash-table-string
                'size:
                (length _%lst163580%_)
                _%args163581%_))))
    (define plist->hash-table-immediate
      (lambda (_%lst163577%_ . _%args163578%_)
        (plist->hash-table!
         _%lst163577%_
         (apply make-hash-table-immediate
                'size:
                (length _%lst163577%_)
                _%args163578%_))))
    (define plist->hash-table!
      (lambda (_%lst163500%_ _%h163501%_)
        (let _%loop163503%_ ((_%rest163505%_ _%lst163500%_))
          (let* ((_%$%rest163506163518%_ _%rest163505%_)
                 (_%$%else163509163526%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (error '"bad property list -- uneven list"
                             _%lst163500%_)))))
            (let ((_%$%K163512163558%_
                   (lambda (_%rest163537%_ _%val163538%_ _%key163539%_)
                     (let* ((_%self156448163541%_ _%h163501%_)
                            (_%key163544%_ _%key163539%_)
                            (_%value163547%_ _%val163538%_))
                       (declare (not safe))
                       (let ((_%object163550163555%_
                              (##unchecked-structure-ref
                               _%self156448163541%_
                               '1
                               '#f
                               'set!))
                             (_%method163551163556%_
                              (##unchecked-structure-ref
                               _%self156448163541%_
                               '9
                               '#f
                               'set!)))
                         (_%method163551163556%_
                          _%object163550163555%_
                          _%key163544%_
                          _%value163547%_)))
                     (_%loop163503%_ _%rest163537%_)))
                  (_%$%K163511163531%_ (lambda () _%h163501%_)))
              (let ((_%$%try-match163508163534%_
                     (lambda ()
                       (if (null? _%$%rest163506163518%_)
                           (_%$%K163511163531%_)
                           (_%$%else163509163526%_)))))
                (if (pair? _%$%rest163506163518%_)
                    (let ((_%$%tl163514163563%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest163506163518%_)))
                          (_%$%hd163513163561%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest163506163518%_))))
                      (if (pair? _%$%tl163514163563%_)
                          (let ((_%$%tl163516163570%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%tl163514163563%_)))
                                (_%$%hd163515163568%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%tl163514163563%_))))
                            (let ((_%key163566%_ _%$%hd163513163561%_)
                                  (_%val163573%_ _%$%hd163515163568%_)
                                  (_%rest163575%_ _%$%tl163516163570%_))
                              (_%$%K163512163558%_
                               _%rest163575%_
                               _%val163573%_
                               _%key163566%_)))
                          (_%$%else163509163526%_)))
                    (_%$%try-match163508163534%_))))))))
    (define __hash-length
      (lambda (_%h163452%_)
        (let* ((_%h163455%_ _%h163452%_)
               (_%self155717163464%_ _%h163455%_)
               (_%self155717163468%_ _%self155717163464%_)
               (_%self155717163470%_ _%self155717163468%_))
          (if __DEBUG
              (let ((_%val163490%_
                     (let ()
                       (declare (not safe))
                       (let ((_%object163482163487%_
                              (##unchecked-structure-ref
                               _%self155717163470%_
                               '1
                               '#f
                               'length))
                             (_%method163483163488%_
                              (##unchecked-structure-ref
                               _%self155717163470%_
                               '6
                               '#f
                               'length)))
                         (_%method163483163488%_ _%object163482163487%_)))))
                (if (fixnum? _%val163490%_)
                    _%val163490%_
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/hash
                       'contract:
                       '(fixnum? val)
                       'value:
                       _%val163490%_)
                      '#!void)))
              (let ()
                (declare (not safe))
                (let ((_%object163492163497%_
                       (##unchecked-structure-ref
                        _%self155717163470%_
                        '1
                        '#f
                        'length))
                      (_%method163493163498%_
                       (##unchecked-structure-ref
                        _%self155717163470%_
                        '6
                        '#f
                        'length)))
                  (_%method163493163498%_ _%object163492163497%_)))))))
    (define hash-length
      (lambda (_%h163437%_)
        (let* ((_%h163440%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h163437%_)))
               (_%h163442%_ _%h163440%_))
          (__hash-length _%h163442%_))))
    (define __hash-ref__%
      (lambda (_%h163368%_ _%key163369%_ _%default163370%_)
        (let* ((_%h163373%_ _%h163368%_)
               (_%result163423%_
                (let* ((_%self156205163382%_ _%h163373%_)
                       (_%key163385%_ _%key163369%_)
                       (_%default163388%_ _%default163370%_)
                       (_%self156205163392%_ _%self156205163382%_)
                       (_%self156205163394%_ _%self156205163392%_))
                  (if __DEBUG
                      (let ()
                        (declare (not safe))
                        (let ((_%object163408163413%_
                               (##unchecked-structure-ref
                                _%self156205163394%_
                                '1
                                '#f
                                'ref))
                              (_%method163409163414%_
                               (##unchecked-structure-ref
                                _%self156205163394%_
                                '8
                                '#f
                                'ref)))
                          (_%method163409163414%_
                           _%object163408163413%_
                           _%key163385%_
                           _%default163388%_)))
                      (let ()
                        (declare (not safe))
                        (let ((_%object163415163420%_
                               (##unchecked-structure-ref
                                _%self156205163394%_
                                '1
                                '#f
                                'ref))
                              (_%method163416163421%_
                               (##unchecked-structure-ref
                                _%self156205163394%_
                                '8
                                '#f
                                'ref)))
                          (_%method163416163421%_
                           _%object163415163420%_
                           _%key163385%_
                           _%default163388%_)))))))
          (if (eq? _%result163423%_ (macro-absent-obj))
              (raise-unbound-key-error
               'hash-ref
               '"unknown hash key"
               'hash:
               _%h163373%_
               'key:
               _%key163369%_)
              _%result163423%_))))
    (define __hash-ref__0
      (lambda (_%h163428%_ _%key163429%_)
        (let ((_%default163431%_ absent-obj))
          (__hash-ref__% _%h163428%_ _%key163429%_ _%default163431%_))))
    (define __hash-ref
      (lambda _g172721_
        (let ((_g172722_ (let () (declare (not safe)) (##length _g172721_))))
          (cond ((let () (declare (not safe)) (##fx= _g172722_ 2))
                 (apply __hash-ref__0 _g172721_))
                ((let () (declare (not safe)) (##fx= _g172722_ 3))
                 (apply __hash-ref__% _g172721_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __hash-ref
                  _g172721_))))))
    (define hash-ref__%
      (lambda (_%h163338%_ _%key163339%_ _%default163340%_)
        (let* ((_%h163343%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h163338%_)))
               (_%h163345%_ _%h163343%_))
          (__hash-ref__% _%h163345%_ _%key163339%_ _%default163340%_))))
    (define hash-ref__0
      (lambda (_%h163358%_ _%key163359%_)
        (let ((_%default163361%_ absent-obj))
          (hash-ref__% _%h163358%_ _%key163359%_ _%default163361%_))))
    (define hash-ref
      (lambda _g172723_
        (let ((_g172724_ (let () (declare (not safe)) (##length _g172723_))))
          (cond ((let () (declare (not safe)) (##fx= _g172724_ 2))
                 (apply hash-ref__0 _g172723_))
                ((let () (declare (not safe)) (##fx= _g172724_ 3))
                 (apply hash-ref__% _g172723_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  hash-ref
                  _g172723_))))))
    (define __hash-get
      (lambda (_%h163283%_ _%key163284%_)
        (let* ((_%h163287%_ _%h163283%_)
               (_%self156205163296%_ _%h163287%_)
               (_%key163299%_ _%key163284%_)
               (_%default163302%_ '#f)
               (_%self156205163306%_ _%self156205163296%_)
               (_%self156205163308%_ _%self156205163306%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object163322163327%_
                       (##unchecked-structure-ref
                        _%self156205163308%_
                        '1
                        '#f
                        'ref))
                      (_%method163323163328%_
                       (##unchecked-structure-ref
                        _%self156205163308%_
                        '8
                        '#f
                        'ref)))
                  (_%method163323163328%_
                   _%object163322163327%_
                   _%key163299%_
                   _%default163302%_)))
              (let ()
                (declare (not safe))
                (let ((_%object163329163334%_
                       (##unchecked-structure-ref
                        _%self156205163308%_
                        '1
                        '#f
                        'ref))
                      (_%method163330163335%_
                       (##unchecked-structure-ref
                        _%self156205163308%_
                        '8
                        '#f
                        'ref)))
                  (_%method163330163335%_
                   _%object163329163334%_
                   _%key163299%_
                   _%default163302%_)))))))
    (define hash-get
      (lambda (_%h163267%_ _%key163268%_)
        (let* ((_%h163271%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h163267%_)))
               (_%h163273%_ _%h163271%_))
          (__hash-get _%h163273%_ _%key163268%_))))
    (define __hash-put!
      (lambda (_%h163212%_ _%key163213%_ _%value163214%_)
        (let* ((_%h163217%_ _%h163212%_)
               (_%self156449163226%_ _%h163217%_)
               (_%key163229%_ _%key163213%_)
               (_%value163232%_ _%value163214%_)
               (_%self156449163236%_ _%self156449163226%_)
               (_%self156449163238%_ _%self156449163236%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object163252163257%_
                       (##unchecked-structure-ref
                        _%self156449163238%_
                        '1
                        '#f
                        'set!))
                      (_%method163253163258%_
                       (##unchecked-structure-ref
                        _%self156449163238%_
                        '9
                        '#f
                        'set!)))
                  (_%method163253163258%_
                   _%object163252163257%_
                   _%key163229%_
                   _%value163232%_)))
              (let ()
                (declare (not safe))
                (let ((_%object163259163264%_
                       (##unchecked-structure-ref
                        _%self156449163238%_
                        '1
                        '#f
                        'set!))
                      (_%method163260163265%_
                       (##unchecked-structure-ref
                        _%self156449163238%_
                        '9
                        '#f
                        'set!)))
                  (_%method163260163265%_
                   _%object163259163264%_
                   _%key163229%_
                   _%value163232%_)))))))
    (define hash-put!
      (lambda (_%h163195%_ _%key163196%_ _%value163197%_)
        (let* ((_%h163200%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h163195%_)))
               (_%h163202%_ _%h163200%_))
          (__hash-put! _%h163202%_ _%key163196%_ _%value163197%_))))
    (define __hash-update!__%
      (lambda (_%h163111%_ _%key163112%_ _%update163113%_ _%default163114%_)
        (let* ((_%h163117%_ _%h163111%_)
               (_%self156693163126%_ _%h163117%_)
               (_%key163129%_ _%key163112%_)
               (_%proc163132%_ _%update163113%_)
               (_%default163135%_ _%default163114%_)
               (_%self156693163139%_ _%self156693163126%_)
               (_%self156693163141%_ _%self156693163139%_))
          (if (procedure? _%proc163132%_)
              (let ((_%proc163157%_ _%proc163132%_))
                (if __DEBUG
                    (let ()
                      (declare (not safe))
                      (let ((_%object163166163171%_
                             (##unchecked-structure-ref
                              _%self156693163141%_
                              '1
                              '#f
                              'update!))
                            (_%method163167163172%_
                             (##unchecked-structure-ref
                              _%self156693163141%_
                              '10
                              '#f
                              'update!)))
                        (_%method163167163172%_
                         _%object163166163171%_
                         _%key163129%_
                         _%proc163157%_
                         _%default163135%_)))
                    (let ()
                      (declare (not safe))
                      (let ((_%object163173163178%_
                             (##unchecked-structure-ref
                              _%self156693163141%_
                              '1
                              '#f
                              'update!))
                            (_%method163174163179%_
                             (##unchecked-structure-ref
                              _%self156693163141%_
                              '10
                              '#f
                              'update!)))
                        (_%method163174163179%_
                         _%object163173163178%_
                         _%key163129%_
                         _%proc163157%_
                         _%default163135%_)))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/hash
                 'contract:
                 'procedure?
                 'value:
                 _%proc163132%_)
                '#!void)))))
    (define __hash-update!__0
      (lambda (_%h163184%_ _%key163185%_ _%update163186%_)
        (let ((_%default163188%_ '#!void))
          (__hash-update!__%
           _%h163184%_
           _%key163185%_
           _%update163186%_
           _%default163188%_))))
    (define __hash-update!
      (lambda _g172725_
        (let ((_g172726_ (let () (declare (not safe)) (##length _g172725_))))
          (cond ((let () (declare (not safe)) (##fx= _g172726_ 3))
                 (apply __hash-update!__0 _g172725_))
                ((let () (declare (not safe)) (##fx= _g172726_ 4))
                 (apply __hash-update!__% _g172725_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __hash-update!
                  _g172725_))))))
    (define hash-update!__%
      (lambda (_%h163078%_ _%key163079%_ _%update163080%_ _%default163081%_)
        (let* ((_%h163084%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h163078%_)))
               (_%h163086%_ _%h163084%_))
          (__hash-update!__%
           _%h163086%_
           _%key163079%_
           _%update163080%_
           _%default163081%_))))
    (define hash-update!__0
      (lambda (_%h163099%_ _%key163100%_ _%update163101%_)
        (let ((_%default163103%_ '#!void))
          (hash-update!__%
           _%h163099%_
           _%key163100%_
           _%update163101%_
           _%default163103%_))))
    (define hash-update!
      (lambda _g172727_
        (let ((_g172728_ (let () (declare (not safe)) (##length _g172727_))))
          (cond ((let () (declare (not safe)) (##fx= _g172728_ 3))
                 (apply hash-update!__0 _g172727_))
                ((let () (declare (not safe)) (##fx= _g172728_ 4))
                 (apply hash-update!__% _g172727_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  hash-update!
                  _g172727_))))))
    (define __hash-remove!
      (lambda (_%h163027%_ _%key163028%_)
        (let* ((_%h163031%_ _%h163027%_)
               (_%self155229163040%_ _%h163031%_)
               (_%key163043%_ _%key163028%_)
               (_%self155229163047%_ _%self155229163040%_)
               (_%self155229163049%_ _%self155229163047%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object163062163067%_
                       (##unchecked-structure-ref
                        _%self155229163049%_
                        '1
                        '#f
                        'delete!))
                      (_%method163063163068%_
                       (##unchecked-structure-ref
                        _%self155229163049%_
                        '4
                        '#f
                        'delete!)))
                  (_%method163063163068%_
                   _%object163062163067%_
                   _%key163043%_)))
              (let ()
                (declare (not safe))
                (let ((_%object163069163074%_
                       (##unchecked-structure-ref
                        _%self155229163049%_
                        '1
                        '#f
                        'delete!))
                      (_%method163070163075%_
                       (##unchecked-structure-ref
                        _%self155229163049%_
                        '4
                        '#f
                        'delete!)))
                  (_%method163070163075%_
                   _%object163069163074%_
                   _%key163043%_)))))))
    (define hash-remove!
      (lambda (_%h163011%_ _%key163012%_)
        (let* ((_%h163015%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h163011%_)))
               (_%h163017%_ _%h163015%_))
          (__hash-remove! _%h163017%_ _%key163012%_))))
    (define __hash-key?
      (lambda (_%h162957%_ _%k162958%_)
        (let ((_%h162961%_ _%h162957%_))
          (not (eq? (let* ((_%self156205162970%_ _%h162961%_)
                           (_%key162973%_ _%k162958%_)
                           (_%default162976%_ absent-value)
                           (_%self156205162980%_ _%self156205162970%_)
                           (_%self156205162982%_ _%self156205162980%_))
                      (if __DEBUG
                          (let ()
                            (declare (not safe))
                            (let ((_%object162996163001%_
                                   (##unchecked-structure-ref
                                    _%self156205162982%_
                                    '1
                                    '#f
                                    'ref))
                                  (_%method162997163002%_
                                   (##unchecked-structure-ref
                                    _%self156205162982%_
                                    '8
                                    '#f
                                    'ref)))
                              (_%method162997163002%_
                               _%object162996163001%_
                               _%key162973%_
                               _%default162976%_)))
                          (let ()
                            (declare (not safe))
                            (let ((_%object163003163008%_
                                   (##unchecked-structure-ref
                                    _%self156205162982%_
                                    '1
                                    '#f
                                    'ref))
                                  (_%method163004163009%_
                                   (##unchecked-structure-ref
                                    _%self156205162982%_
                                    '8
                                    '#f
                                    'ref)))
                              (_%method163004163009%_
                               _%object163003163008%_
                               _%key162973%_
                               _%default162976%_)))))
                    absent-value)))))
    (define hash-key?
      (lambda (_%h162941%_ _%k162942%_)
        (let* ((_%h162945%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162941%_)))
               (_%h162947%_ _%h162945%_))
          (__hash-key? _%h162947%_ _%k162942%_))))
    (define __hash->list
      (lambda (_%h162876%_)
        (let* ((_%h162879%_ _%h162876%_) (_%lst162888%_ '()))
          (let* ((_%self155473162890%_ _%h162879%_)
                 (_%proc162896%_
                  (lambda (_%k162893%_ _%v162894%_)
                    (set! _%lst162888%_
                          (cons (cons _%k162893%_ _%v162894%_)
                                _%lst162888%_))))
                 (_%self155473162900%_ _%self155473162890%_)
                 (_%self155473162902%_ _%self155473162900%_)
                 (_%proc162917%_ _%proc162896%_))
            (if __DEBUG
                (let ()
                  (declare (not safe))
                  (let ((_%object162926162931%_
                         (##unchecked-structure-ref
                          _%self155473162902%_
                          '1
                          '#f
                          'for-each))
                        (_%method162927162932%_
                         (##unchecked-structure-ref
                          _%self155473162902%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162927162932%_
                     _%object162926162931%_
                     _%proc162917%_)))
                (let ()
                  (declare (not safe))
                  (let ((_%object162933162938%_
                         (##unchecked-structure-ref
                          _%self155473162902%_
                          '1
                          '#f
                          'for-each))
                        (_%method162934162939%_
                         (##unchecked-structure-ref
                          _%self155473162902%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162934162939%_
                     _%object162933162938%_
                     _%proc162917%_)))))
          _%lst162888%_)))
    (define hash->list
      (lambda (_%h162861%_)
        (let* ((_%h162864%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162861%_)))
               (_%h162866%_ _%h162864%_))
          (__hash->list _%h162866%_))))
    (define __hash->plist
      (lambda (_%h162796%_)
        (let* ((_%h162799%_ _%h162796%_) (_%lst162808%_ '()))
          (let* ((_%self155473162810%_ _%h162799%_)
                 (_%proc162816%_
                  (lambda (_%k162813%_ _%v162814%_)
                    (set! _%lst162808%_
                          (cons _%k162813%_
                                (cons _%v162814%_ _%lst162808%_)))))
                 (_%self155473162820%_ _%self155473162810%_)
                 (_%self155473162822%_ _%self155473162820%_)
                 (_%proc162837%_ _%proc162816%_))
            (if __DEBUG
                (let ()
                  (declare (not safe))
                  (let ((_%object162846162851%_
                         (##unchecked-structure-ref
                          _%self155473162822%_
                          '1
                          '#f
                          'for-each))
                        (_%method162847162852%_
                         (##unchecked-structure-ref
                          _%self155473162822%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162847162852%_
                     _%object162846162851%_
                     _%proc162837%_)))
                (let ()
                  (declare (not safe))
                  (let ((_%object162853162858%_
                         (##unchecked-structure-ref
                          _%self155473162822%_
                          '1
                          '#f
                          'for-each))
                        (_%method162854162859%_
                         (##unchecked-structure-ref
                          _%self155473162822%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162854162859%_
                     _%object162853162858%_
                     _%proc162837%_)))))
          _%lst162808%_)))
    (define hash->plist
      (lambda (_%h162781%_)
        (let* ((_%h162784%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162781%_)))
               (_%h162786%_ _%h162784%_))
          (__hash->plist _%h162786%_))))
    (define __hash-for-each
      (lambda (_%proc162713%_ _%h162714%_)
        (let* ((_%proc162717%_ _%proc162713%_)
               (_%h162725%_ _%h162714%_)
               (_%self155473162734%_ _%h162725%_)
               (_%proc162737%_ _%proc162717%_)
               (_%self155473162741%_ _%self155473162734%_)
               (_%self155473162743%_ _%self155473162741%_)
               (_%proc162757%_ _%proc162737%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object162766162771%_
                       (##unchecked-structure-ref
                        _%self155473162743%_
                        '1
                        '#f
                        'for-each))
                      (_%method162767162772%_
                       (##unchecked-structure-ref
                        _%self155473162743%_
                        '5
                        '#f
                        'for-each)))
                  (_%method162767162772%_
                   _%object162766162771%_
                   _%proc162757%_)))
              (let ()
                (declare (not safe))
                (let ((_%object162773162778%_
                       (##unchecked-structure-ref
                        _%self155473162743%_
                        '1
                        '#f
                        'for-each))
                      (_%method162774162779%_
                       (##unchecked-structure-ref
                        _%self155473162743%_
                        '5
                        '#f
                        'for-each)))
                  (_%method162774162779%_
                   _%object162773162778%_
                   _%proc162757%_)))))))
    (define hash-for-each
      (lambda (_%proc162687%_ _%h162688%_)
        (if (procedure? _%proc162687%_)
            (let* ((_%proc162692%_ _%proc162687%_)
                   (_%h162701%_
                    (let ()
                      (declare (not safe))
                      (cast HashTable::interface _%h162688%_)))
                   (_%h162703%_ _%h162701%_))
              (__hash-for-each _%proc162692%_ _%h162703%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/hash.ss\"@602.22-602.26"
               'contract:
               'procedure?
               'value:
               _%proc162687%_)
              '#!void))))
    (define __hash-map
      (lambda (_%proc162613%_ _%h162614%_)
        (let* ((_%proc162617%_ _%proc162613%_)
               (_%h162625%_ _%h162614%_)
               (_%result162634%_ '()))
          (let* ((_%self155473162636%_ _%h162625%_)
                 (_%proc162642%_
                  (lambda (_%k162639%_ _%v162640%_)
                    (set! _%result162634%_
                          (cons (let ()
                                  (declare (not safe))
                                  (_%proc162617%_ _%k162639%_ _%v162640%_))
                                _%result162634%_))))
                 (_%self155473162646%_ _%self155473162636%_)
                 (_%self155473162648%_ _%self155473162646%_)
                 (_%proc162663%_ _%proc162642%_))
            (if __DEBUG
                (let ()
                  (declare (not safe))
                  (let ((_%object162672162677%_
                         (##unchecked-structure-ref
                          _%self155473162648%_
                          '1
                          '#f
                          'for-each))
                        (_%method162673162678%_
                         (##unchecked-structure-ref
                          _%self155473162648%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162673162678%_
                     _%object162672162677%_
                     _%proc162663%_)))
                (let ()
                  (declare (not safe))
                  (let ((_%object162679162684%_
                         (##unchecked-structure-ref
                          _%self155473162648%_
                          '1
                          '#f
                          'for-each))
                        (_%method162680162685%_
                         (##unchecked-structure-ref
                          _%self155473162648%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162680162685%_
                     _%object162679162684%_
                     _%proc162663%_)))))
          _%result162634%_)))
    (define hash-map
      (lambda (_%proc162587%_ _%h162588%_)
        (if (procedure? _%proc162587%_)
            (let* ((_%proc162592%_ _%proc162587%_)
                   (_%h162601%_
                    (let ()
                      (declare (not safe))
                      (cast HashTable::interface _%h162588%_)))
                   (_%h162603%_ _%h162601%_))
              (__hash-map _%proc162592%_ _%h162603%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/hash.ss\"@605.17-605.21"
               'contract:
               'procedure?
               'value:
               _%proc162587%_)
              '#!void))))
    (define __hash-fold
      (lambda (_%proc162512%_ _%iv162513%_ _%h162514%_)
        (let* ((_%proc162517%_ _%proc162512%_)
               (_%h162525%_ _%h162514%_)
               (_%result162534%_ _%iv162513%_))
          (let* ((_%self155473162536%_ _%h162525%_)
                 (_%proc162542%_
                  (lambda (_%k162539%_ _%v162540%_)
                    (set! _%result162534%_
                          (let ()
                            (declare (not safe))
                            (_%proc162517%_
                             _%k162539%_
                             _%v162540%_
                             _%result162534%_)))))
                 (_%self155473162546%_ _%self155473162536%_)
                 (_%self155473162548%_ _%self155473162546%_)
                 (_%proc162563%_ _%proc162542%_))
            (if __DEBUG
                (let ()
                  (declare (not safe))
                  (let ((_%object162572162577%_
                         (##unchecked-structure-ref
                          _%self155473162548%_
                          '1
                          '#f
                          'for-each))
                        (_%method162573162578%_
                         (##unchecked-structure-ref
                          _%self155473162548%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162573162578%_
                     _%object162572162577%_
                     _%proc162563%_)))
                (let ()
                  (declare (not safe))
                  (let ((_%object162579162584%_
                         (##unchecked-structure-ref
                          _%self155473162548%_
                          '1
                          '#f
                          'for-each))
                        (_%method162580162585%_
                         (##unchecked-structure-ref
                          _%self155473162548%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162580162585%_
                     _%object162579162584%_
                     _%proc162563%_)))))
          _%result162534%_)))
    (define hash-fold
      (lambda (_%proc162485%_ _%iv162486%_ _%h162487%_)
        (if (procedure? _%proc162485%_)
            (let* ((_%proc162491%_ _%proc162485%_)
                   (_%h162500%_
                    (let ()
                      (declare (not safe))
                      (cast HashTable::interface _%h162487%_)))
                   (_%h162502%_ _%h162500%_))
              (__hash-fold _%proc162491%_ _%iv162486%_ _%h162502%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/hash.ss\"@611.18-611.22"
               'contract:
               'procedure?
               'value:
               _%proc162485%_)
              '#!void))))
    (define __hash-find__%
      (lambda (_%proc162395%_ _%h162396%_ _%default-value162397%_)
        (let* ((_%proc162400%_ _%proc162395%_)
               (_%h162408%_ _%h162396%_)
               (__tmp172729
                (lambda (_%return162417%_)
                  (let* ((_%self155473162419%_ _%h162408%_)
                         (_%proc162428%_
                          (lambda (_%k162422%_ _%v162423%_)
                            (let ((_%$e162425%_
                                   (let ()
                                     (declare (not safe))
                                     (_%proc162400%_
                                      _%k162422%_
                                      _%v162423%_))))
                              (if _%$e162425%_
                                  (_%return162417%_ _%$e162425%_)
                                  '#!void))))
                         (_%self155473162432%_ _%self155473162419%_)
                         (_%self155473162434%_ _%self155473162432%_)
                         (_%proc162449%_ _%proc162428%_))
                    (if __DEBUG
                        (let ()
                          (declare (not safe))
                          (let ((_%object162458162463%_
                                 (##unchecked-structure-ref
                                  _%self155473162434%_
                                  '1
                                  '#f
                                  'for-each))
                                (_%method162459162464%_
                                 (##unchecked-structure-ref
                                  _%self155473162434%_
                                  '5
                                  '#f
                                  'for-each)))
                            (_%method162459162464%_
                             _%object162458162463%_
                             _%proc162449%_)))
                        (let ()
                          (declare (not safe))
                          (let ((_%object162465162470%_
                                 (##unchecked-structure-ref
                                  _%self155473162434%_
                                  '1
                                  '#f
                                  'for-each))
                                (_%method162466162471%_
                                 (##unchecked-structure-ref
                                  _%self155473162434%_
                                  '5
                                  '#f
                                  'for-each)))
                            (_%method162466162471%_
                             _%object162465162470%_
                             _%proc162449%_)))))
                  _%default-value162397%_)))
          (declare (not safe))
          (##call-with-current-continuation __tmp172729))))
    (define __hash-find__0
      (lambda (_%proc162476%_ _%h162477%_)
        (let ((_%default-value162479%_ '#f))
          (__hash-find__%
           _%proc162476%_
           _%h162477%_
           _%default-value162479%_))))
    (define __hash-find
      (lambda _g172730_
        (let ((_g172731_ (let () (declare (not safe)) (##length _g172730_))))
          (cond ((let () (declare (not safe)) (##fx= _g172731_ 2))
                 (apply __hash-find__0 _g172730_))
                ((let () (declare (not safe)) (##fx= _g172731_ 3))
                 (apply __hash-find__% _g172730_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __hash-find
                  _g172730_))))))
    (define hash-find__%
      (lambda (_%proc162355%_ _%h162356%_ _%default-value162357%_)
        (if (procedure? _%proc162355%_)
            (let* ((_%proc162361%_ _%proc162355%_)
                   (_%h162370%_
                    (let ()
                      (declare (not safe))
                      (cast HashTable::interface _%h162356%_)))
                   (_%h162372%_ _%h162370%_))
              (__hash-find__%
               _%proc162361%_
               _%h162372%_
               _%default-value162357%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/hash.ss\"@616.18-616.22"
               'contract:
               'procedure?
               'value:
               _%proc162355%_)
              '#!void))))
    (define hash-find__0
      (lambda (_%proc162385%_ _%h162386%_)
        (let ((_%default-value162388%_ '#f))
          (hash-find__% _%proc162385%_ _%h162386%_ _%default-value162388%_))))
    (define hash-find
      (lambda _g172732_
        (let ((_g172733_ (let () (declare (not safe)) (##length _g172732_))))
          (cond ((let () (declare (not safe)) (##fx= _g172733_ 2))
                 (apply hash-find__0 _g172732_))
                ((let () (declare (not safe)) (##fx= _g172733_ 3))
                 (apply hash-find__% _g172732_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  hash-find
                  _g172732_))))))
    (define __hash-keys
      (lambda (_%h162289%_)
        (let* ((_%h162292%_ _%h162289%_) (_%result162301%_ '()))
          (let* ((_%self155473162303%_ _%h162292%_)
                 (_%proc162309%_
                  (lambda (_%k162306%_ _%v162307%_)
                    (set! _%result162301%_
                          (cons _%k162306%_ _%result162301%_))))
                 (_%self155473162313%_ _%self155473162303%_)
                 (_%self155473162315%_ _%self155473162313%_)
                 (_%proc162330%_ _%proc162309%_))
            (if __DEBUG
                (let ()
                  (declare (not safe))
                  (let ((_%object162339162344%_
                         (##unchecked-structure-ref
                          _%self155473162315%_
                          '1
                          '#f
                          'for-each))
                        (_%method162340162345%_
                         (##unchecked-structure-ref
                          _%self155473162315%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162340162345%_
                     _%object162339162344%_
                     _%proc162330%_)))
                (let ()
                  (declare (not safe))
                  (let ((_%object162346162351%_
                         (##unchecked-structure-ref
                          _%self155473162315%_
                          '1
                          '#f
                          'for-each))
                        (_%method162347162352%_
                         (##unchecked-structure-ref
                          _%self155473162315%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162347162352%_
                     _%object162346162351%_
                     _%proc162330%_)))))
          _%result162301%_)))
    (define hash-keys
      (lambda (_%h162274%_)
        (let* ((_%h162277%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162274%_)))
               (_%h162279%_ _%h162277%_))
          (__hash-keys _%h162279%_))))
    (define __hash-values
      (lambda (_%h162209%_)
        (let* ((_%h162212%_ _%h162209%_) (_%result162221%_ '()))
          (let* ((_%self155473162223%_ _%h162212%_)
                 (_%proc162229%_
                  (lambda (_%k162226%_ _%v162227%_)
                    (set! _%result162221%_
                          (cons _%v162227%_ _%result162221%_))))
                 (_%self155473162233%_ _%self155473162223%_)
                 (_%self155473162235%_ _%self155473162233%_)
                 (_%proc162250%_ _%proc162229%_))
            (if __DEBUG
                (let ()
                  (declare (not safe))
                  (let ((_%object162259162264%_
                         (##unchecked-structure-ref
                          _%self155473162235%_
                          '1
                          '#f
                          'for-each))
                        (_%method162260162265%_
                         (##unchecked-structure-ref
                          _%self155473162235%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162260162265%_
                     _%object162259162264%_
                     _%proc162250%_)))
                (let ()
                  (declare (not safe))
                  (let ((_%object162266162271%_
                         (##unchecked-structure-ref
                          _%self155473162235%_
                          '1
                          '#f
                          'for-each))
                        (_%method162267162272%_
                         (##unchecked-structure-ref
                          _%self155473162235%_
                          '5
                          '#f
                          'for-each)))
                    (_%method162267162272%_
                     _%object162266162271%_
                     _%proc162250%_)))))
          _%result162221%_)))
    (define hash-values
      (lambda (_%h162194%_)
        (let* ((_%h162197%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162194%_)))
               (_%h162199%_ _%h162197%_))
          (__hash-values _%h162199%_))))
    (define __hash-copy
      (lambda (_%h162149%_)
        (let* ((_%h162152%_ _%h162149%_)
               (_%self154985162161%_ _%h162152%_)
               (_%self154985162165%_ _%self154985162161%_)
               (_%self154985162167%_ _%self154985162165%_))
          (if __DEBUG
              (let ((__tmp172734
                     (let ()
                       (declare (not safe))
                       (let ((_%object162179162184%_
                              (##unchecked-structure-ref
                               _%self154985162167%_
                               '1
                               '#f
                               'copy))
                             (_%method162180162185%_
                              (##unchecked-structure-ref
                               _%self154985162167%_
                               '3
                               '#f
                               'copy)))
                         (_%method162180162185%_ _%object162179162184%_)))))
                (declare (not safe))
                (cast HashTable::interface __tmp172734))
              (let ()
                (declare (not safe))
                (let ((_%object162186162191%_
                       (##unchecked-structure-ref
                        _%self154985162167%_
                        '1
                        '#f
                        'copy))
                      (_%method162187162192%_
                       (##unchecked-structure-ref
                        _%self154985162167%_
                        '3
                        '#f
                        'copy)))
                  (_%method162187162192%_ _%object162186162191%_)))))))
    (define hash-copy
      (lambda (_%h162134%_)
        (let* ((_%h162137%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162134%_)))
               (_%h162139%_ _%h162137%_))
          (__hash-copy _%h162139%_))))
    (define __hash-new
      (lambda (_%h162069%_)
        (let* ((_%h162072%_ _%h162069%_)
               (_%self155961162081%_ _%h162072%_)
               (_%size-hint162084%_ '#f)
               (_%self155961162088%_ _%self155961162081%_)
               (_%self155961162090%_ _%self155961162088%_))
          (if (let ((_%$e162106%_ '#t)) (and _%$e162106%_ _%$e162106%_))
              (let ((_%size-hint162110%_ _%size-hint162084%_))
                (if __DEBUG
                    (let ((__tmp172735
                           (let ()
                             (declare (not safe))
                             (let ((_%object162119162124%_
                                    (##unchecked-structure-ref
                                     _%self155961162090%_
                                     '1
                                     '#f
                                     'new))
                                   (_%method162120162125%_
                                    (##unchecked-structure-ref
                                     _%self155961162090%_
                                     '7
                                     '#f
                                     'new)))
                               (_%method162120162125%_
                                _%object162119162124%_
                                _%size-hint162110%_)))))
                      (declare (not safe))
                      (cast HashTable::interface __tmp172735))
                    (let ()
                      (declare (not safe))
                      (let ((_%object162126162131%_
                             (##unchecked-structure-ref
                              _%self155961162090%_
                              '1
                              '#f
                              'new))
                            (_%method162127162132%_
                             (##unchecked-structure-ref
                              _%self155961162090%_
                              '7
                              '#f
                              'new)))
                        (_%method162127162132%_
                         _%object162126162131%_
                         _%size-hint162110%_)))))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/hash
                 'contract:
                 '(? (or not fixnum?))
                 'value:
                 _%size-hint162084%_)
                '#!void)))))
    (define hash-new
      (lambda (_%h162054%_)
        (let* ((_%h162057%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h162054%_)))
               (_%h162059%_ _%h162057%_))
          (__hash-new _%h162059%_))))
    (define __hash-clear!
      (lambda (_%h162009%_)
        (let* ((_%h162012%_ _%h162009%_)
               (_%self154740162021%_ _%h162012%_)
               (_%self154740162025%_ _%self154740162021%_)
               (_%self154740162027%_ _%self154740162025%_))
          (if __DEBUG
              (let ()
                (declare (not safe))
                (let ((_%object162039162044%_
                       (##unchecked-structure-ref
                        _%self154740162027%_
                        '1
                        '#f
                        'clear!))
                      (_%method162040162045%_
                       (##unchecked-structure-ref
                        _%self154740162027%_
                        '2
                        '#f
                        'clear!)))
                  (_%method162040162045%_ _%object162039162044%_)))
              (let ()
                (declare (not safe))
                (let ((_%object162046162051%_
                       (##unchecked-structure-ref
                        _%self154740162027%_
                        '1
                        '#f
                        'clear!))
                      (_%method162047162052%_
                       (##unchecked-structure-ref
                        _%self154740162027%_
                        '2
                        '#f
                        'clear!)))
                  (_%method162047162052%_ _%object162046162051%_)))))))
    (define hash-clear!
      (lambda (_%h161994%_)
        (let* ((_%h161997%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h161994%_)))
               (_%h161999%_ _%h161997%_))
          (__hash-clear! _%h161999%_))))
    (define __hash-merge
      (lambda (_%h161946%_ . _%rest161947%_)
        (let* ((_%h161950%_ _%h161946%_)
               (_%copy161992%_
                (let* ((_%self154985161959%_ _%h161950%_)
                       (_%self154985161963%_ _%self154985161959%_)
                       (_%self154985161965%_ _%self154985161963%_))
                  (if __DEBUG
                      (let ((__tmp172736
                             (let ()
                               (declare (not safe))
                               (let ((_%object161977161982%_
                                      (##unchecked-structure-ref
                                       _%self154985161965%_
                                       '1
                                       '#f
                                       'copy))
                                     (_%method161978161983%_
                                      (##unchecked-structure-ref
                                       _%self154985161965%_
                                       '3
                                       '#f
                                       'copy)))
                                 (_%method161978161983%_
                                  _%object161977161982%_)))))
                        (declare (not safe))
                        (cast HashTable::interface __tmp172736))
                      (let ()
                        (declare (not safe))
                        (let ((_%object161984161989%_
                               (##unchecked-structure-ref
                                _%self154985161965%_
                                '1
                                '#f
                                'copy))
                              (_%method161985161990%_
                               (##unchecked-structure-ref
                                _%self154985161965%_
                                '3
                                '#f
                                'copy)))
                          (_%method161985161990%_ _%object161984161989%_)))))))
          (apply hash-merge! _%copy161992%_ _%rest161947%_)
          _%copy161992%_)))
    (define hash-merge
      (lambda (_%h161930%_ . _%rest161931%_)
        (let* ((_%h161934%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h161930%_)))
               (_%h161936%_ _%h161934%_))
          (declare (not safe))
          (##apply __hash-merge _%h161936%_ _%rest161931%_))))
    (define __hash-merge-right
      (lambda (_%h161882%_ . _%rest161883%_)
        (let* ((_%h161886%_ _%h161882%_)
               (_%copy161928%_
                (let* ((_%self154985161895%_ _%h161886%_)
                       (_%self154985161899%_ _%self154985161895%_)
                       (_%self154985161901%_ _%self154985161899%_))
                  (if __DEBUG
                      (let ((__tmp172737
                             (let ()
                               (declare (not safe))
                               (let ((_%object161913161918%_
                                      (##unchecked-structure-ref
                                       _%self154985161901%_
                                       '1
                                       '#f
                                       'copy))
                                     (_%method161914161919%_
                                      (##unchecked-structure-ref
                                       _%self154985161901%_
                                       '3
                                       '#f
                                       'copy)))
                                 (_%method161914161919%_
                                  _%object161913161918%_)))))
                        (declare (not safe))
                        (cast HashTable::interface __tmp172737))
                      (let ()
                        (declare (not safe))
                        (let ((_%object161920161925%_
                               (##unchecked-structure-ref
                                _%self154985161901%_
                                '1
                                '#f
                                'copy))
                              (_%method161921161926%_
                               (##unchecked-structure-ref
                                _%self154985161901%_
                                '3
                                '#f
                                'copy)))
                          (_%method161921161926%_ _%object161920161925%_)))))))
          (apply hash-merge-right! _%copy161928%_ _%rest161883%_)
          _%copy161928%_)))
    (define hash-merge-right
      (lambda (_%h161866%_ . _%rest161867%_)
        (let* ((_%h161870%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h161866%_)))
               (_%h161872%_ _%h161870%_))
          (declare (not safe))
          (##apply __hash-merge-right _%h161872%_ _%rest161867%_))))
    (define __hash-merge!
      (lambda (_%h161726%_ . _%rest161727%_)
        (let ((_%h161730%_ _%h161726%_))
          (let ((__tmp172738
                 (lambda (_%hr161739%_)
                   (let* ((_%hr161742%_
                           (let ()
                             (declare (not safe))
                             (cast HashTable::interface _%hr161739%_)))
                          (_%hr161744%_ _%hr161742%_)
                          (_%self155473161757%_ _%hr161744%_)
                          (_%proc161826%_
                           (lambda (_%k161760%_ _%v161761%_)
                             (if (let* ((_%h161763%_ _%h161730%_)
                                        (_%k161766%_ _%k161760%_)
                                        (_%h161770%_ _%h161763%_)
                                        (_%h161772%_ _%h161770%_))
                                   (__hash-key? _%h161772%_ _%k161766%_))
                                 '#!void
                                 (let* ((_%self156449161788%_ _%h161730%_)
                                        (_%key161791%_ _%k161760%_)
                                        (_%value161794%_ _%v161761%_)
                                        (_%self156449161798%_
                                         _%self156449161788%_)
                                        (_%self156449161800%_
                                         _%self156449161798%_))
                                   (if __DEBUG
                                       (let ()
                                         (declare (not safe))
                                         (let ((_%object161811161816%_
                                                (##unchecked-structure-ref
                                                 _%self156449161800%_
                                                 '1
                                                 '#f
                                                 'set!))
                                               (_%method161812161817%_
                                                (##unchecked-structure-ref
                                                 _%self156449161800%_
                                                 '9
                                                 '#f
                                                 'set!)))
                                           (_%method161812161817%_
                                            _%object161811161816%_
                                            _%key161791%_
                                            _%value161794%_)))
                                       (let ()
                                         (declare (not safe))
                                         (let ((_%object161818161823%_
                                                (##unchecked-structure-ref
                                                 _%self156449161800%_
                                                 '1
                                                 '#f
                                                 'set!))
                                               (_%method161819161824%_
                                                (##unchecked-structure-ref
                                                 _%self156449161800%_
                                                 '9
                                                 '#f
                                                 'set!)))
                                           (_%method161819161824%_
                                            _%object161818161823%_
                                            _%key161791%_
                                            _%value161794%_))))))))
                          (_%self155473161830%_ _%self155473161757%_)
                          (_%self155473161832%_ _%self155473161830%_)
                          (_%proc161842%_ _%proc161826%_))
                     (if __DEBUG
                         (let ()
                           (declare (not safe))
                           (let ((_%object161851161856%_
                                  (##unchecked-structure-ref
                                   _%self155473161832%_
                                   '1
                                   '#f
                                   'for-each))
                                 (_%method161852161857%_
                                  (##unchecked-structure-ref
                                   _%self155473161832%_
                                   '5
                                   '#f
                                   'for-each)))
                             (_%method161852161857%_
                              _%object161851161856%_
                              _%proc161842%_)))
                         (let ()
                           (declare (not safe))
                           (let ((_%object161858161863%_
                                  (##unchecked-structure-ref
                                   _%self155473161832%_
                                   '1
                                   '#f
                                   'for-each))
                                 (_%method161859161864%_
                                  (##unchecked-structure-ref
                                   _%self155473161832%_
                                   '5
                                   '#f
                                   'for-each)))
                             (_%method161859161864%_
                              _%object161858161863%_
                              _%proc161842%_))))))))
            (declare (not safe))
            (##for-each __tmp172738 _%rest161727%_))
          _%h161730%_)))
    (define hash-merge!
      (lambda (_%h161710%_ . _%rest161711%_)
        (let* ((_%h161714%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h161710%_)))
               (_%h161716%_ _%h161714%_))
          (declare (not safe))
          (##apply __hash-merge! _%h161716%_ _%rest161711%_))))
    (define __hash-merge-right!
      (lambda (_%h161590%_ . _%rest161591%_)
        (let ((_%h161594%_ _%h161590%_))
          (let ((__tmp172739
                 (lambda (_%hr161603%_)
                   (let* ((_%hr161606%_
                           (let ()
                             (declare (not safe))
                             (cast HashTable::interface _%hr161603%_)))
                          (_%hr161608%_ _%hr161606%_)
                          (_%self155473161621%_ _%hr161608%_)
                          (_%proc161670%_
                           (lambda (_%k161624%_ _%v161625%_)
                             (let* ((_%self156449161627%_ _%h161594%_)
                                    (_%key161630%_ _%k161624%_)
                                    (_%value161633%_ _%v161625%_)
                                    (_%self156449161637%_ _%self156449161627%_)
                                    (_%self156449161639%_
                                     _%self156449161637%_))
                               (if __DEBUG
                                   (let ()
                                     (declare (not safe))
                                     (let ((_%object161655161660%_
                                            (##unchecked-structure-ref
                                             _%self156449161639%_
                                             '1
                                             '#f
                                             'set!))
                                           (_%method161656161661%_
                                            (##unchecked-structure-ref
                                             _%self156449161639%_
                                             '9
                                             '#f
                                             'set!)))
                                       (_%method161656161661%_
                                        _%object161655161660%_
                                        _%key161630%_
                                        _%value161633%_)))
                                   (let ()
                                     (declare (not safe))
                                     (let ((_%object161662161667%_
                                            (##unchecked-structure-ref
                                             _%self156449161639%_
                                             '1
                                             '#f
                                             'set!))
                                           (_%method161663161668%_
                                            (##unchecked-structure-ref
                                             _%self156449161639%_
                                             '9
                                             '#f
                                             'set!)))
                                       (_%method161663161668%_
                                        _%object161662161667%_
                                        _%key161630%_
                                        _%value161633%_)))))))
                          (_%self155473161674%_ _%self155473161621%_)
                          (_%self155473161676%_ _%self155473161674%_)
                          (_%proc161686%_ _%proc161670%_))
                     (if __DEBUG
                         (let ()
                           (declare (not safe))
                           (let ((_%object161695161700%_
                                  (##unchecked-structure-ref
                                   _%self155473161676%_
                                   '1
                                   '#f
                                   'for-each))
                                 (_%method161696161701%_
                                  (##unchecked-structure-ref
                                   _%self155473161676%_
                                   '5
                                   '#f
                                   'for-each)))
                             (_%method161696161701%_
                              _%object161695161700%_
                              _%proc161686%_)))
                         (let ()
                           (declare (not safe))
                           (let ((_%object161702161707%_
                                  (##unchecked-structure-ref
                                   _%self155473161676%_
                                   '1
                                   '#f
                                   'for-each))
                                 (_%method161703161708%_
                                  (##unchecked-structure-ref
                                   _%self155473161676%_
                                   '5
                                   '#f
                                   'for-each)))
                             (_%method161703161708%_
                              _%object161702161707%_
                              _%proc161686%_))))))))
            (declare (not safe))
            (##for-each __tmp172739 _%rest161591%_))
          _%h161594%_)))
    (define hash-merge-right!
      (lambda (_%h161574%_ . _%rest161575%_)
        (let* ((_%h161578%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h161574%_)))
               (_%h161580%_ _%h161578%_))
          (declare (not safe))
          (##apply __hash-merge-right! _%h161580%_ _%rest161575%_))))))
