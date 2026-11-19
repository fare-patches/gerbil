(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/table::timestamp 1795039812)
  (begin
    (declare (not safe))
    (define __table::t.id 'gerbil#__table::t)
    (define __table::t
      (##structure
       ##type-type
       __table::t.id
       'raw-table
       '26
       '#f
       '#(table
          1
          #f
          count
          0
          #f
          free
          0
          #f
          hash
          0
          #f
          test
          0
          #f
          seed
          0
          #f
          lock
          0
          #f)))
    (define raw-table?
      (lambda (_%obj127395%_)
        (if (##structure? _%obj127395%_)
            (##structure-instance-of? _%obj127395%_ __table::t.id)
            '#f)))
    (define &raw-table-table
      (lambda (_%tab127393%_)
        (##unchecked-structure-ref
         _%tab127393%_
         '1
         __table::t
         'raw-table-table)))
    (define &raw-table-count
      (lambda (_%tab127391%_)
        (##unchecked-structure-ref
         _%tab127391%_
         '2
         __table::t
         'raw-table-count)))
    (define &raw-table-free
      (lambda (_%tab127389%_)
        (##unchecked-structure-ref
         _%tab127389%_
         '3
         __table::t
         'raw-table-free)))
    (define &raw-table-hash
      (lambda (_%tab127387%_)
        (##unchecked-structure-ref
         _%tab127387%_
         '4
         __table::t
         'raw-table-hash)))
    (define &raw-table-test
      (lambda (_%tab127385%_)
        (##unchecked-structure-ref
         _%tab127385%_
         '5
         __table::t
         'raw-table-test)))
    (define &raw-table-seed
      (lambda (_%tab127383%_)
        (##unchecked-structure-ref
         _%tab127383%_
         '6
         __table::t
         'raw-table-seed)))
    (define &raw-table-lock
      (lambda (_%tab127381%_)
        (##unchecked-structure-ref
         _%tab127381%_
         '7
         __table::t
         'raw-table-lock)))
    (define &raw-table-table-set!
      (lambda (_%tab127378%_ _%val127379%_)
        (##unchecked-structure-set!
         _%tab127378%_
         _%val127379%_
         '1
         __table::t
         'raw-table-table-set!)))
    (define &raw-table-count-set!
      (lambda (_%tab127375%_ _%val127376%_)
        (##unchecked-structure-set!
         _%tab127375%_
         _%val127376%_
         '2
         __table::t
         'raw-table-count-set!)))
    (define &raw-table-free-set!
      (lambda (_%tab127372%_ _%val127373%_)
        (##unchecked-structure-set!
         _%tab127372%_
         _%val127373%_
         '3
         __table::t
         'raw-table-free-set!)))
    (define &raw-table-hash-set!
      (lambda (_%tab127369%_ _%val127370%_)
        (##unchecked-structure-set!
         _%tab127369%_
         _%val127370%_
         '4
         __table::t
         'raw-table-hash-set!)))
    (define &raw-table-test-set!
      (lambda (_%tab127366%_ _%val127367%_)
        (##unchecked-structure-set!
         _%tab127366%_
         _%val127367%_
         '5
         __table::t
         'raw-table-test-set!)))
    (define &raw-table-seed-set!
      (lambda (_%tab127363%_ _%val127364%_)
        (##unchecked-structure-set!
         _%tab127363%_
         _%val127364%_
         '6
         __table::t
         'raw-table-seed-set!)))
    (define &raw-table-lock-set!
      (lambda (_%tab127360%_ _%val127361%_)
        (##unchecked-structure-set!
         _%tab127360%_
         _%val127361%_
         '7
         __table::t
         'raw-table-lock-set!)))
    (define raw-table-size-hint->size
      (lambda (_%size-hint127358%_)
        (if (and (fixnum? _%size-hint127358%_) (##fx> _%size-hint127358%_ '0))
            (##fx* (fxmax '2 (expt '2 (integer-length _%size-hint127358%_)))
                   '4)
            '16)))
    (define ensure-lock
      (lambda (_%lock127354%_)
        (if (eq? _%lock127354%_ '#t) (vector '0 '#f) _%lock127354%_)))
    (define make-raw-table__%
      (lambda (_%size-hint127319%_
               _%hash127320%_
               _%test127321%_
               _%seed127322%_
               _%lock127323%_)
        (let* ((_%size127325%_ (raw-table-size-hint->size _%size-hint127319%_))
               (_%table127327%_
                (##make-vector _%size127325%_ (macro-unused-obj))))
          (##structure
           __table::t
           _%table127327%_
           '0
           (##fxquotient _%size127325%_ '2)
           _%hash127320%_
           _%test127321%_
           _%seed127322%_
           (ensure-lock _%lock127323%_)))))
    (define make-raw-table__0
      (lambda (_%size-hint127333%_ _%hash127334%_ _%test127335%_)
        (let* ((_%seed127337%_ '0) (_%lock127339%_ '#f))
          (make-raw-table__%
           _%size-hint127333%_
           _%hash127334%_
           _%test127335%_
           _%seed127337%_
           _%lock127339%_))))
    (define make-raw-table__1
      (lambda (_%size-hint127341%_
               _%hash127342%_
               _%test127343%_
               _%seed127344%_)
        (let ((_%lock127346%_ '#f))
          (make-raw-table__%
           _%size-hint127341%_
           _%hash127342%_
           _%test127343%_
           _%seed127344%_
           _%lock127346%_))))
    (define make-raw-table
      (lambda _g127396_
        (let ((_g127397_ (##length _g127396_)))
          (cond ((##fx= _g127397_ 3) (apply make-raw-table__0 _g127396_))
                ((##fx= _g127397_ 4) (apply make-raw-table__1 _g127396_))
                ((##fx= _g127397_ 5) (apply make-raw-table__% _g127396_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-raw-table
                  _g127396_))))))
    (define make-raw-table/lock__%
      (lambda (_%size-hint127299%_
               _%hash127300%_
               _%test127301%_
               _%seed127302%_)
        (make-raw-table__%
         _%size-hint127299%_
         _%hash127300%_
         _%test127301%_
         _%seed127302%_
         '#t)))
    (define make-raw-table/lock__0
      (lambda (_%size-hint127307%_ _%hash127308%_ _%test127309%_)
        (let ((_%seed127311%_ '0))
          (make-raw-table/lock__%
           _%size-hint127307%_
           _%hash127308%_
           _%test127309%_
           _%seed127311%_))))
    (define make-raw-table/lock
      (lambda _g127398_
        (let ((_g127399_ (##length _g127398_)))
          (cond ((##fx= _g127399_ 3) (apply make-raw-table/lock__0 _g127398_))
                ((##fx= _g127399_ 4) (apply make-raw-table/lock__% _g127398_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-raw-table/lock
                  _g127398_))))))
    (define raw-table-length
      (lambda (_%tab127296%_) (&raw-table-count _%tab127296%_)))
    (define raw-table-length/lock
      (lambda (_%tab127269%_)
        (let ((_%lock127271%_ (&raw-table-lock _%tab127269%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again127276%_ ((_%spin127279%_ '0))
              (if (##fx= (##vector-cas! _%lock127271%_ '0 '1 '0) '0)
                  (##vector-set! _%lock127271%_ '1 (current-thread))
                  (if (##fx< _%spin127279%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again127276%_ (##fx+ _%spin127279%_ '1)))
                      (let ((_%owner127285%_ (##vector-ref _%lock127271%_ '1)))
                        (if (eq? _%owner127285%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner127285%_)
                                (let () (##thread-yield!) (_%again127276%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127291%_ (&raw-table-count _%tab127269%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock127271%_ '1 '#f)
                (##vector-cas! _%lock127271%_ '0 '0 '1)))
            _%$r127291%_))))
    (define raw-table-ref
      (lambda (_%tab127221%_ _%key127222%_ _%default127223%_)
        (let ((_%table127225%_ (&raw-table-table _%tab127221%_))
              (_%seed127226%_ (&raw-table-seed _%tab127221%_))
              (_%hash127227%_ (&raw-table-hash _%tab127221%_))
              (_%test127228%_ (&raw-table-test _%tab127221%_)))
          (let* ((_%h127230%_
                  (fxxor (_%hash127227%_ _%key127222%_) _%seed127226%_))
                 (_%size127233%_ (vector-length _%table127225%_))
                 (_%entries127236%_ (##fxquotient _%size127233%_ '2))
                 (_%start127239%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h127230%_ _%entries127236%_)
                   '1)))
            (let _%loop127243%_ ((_%probe127246%_ _%start127239%_)
                                 (_%i127248%_ '1)
                                 (_%deleted127250%_ '#f))
              (let ((_%k127253%_ (vector-ref _%table127225%_ _%probe127246%_)))
                (if (eq? _%k127253%_ (macro-unused-obj))
                    _%default127223%_
                    (if (eq? _%k127253%_ (macro-deleted-obj))
                        (_%loop127243%_
                         (let ((_%next-probe127258%_
                                (fx+ _%start127239%_
                                     _%i127248%_
                                     (fx* _%i127248%_ _%i127248%_))))
                           (##fxmodulo _%next-probe127258%_ _%size127233%_))
                         (##fx+ _%i127248%_ '1)
                         (let ((_%$e127261%_ _%deleted127250%_))
                           (if _%$e127261%_ _%$e127261%_ _%probe127246%_)))
                        (if (_%test127228%_ _%key127222%_ _%k127253%_)
                            (vector-ref
                             _%table127225%_
                             (##fx+ _%probe127246%_ '1))
                            (_%loop127243%_
                             (let ((_%next-probe127266%_
                                    (fx+ _%start127239%_
                                         _%i127248%_
                                         (fx* _%i127248%_ _%i127248%_))))
                               (##fxmodulo
                                _%next-probe127266%_
                                _%size127233%_))
                             (##fx+ _%i127248%_ '1)
                             _%deleted127250%_))))))))))
    (define raw-table-ref/lock
      (lambda (_%tab127192%_ _%key127193%_ _%default127194%_)
        (let ((_%lock127196%_ (&raw-table-lock _%tab127192%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again127201%_ ((_%spin127204%_ '0))
              (if (##fx= (##vector-cas! _%lock127196%_ '0 '1 '0) '0)
                  (##vector-set! _%lock127196%_ '1 (current-thread))
                  (if (##fx< _%spin127204%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again127201%_ (##fx+ _%spin127204%_ '1)))
                      (let ((_%owner127210%_ (##vector-ref _%lock127196%_ '1)))
                        (if (eq? _%owner127210%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner127210%_)
                                (let () (##thread-yield!) (_%again127201%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127216%_
                 (raw-table-ref
                  _%tab127192%_
                  _%key127193%_
                  _%default127194%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock127196%_ '1 '#f)
                (##vector-cas! _%lock127196%_ '0 '0 '1)))
            _%$r127216%_))))
    (define raw-table-set!
      (lambda (_%tab127188%_ _%key127189%_ _%value127190%_)
        (if (##fx< (&raw-table-free _%tab127188%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab127188%_))
                    '4))
            (__raw-table-rehash! _%tab127188%_)
            '#!void)
        (__raw-table-set! _%tab127188%_ _%key127189%_ _%value127190%_)))
    (define raw-table-set!/lock
      (lambda (_%tab127159%_ _%key127160%_ _%value127161%_)
        (let ((_%lock127163%_ (&raw-table-lock _%tab127159%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again127168%_ ((_%spin127171%_ '0))
              (if (##fx= (##vector-cas! _%lock127163%_ '0 '1 '0) '0)
                  (##vector-set! _%lock127163%_ '1 (current-thread))
                  (if (##fx< _%spin127171%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again127168%_ (##fx+ _%spin127171%_ '1)))
                      (let ((_%owner127177%_ (##vector-ref _%lock127163%_ '1)))
                        (if (eq? _%owner127177%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner127177%_)
                                (let () (##thread-yield!) (_%again127168%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127183%_
                 (raw-table-set! _%tab127159%_ _%key127160%_ _%value127161%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock127163%_ '1 '#f)
                (##vector-cas! _%lock127163%_ '0 '0 '1)))
            _%$r127183%_))))
    (define raw-table-update!
      (lambda (_%tab127154%_ _%key127155%_ _%update127156%_ _%default127157%_)
        (if (##fx< (&raw-table-free _%tab127154%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab127154%_))
                    '4))
            (__raw-table-rehash! _%tab127154%_)
            '#!void)
        (__raw-table-update!
         _%tab127154%_
         _%key127155%_
         _%update127156%_
         _%default127157%_)))
    (define raw-table-update!/lock
      (lambda (_%tab127124%_ _%key127125%_ _%update127126%_ _%default127127%_)
        (let ((_%lock127129%_ (&raw-table-lock _%tab127124%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again127134%_ ((_%spin127137%_ '0))
              (if (##fx= (##vector-cas! _%lock127129%_ '0 '1 '0) '0)
                  (##vector-set! _%lock127129%_ '1 (current-thread))
                  (if (##fx< _%spin127137%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again127134%_ (##fx+ _%spin127137%_ '1)))
                      (let ((_%owner127143%_ (##vector-ref _%lock127129%_ '1)))
                        (if (eq? _%owner127143%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner127143%_)
                                (let () (##thread-yield!) (_%again127134%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127149%_
                 (raw-table-update!
                  _%tab127124%_
                  _%key127125%_
                  _%update127126%_
                  _%default127127%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock127129%_ '1 '#f)
                (##vector-cas! _%lock127129%_ '0 '0 '1)))
            _%$r127149%_))))
    (define raw-table-delete!
      (lambda (_%tab127081%_ _%key127082%_)
        (let ((_%table127084%_ (&raw-table-table _%tab127081%_))
              (_%seed127085%_ (&raw-table-seed _%tab127081%_))
              (_%hash127086%_ (&raw-table-hash _%tab127081%_))
              (_%test127087%_ (&raw-table-test _%tab127081%_)))
          (let* ((_%h127089%_
                  (fxxor (_%hash127086%_ _%key127082%_) _%seed127085%_))
                 (_%size127092%_ (vector-length _%table127084%_))
                 (_%entries127095%_ (##fxquotient _%size127092%_ '2))
                 (_%start127098%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h127089%_ _%entries127095%_)
                   '1)))
            (let _%loop127102%_ ((_%probe127105%_ _%start127098%_)
                                 (_%i127107%_ '1))
              (let ((_%k127110%_ (vector-ref _%table127084%_ _%probe127105%_)))
                (if (eq? _%k127110%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k127110%_ (macro-deleted-obj))
                        (_%loop127102%_
                         (let ((_%next-probe127115%_
                                (fx+ _%start127098%_
                                     _%i127107%_
                                     (fx* _%i127107%_ _%i127107%_))))
                           (##fxmodulo _%next-probe127115%_ _%size127092%_))
                         (##fx+ _%i127107%_ '1))
                        (if (_%test127087%_ _%key127082%_ _%k127110%_)
                            (let ()
                              (vector-set!
                               _%table127084%_
                               _%probe127105%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table127084%_
                               (##fx+ _%probe127105%_ '1)
                               (macro-absent-obj))
                              (&raw-table-count-set!
                               _%tab127081%_
                               (##fx- (&raw-table-count _%tab127081%_) '1)))
                            (_%loop127102%_
                             (let ((_%next-probe127121%_
                                    (fx+ _%start127098%_
                                         _%i127107%_
                                         (fx* _%i127107%_ _%i127107%_))))
                               (##fxmodulo
                                _%next-probe127121%_
                                _%size127092%_))
                             (##fx+ _%i127107%_ '1)))))))))))
    (define raw-table-delete!/lock
      (lambda (_%tab127053%_ _%key127054%_)
        (let ((_%lock127056%_ (&raw-table-lock _%tab127053%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again127061%_ ((_%spin127064%_ '0))
              (if (##fx= (##vector-cas! _%lock127056%_ '0 '1 '0) '0)
                  (##vector-set! _%lock127056%_ '1 (current-thread))
                  (if (##fx< _%spin127064%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again127061%_ (##fx+ _%spin127064%_ '1)))
                      (let ((_%owner127070%_ (##vector-ref _%lock127056%_ '1)))
                        (if (eq? _%owner127070%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner127070%_)
                                (let () (##thread-yield!) (_%again127061%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127076%_ (raw-table-delete! _%tab127053%_ _%key127054%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock127056%_ '1 '#f)
                (##vector-cas! _%lock127056%_ '0 '0 '1)))
            _%$r127076%_))))
    (define raw-table-for-each
      (lambda (_%tab127037%_ _%proc127038%_)
        (let* ((_%table127040%_ (&raw-table-table _%tab127037%_))
               (_%size127042%_ (vector-length _%table127040%_)))
          (let _%loop127045%_ ((_%i127047%_ '0))
            (if (##fx< _%i127047%_ _%size127042%_)
                (begin
                  (let ((_%key127049%_
                         (vector-ref _%table127040%_ _%i127047%_)))
                    (if (if (eq? _%key127049%_ (macro-unused-obj))
                            '#f
                            (not (eq? _%key127049%_ (macro-deleted-obj))))
                        (let ((_%value127051%_
                               (vector-ref
                                _%table127040%_
                                (##fx+ _%i127047%_ '1))))
                          (_%proc127038%_ _%key127049%_ _%value127051%_))
                        '#!void))
                  (_%loop127045%_ (##fx+ _%i127047%_ '2)))
                '#!void)))))
    (define raw-table-for-each/lock
      (lambda (_%tab127009%_ _%proc127010%_)
        (let ((_%lock127012%_ (&raw-table-lock _%tab127009%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again127017%_ ((_%spin127020%_ '0))
              (if (##fx= (##vector-cas! _%lock127012%_ '0 '1 '0) '0)
                  (##vector-set! _%lock127012%_ '1 (current-thread))
                  (if (##fx< _%spin127020%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again127017%_ (##fx+ _%spin127020%_ '1)))
                      (let ((_%owner127026%_ (##vector-ref _%lock127012%_ '1)))
                        (if (eq? _%owner127026%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner127026%_)
                                (let () (##thread-yield!) (_%again127017%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127032%_
                 (raw-table-for-each _%tab127009%_ _%proc127010%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock127012%_ '1 '#f)
                (##vector-cas! _%lock127012%_ '0 '0 '1)))
            _%$r127032%_))))
    (define raw-table-copy
      (lambda (_%tab127005%_)
        (let ((_%new-tab127007%_ (##structure-copy _%tab127005%_)))
          (&raw-table-table-set!
           _%new-tab127007%_
           (vector-copy (&raw-table-table _%tab127005%_)))
          (&raw-table-lock-set!
           _%new-tab127007%_
           (ensure-lock (if (&raw-table-lock _%tab127005%_) '#t '#f)))
          _%new-tab127007%_)))
    (define raw-table-copy/lock
      (lambda (_%tab126978%_)
        (let ((_%lock126980%_ (&raw-table-lock _%tab126978%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126985%_ ((_%spin126988%_ '0))
              (if (##fx= (##vector-cas! _%lock126980%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126980%_ '1 (current-thread))
                  (if (##fx< _%spin126988%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126985%_ (##fx+ _%spin126988%_ '1)))
                      (let ((_%owner126994%_ (##vector-ref _%lock126980%_ '1)))
                        (if (eq? _%owner126994%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126994%_)
                                (let () (##thread-yield!) (_%again126985%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r127000%_ (raw-table-copy _%tab126978%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126980%_ '1 '#f)
                (##vector-cas! _%lock126980%_ '0 '0 '1)))
            _%$r127000%_))))
    (define raw-table-new__%
      (lambda (_%tab126965%_ _%size-hint126966%_)
        (make-raw-table__%
         (if (eq? _%size-hint126966%_ '#t)
             (vector-length (&raw-table-table _%tab126965%_))
             _%size-hint126966%_)
         (&raw-table-hash _%tab126965%_)
         (&raw-table-test _%tab126965%_)
         (&raw-table-seed _%tab126965%_)
         (if (&raw-table-lock _%tab126965%_) '#t '#f))))
    (define raw-table-new__0
      (lambda (_%tab126971%_)
        (let ((_%size-hint126973%_ '#f))
          (raw-table-new__% _%tab126971%_ _%size-hint126973%_))))
    (define raw-table-new
      (lambda _g127400_
        (let ((_g127401_ (##length _g127400_)))
          (cond ((##fx= _g127401_ 1) (apply raw-table-new__0 _g127400_))
                ((##fx= _g127401_ 2) (apply raw-table-new__% _g127400_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  raw-table-new
                  _g127400_))))))
    (define raw-table-clear!
      (lambda (_%tab126962%_)
        (vector-fill! (&raw-table-table _%tab126962%_) (macro-unused-obj))
        (&raw-table-count-set! _%tab126962%_ '0)
        (&raw-table-free-set!
         _%tab126962%_
         (##fxquotient (vector-length (&raw-table-table _%tab126962%_)) '2))))
    (define raw-table-clear!/lock
      (lambda (_%tab126935%_)
        (let ((_%lock126937%_ (&raw-table-lock _%tab126935%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126942%_ ((_%spin126945%_ '0))
              (if (##fx= (##vector-cas! _%lock126937%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126937%_ '1 (current-thread))
                  (if (##fx< _%spin126945%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126942%_ (##fx+ _%spin126945%_ '1)))
                      (let ((_%owner126951%_ (##vector-ref _%lock126937%_ '1)))
                        (if (eq? _%owner126951%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126951%_)
                                (let () (##thread-yield!) (_%again126942%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126957%_ (raw-table-clear! _%tab126935%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126937%_ '1 '#f)
                (##vector-cas! _%lock126937%_ '0 '0 '1)))
            _%$r126957%_))))
    (define __raw-table-set!
      (lambda (_%tab126885%_ _%key126886%_ _%value126887%_)
        (let ((_%table126889%_ (&raw-table-table _%tab126885%_))
              (_%seed126890%_ (&raw-table-seed _%tab126885%_))
              (_%hash126891%_ (&raw-table-hash _%tab126885%_))
              (_%test126892%_ (&raw-table-test _%tab126885%_)))
          (let* ((_%h126894%_
                  (fxxor (_%hash126891%_ _%key126886%_) _%seed126890%_))
                 (_%size126897%_ (vector-length _%table126889%_))
                 (_%entries126900%_ (##fxquotient _%size126897%_ '2))
                 (_%start126903%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126894%_ _%entries126900%_)
                   '1)))
            (let _%loop126907%_ ((_%probe126910%_ _%start126903%_)
                                 (_%i126912%_ '1)
                                 (_%deleted126914%_ '#f))
              (let ((_%k126917%_ (vector-ref _%table126889%_ _%probe126910%_)))
                (if (eq? _%k126917%_ (macro-unused-obj))
                    (if _%deleted126914%_
                        (begin
                          (vector-set!
                           _%table126889%_
                           _%deleted126914%_
                           _%key126886%_)
                          (vector-set!
                           _%table126889%_
                           (##fx+ _%deleted126914%_ '1)
                           _%value126887%_)
                          (&raw-table-count-set!
                           _%tab126885%_
                           (##fx+ (&raw-table-count _%tab126885%_) '1)))
                        (begin
                          (vector-set!
                           _%table126889%_
                           _%probe126910%_
                           _%key126886%_)
                          (vector-set!
                           _%table126889%_
                           (##fx+ _%probe126910%_ '1)
                           _%value126887%_)
                          (let ()
                            (&raw-table-free-set!
                             _%tab126885%_
                             (##fx- (&raw-table-free _%tab126885%_) '1))
                            (&raw-table-count-set!
                             _%tab126885%_
                             (##fx+ (&raw-table-count _%tab126885%_) '1)))))
                    (if (eq? _%k126917%_ (macro-deleted-obj))
                        (_%loop126907%_
                         (let ((_%next-probe126924%_
                                (fx+ _%start126903%_
                                     _%i126912%_
                                     (fx* _%i126912%_ _%i126912%_))))
                           (##fxmodulo _%next-probe126924%_ _%size126897%_))
                         (##fx+ _%i126912%_ '1)
                         (let ((_%$e126927%_ _%deleted126914%_))
                           (if _%$e126927%_ _%$e126927%_ _%probe126910%_)))
                        (if (_%test126892%_ _%key126886%_ _%k126917%_)
                            (let ()
                              (vector-set!
                               _%table126889%_
                               _%probe126910%_
                               _%key126886%_)
                              (vector-set!
                               _%table126889%_
                               (##fx+ _%probe126910%_ '1)
                               _%value126887%_))
                            (_%loop126907%_
                             (let ((_%next-probe126932%_
                                    (fx+ _%start126903%_
                                         _%i126912%_
                                         (fx* _%i126912%_ _%i126912%_))))
                               (##fxmodulo
                                _%next-probe126932%_
                                _%size126897%_))
                             (##fx+ _%i126912%_ '1)
                             _%deleted126914%_))))))))))
    (define __raw-table-update!
      (lambda (_%tab126834%_ _%key126835%_ _%update126836%_ _%default126837%_)
        (let ((_%table126839%_ (&raw-table-table _%tab126834%_))
              (_%seed126840%_ (&raw-table-seed _%tab126834%_))
              (_%hash126841%_ (&raw-table-hash _%tab126834%_))
              (_%test126842%_ (&raw-table-test _%tab126834%_)))
          (let* ((_%h126844%_
                  (fxxor (_%hash126841%_ _%key126835%_) _%seed126840%_))
                 (_%size126847%_ (vector-length _%table126839%_))
                 (_%entries126850%_ (##fxquotient _%size126847%_ '2))
                 (_%start126853%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126844%_ _%entries126850%_)
                   '1)))
            (let _%loop126857%_ ((_%probe126860%_ _%start126853%_)
                                 (_%i126862%_ '1)
                                 (_%deleted126864%_ '#f))
              (let ((_%k126867%_ (vector-ref _%table126839%_ _%probe126860%_)))
                (if (eq? _%k126867%_ (macro-unused-obj))
                    (if _%deleted126864%_
                        (begin
                          (vector-set!
                           _%table126839%_
                           _%deleted126864%_
                           _%key126835%_)
                          (vector-set!
                           _%table126839%_
                           (##fx+ _%deleted126864%_ '1)
                           (_%update126836%_ _%default126837%_))
                          (&raw-table-count-set!
                           _%tab126834%_
                           (##fx+ (&raw-table-count _%tab126834%_) '1)))
                        (begin
                          (vector-set!
                           _%table126839%_
                           _%probe126860%_
                           _%key126835%_)
                          (vector-set!
                           _%table126839%_
                           (##fx+ _%probe126860%_ '1)
                           (_%update126836%_ _%default126837%_))
                          (let ()
                            (&raw-table-free-set!
                             _%tab126834%_
                             (##fx- (&raw-table-free _%tab126834%_) '1))
                            (&raw-table-count-set!
                             _%tab126834%_
                             (##fx+ (&raw-table-count _%tab126834%_) '1)))))
                    (if (eq? _%k126867%_ (macro-deleted-obj))
                        (_%loop126857%_
                         (let ((_%next-probe126874%_
                                (fx+ _%start126853%_
                                     _%i126862%_
                                     (fx* _%i126862%_ _%i126862%_))))
                           (##fxmodulo _%next-probe126874%_ _%size126847%_))
                         (##fx+ _%i126862%_ '1)
                         (let ((_%$e126877%_ _%deleted126864%_))
                           (if _%$e126877%_ _%$e126877%_ _%probe126860%_)))
                        (if (_%test126842%_ _%key126835%_ _%k126867%_)
                            (let ()
                              (vector-set!
                               _%table126839%_
                               _%probe126860%_
                               _%key126835%_)
                              (vector-set!
                               _%table126839%_
                               (##fx+ _%probe126860%_ '1)
                               (_%update126836%_
                                (vector-ref
                                 _%table126839%_
                                 (##fx+ _%probe126860%_ '1)))))
                            (_%loop126857%_
                             (let ((_%next-probe126882%_
                                    (fx+ _%start126853%_
                                         _%i126862%_
                                         (fx* _%i126862%_ _%i126862%_))))
                               (##fxmodulo
                                _%next-probe126882%_
                                _%size126847%_))
                             (##fx+ _%i126862%_ '1)
                             _%deleted126864%_))))))))))
    (define __raw-table-rehash!
      (lambda (_%tab126815%_)
        (let* ((_%old-table126817%_ (&raw-table-table _%tab126815%_))
               (_%old-size126819%_ (vector-length _%old-table126817%_))
               (_%new-size126821%_
                (if (##fx< (&raw-table-count _%tab126815%_)
                           (##fxquotient _%old-size126819%_ '4))
                    (vector-length _%old-table126817%_)
                    (##fx* '2 (vector-length _%old-table126817%_))))
               (_%new-table126823%_
                (##make-vector _%new-size126821%_ (macro-unused-obj))))
          (&raw-table-table-set! _%tab126815%_ _%new-table126823%_)
          (&raw-table-count-set! _%tab126815%_ '0)
          (&raw-table-free-set!
           _%tab126815%_
           (##fxquotient _%new-size126821%_ '2))
          (let _%lp126826%_ ((_%i126828%_ '0))
            (if (##fx< _%i126828%_ _%old-size126819%_)
                (begin
                  (let ((_%key126830%_
                         (vector-ref _%old-table126817%_ _%i126828%_)))
                    (if (if (eq? _%key126830%_ (macro-unused-obj))
                            '#f
                            (not (eq? _%key126830%_ (macro-deleted-obj))))
                        (let ((_%value126832%_
                               (vector-ref
                                _%old-table126817%_
                                (##fx+ _%i126828%_ '1))))
                          (__raw-table-set!
                           _%tab126815%_
                           _%key126830%_
                           _%value126832%_))
                        '#!void))
                  (_%lp126826%_ (##fx+ _%i126828%_ '2)))
                '#!void)))))
    (define eq-hash
      (lambda (_%obj126807%_)
        (let ((_%t126809%_ (##type _%obj126807%_)))
          (if (##fx= (##fxand _%t126809%_ '1) '0)
              (fxand (##type-cast _%obj126807%_ (macro-type-fixnum))
                     (macro-max-fixnum32))
              (if (symbolic? _%obj126807%_)
                  (##symbol-hash _%obj126807%_)
                  (if (procedure? _%obj126807%_)
                      (procedure-hash _%obj126807%_)
                      (fxand (__object->eq-hash _%obj126807%_)
                             (macro-max-fixnum32))))))))
    (define procedure-hash
      (lambda (_%obj126803%_)
        (let ((_%h126805%_
               (if (##closure? _%obj126803%_)
                   (__object->eq-hash _%obj126803%_)
                   (##type-cast _%obj126803%_ '0))))
          (fxand _%h126805%_ (macro-max-fixnum32)))))
    (define __eq-hash
      (lambda (_%obj126801%_) (__object->eq-hash _%obj126801%_)))
    (define eqv-hash
      (lambda (_%obj126791%_)
        (letrec ((_%combine126793%_
                  (lambda (_%a126798%_ _%b126799%_)
                    (fxand (##fx* (##fx+ _%a126798%_
                                         (fxarithmetic-shift-left
                                          _%b126799%_
                                          '1))
                                  '331804471)
                           (macro-max-fixnum32))))
                 (_%hash126794%_
                  (lambda (_%obj126796%_)
                    (macro-number-dispatch
                     _%obj126796%_
                     (eq-hash _%obj126796%_)
                     (fxand _%obj126796%_ (macro-max-fixnum32))
                     (modulo _%obj126796%_ '331804481)
                     (_%combine126793%_
                      (_%hash126794%_ (macro-ratnum-numerator _%obj126796%_))
                      (_%hash126794%_
                       (macro-ratnum-denominator _%obj126796%_)))
                     (_%combine126793%_
                      (##u16vector-ref _%obj126796%_ '0)
                      (_%combine126793%_
                       (##u16vector-ref _%obj126796%_ '1)
                       (_%combine126793%_
                        (##u16vector-ref _%obj126796%_ '2)
                        (##u16vector-ref _%obj126796%_ '3))))
                     (_%combine126793%_
                      (_%hash126794%_ (macro-cpxnum-real _%obj126796%_))
                      (_%hash126794%_ (macro-cpxnum-imag _%obj126796%_)))))))
          (_%hash126794%_ _%obj126791%_))))
    (define symbolic?
      (lambda (_%obj126786%_)
        (let ((_%$e126788%_ (symbol? _%obj126786%_)))
          (if _%$e126788%_ _%$e126788%_ (keyword? _%obj126786%_)))))
    (define symbolic-hash
      (lambda (_%obj126784%_) (##symbol-hash _%obj126784%_)))
    (define string-hash
      (lambda (_%obj126782%_) (##string=?-hash _%obj126782%_)))
    (define immediate-hash
      (lambda (_%obj126780%_) (##type-cast _%obj126780%_ (macro-type-fixnum))))
    (define make-eq-table__%
      (lambda (_%size-hint126762%_ _%seed126763%_)
        (make-raw-table__1 _%size-hint126762%_ eq-hash eq? _%seed126763%_)))
    (define make-eq-table__0
      (lambda ()
        (let* ((_%size-hint126769%_ '#f) (_%seed126771%_ '0))
          (make-eq-table__% _%size-hint126769%_ _%seed126771%_))))
    (define make-eq-table__1
      (lambda (_%size-hint126773%_)
        (let ((_%seed126775%_ '0))
          (make-eq-table__% _%size-hint126773%_ _%seed126775%_))))
    (define make-eq-table
      (lambda _g127402_
        (let ((_g127403_ (##length _g127402_)))
          (cond ((##fx= _g127403_ 0) (apply make-eq-table__0 _g127402_))
                ((##fx= _g127403_ 1) (apply make-eq-table__1 _g127402_))
                ((##fx= _g127403_ 2) (apply make-eq-table__% _g127402_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-eq-table
                  _g127402_))))))
    (define make-eq-table/lock__%
      (lambda (_%size-hint126742%_ _%seed126744%_)
        (make-raw-table/lock__%
         _%size-hint126742%_
         eq-hash
         eq?
         _%seed126744%_)))
    (define make-eq-table/lock__0
      (lambda ()
        (let* ((_%size-hint126750%_ '#f) (_%seed126752%_ '0))
          (make-eq-table/lock__% _%size-hint126750%_ _%seed126752%_))))
    (define make-eq-table/lock__1
      (lambda (_%size-hint126754%_)
        (let ((_%seed126756%_ '0))
          (make-eq-table/lock__% _%size-hint126754%_ _%seed126756%_))))
    (define make-eq-table/lock
      (lambda _g127404_
        (let ((_g127405_ (##length _g127404_)))
          (cond ((##fx= _g127405_ 0) (apply make-eq-table/lock__0 _g127404_))
                ((##fx= _g127405_ 1) (apply make-eq-table/lock__1 _g127404_))
                ((##fx= _g127405_ 2) (apply make-eq-table/lock__% _g127404_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-eq-table/lock
                  _g127404_))))))
    (define eq-table-ref
      (lambda (_%tab126695%_ _%key126696%_ _%default126697%_)
        (let ((_%table126699%_ (&raw-table-table _%tab126695%_))
              (_%seed126700%_ (&raw-table-seed _%tab126695%_)))
          (let* ((_%h126702%_ (fxxor (eq-hash _%key126696%_) _%seed126700%_))
                 (_%size126705%_ (vector-length _%table126699%_))
                 (_%entries126708%_ (##fxquotient _%size126705%_ '2))
                 (_%start126711%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126702%_ _%entries126708%_)
                   '1)))
            (let _%loop126715%_ ((_%probe126718%_ _%start126711%_)
                                 (_%i126720%_ '1)
                                 (_%deleted126722%_ '#f))
              (let ((_%k126725%_ (vector-ref _%table126699%_ _%probe126718%_)))
                (if (eq? _%k126725%_ (macro-unused-obj))
                    _%default126697%_
                    (if (eq? _%k126725%_ (macro-deleted-obj))
                        (_%loop126715%_
                         (let ((_%next-probe126730%_
                                (fx+ _%start126711%_
                                     _%i126720%_
                                     (fx* _%i126720%_ _%i126720%_))))
                           (##fxmodulo _%next-probe126730%_ _%size126705%_))
                         (##fx+ _%i126720%_ '1)
                         (let ((_%$e126733%_ _%deleted126722%_))
                           (if _%$e126733%_ _%$e126733%_ _%probe126718%_)))
                        (if (eq? _%key126696%_ _%k126725%_)
                            (vector-ref
                             _%table126699%_
                             (##fx+ _%probe126718%_ '1))
                            (_%loop126715%_
                             (let ((_%next-probe126738%_
                                    (fx+ _%start126711%_
                                         _%i126720%_
                                         (fx* _%i126720%_ _%i126720%_))))
                               (##fxmodulo
                                _%next-probe126738%_
                                _%size126705%_))
                             (##fx+ _%i126720%_ '1)
                             _%deleted126722%_))))))))))
    (define eq-table-ref/lock
      (lambda (_%tab126666%_ _%key126667%_ _%default126668%_)
        (let ((_%lock126670%_ (&raw-table-lock _%tab126666%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126675%_ ((_%spin126678%_ '0))
              (if (##fx= (##vector-cas! _%lock126670%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126670%_ '1 (current-thread))
                  (if (##fx< _%spin126678%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126675%_ (##fx+ _%spin126678%_ '1)))
                      (let ((_%owner126684%_ (##vector-ref _%lock126670%_ '1)))
                        (if (eq? _%owner126684%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126684%_)
                                (let () (##thread-yield!) (_%again126675%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126690%_
                 (eq-table-ref _%tab126666%_ _%key126667%_ _%default126668%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126670%_ '1 '#f)
                (##vector-cas! _%lock126670%_ '0 '0 '1)))
            _%$r126690%_))))
    (define __eq-table-set!
      (lambda (_%tab126618%_ _%key126619%_ _%value126620%_)
        (let ((_%table126622%_ (&raw-table-table _%tab126618%_))
              (_%seed126623%_ (&raw-table-seed _%tab126618%_)))
          (let* ((_%h126625%_ (fxxor (eq-hash _%key126619%_) _%seed126623%_))
                 (_%size126628%_ (vector-length _%table126622%_))
                 (_%entries126631%_ (##fxquotient _%size126628%_ '2))
                 (_%start126634%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126625%_ _%entries126631%_)
                   '1)))
            (let _%loop126638%_ ((_%probe126641%_ _%start126634%_)
                                 (_%i126643%_ '1)
                                 (_%deleted126645%_ '#f))
              (let ((_%k126648%_ (vector-ref _%table126622%_ _%probe126641%_)))
                (if (eq? _%k126648%_ (macro-unused-obj))
                    (if _%deleted126645%_
                        (begin
                          (vector-set!
                           _%table126622%_
                           _%deleted126645%_
                           _%key126619%_)
                          (vector-set!
                           _%table126622%_
                           (##fx+ _%deleted126645%_ '1)
                           _%value126620%_)
                          (&raw-table-count-set!
                           _%tab126618%_
                           (##fx+ (&raw-table-count _%tab126618%_) '1)))
                        (begin
                          (vector-set!
                           _%table126622%_
                           _%probe126641%_
                           _%key126619%_)
                          (vector-set!
                           _%table126622%_
                           (##fx+ _%probe126641%_ '1)
                           _%value126620%_)
                          (let ()
                            (&raw-table-free-set!
                             _%tab126618%_
                             (##fx- (&raw-table-free _%tab126618%_) '1))
                            (&raw-table-count-set!
                             _%tab126618%_
                             (##fx+ (&raw-table-count _%tab126618%_) '1)))))
                    (if (eq? _%k126648%_ (macro-deleted-obj))
                        (_%loop126638%_
                         (let ((_%next-probe126655%_
                                (fx+ _%start126634%_
                                     _%i126643%_
                                     (fx* _%i126643%_ _%i126643%_))))
                           (##fxmodulo _%next-probe126655%_ _%size126628%_))
                         (##fx+ _%i126643%_ '1)
                         (let ((_%$e126658%_ _%deleted126645%_))
                           (if _%$e126658%_ _%$e126658%_ _%probe126641%_)))
                        (if (eq? _%key126619%_ _%k126648%_)
                            (let ()
                              (vector-set!
                               _%table126622%_
                               _%probe126641%_
                               _%key126619%_)
                              (vector-set!
                               _%table126622%_
                               (##fx+ _%probe126641%_ '1)
                               _%value126620%_))
                            (_%loop126638%_
                             (let ((_%next-probe126663%_
                                    (fx+ _%start126634%_
                                         _%i126643%_
                                         (fx* _%i126643%_ _%i126643%_))))
                               (##fxmodulo
                                _%next-probe126663%_
                                _%size126628%_))
                             (##fx+ _%i126643%_ '1)
                             _%deleted126645%_))))))))))
    (define eq-table-set!
      (lambda (_%tab126614%_ _%key126615%_ _%value126616%_)
        (if (##fx< (&raw-table-free _%tab126614%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab126614%_))
                    '4))
            (__raw-table-rehash! _%tab126614%_)
            '#!void)
        (__eq-table-set! _%tab126614%_ _%key126615%_ _%value126616%_)))
    (define eq-table-set!/lock
      (lambda (_%tab126584%_ _%key126585%_ _%value126586%_)
        (let ((_%lock126589%_ (&raw-table-lock _%tab126584%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126594%_ ((_%spin126597%_ '0))
              (if (##fx= (##vector-cas! _%lock126589%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126589%_ '1 (current-thread))
                  (if (##fx< _%spin126597%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126594%_ (##fx+ _%spin126597%_ '1)))
                      (let ((_%owner126603%_ (##vector-ref _%lock126589%_ '1)))
                        (if (eq? _%owner126603%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126603%_)
                                (let () (##thread-yield!) (_%again126594%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126609%_
                 (eq-table-set! _%tab126584%_ _%key126585%_ _%value126586%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126589%_ '1 '#f)
                (##vector-cas! _%lock126589%_ '0 '0 '1)))
            _%$r126609%_))))
    (define __eq-table-update!
      (lambda (_%tab126535%_
               _%key126536%_
               _%eq-table-update!126537%_
               _%default126538%_)
        (let ((_%table126540%_ (&raw-table-table _%tab126535%_))
              (_%seed126541%_ (&raw-table-seed _%tab126535%_)))
          (let* ((_%h126543%_ (fxxor (eq-hash _%key126536%_) _%seed126541%_))
                 (_%size126546%_ (vector-length _%table126540%_))
                 (_%entries126549%_ (##fxquotient _%size126546%_ '2))
                 (_%start126552%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126543%_ _%entries126549%_)
                   '1)))
            (let _%loop126556%_ ((_%probe126559%_ _%start126552%_)
                                 (_%i126561%_ '1)
                                 (_%deleted126563%_ '#f))
              (let ((_%k126566%_ (vector-ref _%table126540%_ _%probe126559%_)))
                (if (eq? _%k126566%_ (macro-unused-obj))
                    (if _%deleted126563%_
                        (begin
                          (vector-set!
                           _%table126540%_
                           _%deleted126563%_
                           _%key126536%_)
                          (vector-set!
                           _%table126540%_
                           (##fx+ _%deleted126563%_ '1)
                           (_%eq-table-update!126537%_ _%default126538%_))
                          (&raw-table-count-set!
                           _%tab126535%_
                           (##fx+ (&raw-table-count _%tab126535%_) '1)))
                        (begin
                          (vector-set!
                           _%table126540%_
                           _%probe126559%_
                           _%key126536%_)
                          (vector-set!
                           _%table126540%_
                           (##fx+ _%probe126559%_ '1)
                           (_%eq-table-update!126537%_ _%default126538%_))
                          (let ()
                            (&raw-table-free-set!
                             _%tab126535%_
                             (##fx- (&raw-table-free _%tab126535%_) '1))
                            (&raw-table-count-set!
                             _%tab126535%_
                             (##fx+ (&raw-table-count _%tab126535%_) '1)))))
                    (if (eq? _%k126566%_ (macro-deleted-obj))
                        (_%loop126556%_
                         (let ((_%next-probe126573%_
                                (fx+ _%start126552%_
                                     _%i126561%_
                                     (fx* _%i126561%_ _%i126561%_))))
                           (##fxmodulo _%next-probe126573%_ _%size126546%_))
                         (##fx+ _%i126561%_ '1)
                         (let ((_%$e126576%_ _%deleted126563%_))
                           (if _%$e126576%_ _%$e126576%_ _%probe126559%_)))
                        (if (eq? _%key126536%_ _%k126566%_)
                            (let ()
                              (vector-set!
                               _%table126540%_
                               _%probe126559%_
                               _%key126536%_)
                              (vector-set!
                               _%table126540%_
                               (##fx+ _%probe126559%_ '1)
                               (_%eq-table-update!126537%_
                                (vector-ref
                                 _%table126540%_
                                 (##fx+ _%probe126559%_ '1)))))
                            (_%loop126556%_
                             (let ((_%next-probe126581%_
                                    (fx+ _%start126552%_
                                         _%i126561%_
                                         (fx* _%i126561%_ _%i126561%_))))
                               (##fxmodulo
                                _%next-probe126581%_
                                _%size126546%_))
                             (##fx+ _%i126561%_ '1)
                             _%deleted126563%_))))))))))
    (define eq-table-update!
      (lambda (_%tab126530%_
               _%key126531%_
               _%eq-table-update!126532%_
               _%default126533%_)
        (if (##fx< (&raw-table-free _%tab126530%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab126530%_))
                    '4))
            (__raw-table-rehash! _%tab126530%_)
            '#!void)
        (__eq-table-update!
         _%tab126530%_
         _%key126531%_
         _%eq-table-update!126532%_
         _%default126533%_)))
    (define eq-table-update!/lock
      (lambda (_%tab126499%_
               _%key126500%_
               _%eq-table-update!126501%_
               _%default126502%_)
        (let ((_%lock126505%_ (&raw-table-lock _%tab126499%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126510%_ ((_%spin126513%_ '0))
              (if (##fx= (##vector-cas! _%lock126505%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126505%_ '1 (current-thread))
                  (if (##fx< _%spin126513%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126510%_ (##fx+ _%spin126513%_ '1)))
                      (let ((_%owner126519%_ (##vector-ref _%lock126505%_ '1)))
                        (if (eq? _%owner126519%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126519%_)
                                (let () (##thread-yield!) (_%again126510%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126525%_
                 (_%eq-table-update!126501%_
                  _%tab126499%_
                  _%key126500%_
                  _%eq-table-update!126501%_
                  _%default126502%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126505%_ '1 '#f)
                (##vector-cas! _%lock126505%_ '0 '0 '1)))
            _%$r126525%_))))
    (define eq-table-delete!
      (lambda (_%tab126456%_ _%key126457%_)
        (let ((_%table126459%_ (&raw-table-table _%tab126456%_))
              (_%seed126461%_ (&raw-table-seed _%tab126456%_)))
          (let* ((_%h126464%_ (fxxor (eq-hash _%key126457%_) _%seed126461%_))
                 (_%size126467%_ (vector-length _%table126459%_))
                 (_%entries126470%_ (##fxquotient _%size126467%_ '2))
                 (_%start126473%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126464%_ _%entries126470%_)
                   '1)))
            (let _%loop126477%_ ((_%probe126480%_ _%start126473%_)
                                 (_%i126482%_ '1))
              (let ((_%k126485%_ (vector-ref _%table126459%_ _%probe126480%_)))
                (if (eq? _%k126485%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k126485%_ (macro-deleted-obj))
                        (_%loop126477%_
                         (let ((_%next-probe126490%_
                                (fx+ _%start126473%_
                                     _%i126482%_
                                     (fx* _%i126482%_ _%i126482%_))))
                           (##fxmodulo _%next-probe126490%_ _%size126467%_))
                         (##fx+ _%i126482%_ '1))
                        (if (eq? _%key126457%_ _%k126485%_)
                            (let ()
                              (vector-set!
                               _%table126459%_
                               _%probe126480%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table126459%_
                               (##fx+ _%probe126480%_ '1)
                               (macro-absent-obj))
                              (&raw-table-count-set!
                               _%tab126456%_
                               (##fx- (&raw-table-count _%tab126456%_) '1)))
                            (_%loop126477%_
                             (let ((_%next-probe126496%_
                                    (fx+ _%start126473%_
                                         _%i126482%_
                                         (fx* _%i126482%_ _%i126482%_))))
                               (##fxmodulo
                                _%next-probe126496%_
                                _%size126467%_))
                             (##fx+ _%i126482%_ '1)))))))))))
    (define eq-table-delete!/lock
      (lambda (_%tab126426%_ _%key126428%_)
        (let ((_%lock126431%_ (&raw-table-lock _%tab126426%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126436%_ ((_%spin126439%_ '0))
              (if (##fx= (##vector-cas! _%lock126431%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126431%_ '1 (current-thread))
                  (if (##fx< _%spin126439%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126436%_ (##fx+ _%spin126439%_ '1)))
                      (let ((_%owner126445%_ (##vector-ref _%lock126431%_ '1)))
                        (if (eq? _%owner126445%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126445%_)
                                (let () (##thread-yield!) (_%again126436%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126451%_ (eq-table-delete! _%tab126426%_ _%key126428%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126431%_ '1 '#f)
                (##vector-cas! _%lock126431%_ '0 '0 '1)))
            _%$r126451%_))))
    (define make-eqv-table__%
      (lambda (_%size-hint126408%_ _%seed126409%_)
        (make-raw-table__1 _%size-hint126408%_ eqv-hash eqv? _%seed126409%_)))
    (define make-eqv-table__0
      (lambda ()
        (let* ((_%size-hint126415%_ '#f) (_%seed126417%_ '0))
          (make-eqv-table__% _%size-hint126415%_ _%seed126417%_))))
    (define make-eqv-table__1
      (lambda (_%size-hint126419%_)
        (let ((_%seed126421%_ '0))
          (make-eqv-table__% _%size-hint126419%_ _%seed126421%_))))
    (define make-eqv-table
      (lambda _g127406_
        (let ((_g127407_ (##length _g127406_)))
          (cond ((##fx= _g127407_ 0) (apply make-eqv-table__0 _g127406_))
                ((##fx= _g127407_ 1) (apply make-eqv-table__1 _g127406_))
                ((##fx= _g127407_ 2) (apply make-eqv-table__% _g127406_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-eqv-table
                  _g127406_))))))
    (define make-eqv-table/lock__%
      (lambda (_%size-hint126388%_ _%seed126390%_)
        (make-raw-table/lock__%
         _%size-hint126388%_
         eqv-hash
         eqv?
         _%seed126390%_)))
    (define make-eqv-table/lock__0
      (lambda ()
        (let* ((_%size-hint126396%_ '#f) (_%seed126398%_ '0))
          (make-eqv-table/lock__% _%size-hint126396%_ _%seed126398%_))))
    (define make-eqv-table/lock__1
      (lambda (_%size-hint126400%_)
        (let ((_%seed126402%_ '0))
          (make-eqv-table/lock__% _%size-hint126400%_ _%seed126402%_))))
    (define make-eqv-table/lock
      (lambda _g127408_
        (let ((_g127409_ (##length _g127408_)))
          (cond ((##fx= _g127409_ 0) (apply make-eqv-table/lock__0 _g127408_))
                ((##fx= _g127409_ 1) (apply make-eqv-table/lock__1 _g127408_))
                ((##fx= _g127409_ 2) (apply make-eqv-table/lock__% _g127408_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-eqv-table/lock
                  _g127408_))))))
    (define eqv-table-ref
      (lambda (_%tab126341%_ _%key126342%_ _%default126343%_)
        (let ((_%table126345%_ (&raw-table-table _%tab126341%_))
              (_%seed126346%_ (&raw-table-seed _%tab126341%_)))
          (let* ((_%h126348%_ (fxxor (eqv-hash _%key126342%_) _%seed126346%_))
                 (_%size126351%_ (vector-length _%table126345%_))
                 (_%entries126354%_ (##fxquotient _%size126351%_ '2))
                 (_%start126357%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126348%_ _%entries126354%_)
                   '1)))
            (let _%loop126361%_ ((_%probe126364%_ _%start126357%_)
                                 (_%i126366%_ '1)
                                 (_%deleted126368%_ '#f))
              (let ((_%k126371%_ (vector-ref _%table126345%_ _%probe126364%_)))
                (if (eq? _%k126371%_ (macro-unused-obj))
                    _%default126343%_
                    (if (eq? _%k126371%_ (macro-deleted-obj))
                        (_%loop126361%_
                         (let ((_%next-probe126376%_
                                (fx+ _%start126357%_
                                     _%i126366%_
                                     (fx* _%i126366%_ _%i126366%_))))
                           (##fxmodulo _%next-probe126376%_ _%size126351%_))
                         (##fx+ _%i126366%_ '1)
                         (let ((_%$e126379%_ _%deleted126368%_))
                           (if _%$e126379%_ _%$e126379%_ _%probe126364%_)))
                        (if (eqv? _%key126342%_ _%k126371%_)
                            (vector-ref
                             _%table126345%_
                             (##fx+ _%probe126364%_ '1))
                            (_%loop126361%_
                             (let ((_%next-probe126384%_
                                    (fx+ _%start126357%_
                                         _%i126366%_
                                         (fx* _%i126366%_ _%i126366%_))))
                               (##fxmodulo
                                _%next-probe126384%_
                                _%size126351%_))
                             (##fx+ _%i126366%_ '1)
                             _%deleted126368%_))))))))))
    (define eqv-table-ref/lock
      (lambda (_%tab126312%_ _%key126313%_ _%default126314%_)
        (let ((_%lock126316%_ (&raw-table-lock _%tab126312%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126321%_ ((_%spin126324%_ '0))
              (if (##fx= (##vector-cas! _%lock126316%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126316%_ '1 (current-thread))
                  (if (##fx< _%spin126324%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126321%_ (##fx+ _%spin126324%_ '1)))
                      (let ((_%owner126330%_ (##vector-ref _%lock126316%_ '1)))
                        (if (eq? _%owner126330%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126330%_)
                                (let () (##thread-yield!) (_%again126321%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126336%_
                 (eqv-table-ref
                  _%tab126312%_
                  _%key126313%_
                  _%default126314%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126316%_ '1 '#f)
                (##vector-cas! _%lock126316%_ '0 '0 '1)))
            _%$r126336%_))))
    (define __eqv-table-set!
      (lambda (_%tab126264%_ _%key126265%_ _%value126266%_)
        (let ((_%table126268%_ (&raw-table-table _%tab126264%_))
              (_%seed126269%_ (&raw-table-seed _%tab126264%_)))
          (let* ((_%h126271%_ (fxxor (eqv-hash _%key126265%_) _%seed126269%_))
                 (_%size126274%_ (vector-length _%table126268%_))
                 (_%entries126277%_ (##fxquotient _%size126274%_ '2))
                 (_%start126280%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126271%_ _%entries126277%_)
                   '1)))
            (let _%loop126284%_ ((_%probe126287%_ _%start126280%_)
                                 (_%i126289%_ '1)
                                 (_%deleted126291%_ '#f))
              (let ((_%k126294%_ (vector-ref _%table126268%_ _%probe126287%_)))
                (if (eq? _%k126294%_ (macro-unused-obj))
                    (if _%deleted126291%_
                        (begin
                          (vector-set!
                           _%table126268%_
                           _%deleted126291%_
                           _%key126265%_)
                          (vector-set!
                           _%table126268%_
                           (##fx+ _%deleted126291%_ '1)
                           _%value126266%_)
                          (&raw-table-count-set!
                           _%tab126264%_
                           (##fx+ (&raw-table-count _%tab126264%_) '1)))
                        (begin
                          (vector-set!
                           _%table126268%_
                           _%probe126287%_
                           _%key126265%_)
                          (vector-set!
                           _%table126268%_
                           (##fx+ _%probe126287%_ '1)
                           _%value126266%_)
                          (let ()
                            (&raw-table-free-set!
                             _%tab126264%_
                             (##fx- (&raw-table-free _%tab126264%_) '1))
                            (&raw-table-count-set!
                             _%tab126264%_
                             (##fx+ (&raw-table-count _%tab126264%_) '1)))))
                    (if (eq? _%k126294%_ (macro-deleted-obj))
                        (_%loop126284%_
                         (let ((_%next-probe126301%_
                                (fx+ _%start126280%_
                                     _%i126289%_
                                     (fx* _%i126289%_ _%i126289%_))))
                           (##fxmodulo _%next-probe126301%_ _%size126274%_))
                         (##fx+ _%i126289%_ '1)
                         (let ((_%$e126304%_ _%deleted126291%_))
                           (if _%$e126304%_ _%$e126304%_ _%probe126287%_)))
                        (if (eqv? _%key126265%_ _%k126294%_)
                            (let ()
                              (vector-set!
                               _%table126268%_
                               _%probe126287%_
                               _%key126265%_)
                              (vector-set!
                               _%table126268%_
                               (##fx+ _%probe126287%_ '1)
                               _%value126266%_))
                            (_%loop126284%_
                             (let ((_%next-probe126309%_
                                    (fx+ _%start126280%_
                                         _%i126289%_
                                         (fx* _%i126289%_ _%i126289%_))))
                               (##fxmodulo
                                _%next-probe126309%_
                                _%size126274%_))
                             (##fx+ _%i126289%_ '1)
                             _%deleted126291%_))))))))))
    (define eqv-table-set!
      (lambda (_%tab126260%_ _%key126261%_ _%value126262%_)
        (if (##fx< (&raw-table-free _%tab126260%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab126260%_))
                    '4))
            (__raw-table-rehash! _%tab126260%_)
            '#!void)
        (__eqv-table-set! _%tab126260%_ _%key126261%_ _%value126262%_)))
    (define eqv-table-set!/lock
      (lambda (_%tab126230%_ _%key126231%_ _%value126232%_)
        (let ((_%lock126235%_ (&raw-table-lock _%tab126230%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126240%_ ((_%spin126243%_ '0))
              (if (##fx= (##vector-cas! _%lock126235%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126235%_ '1 (current-thread))
                  (if (##fx< _%spin126243%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126240%_ (##fx+ _%spin126243%_ '1)))
                      (let ((_%owner126249%_ (##vector-ref _%lock126235%_ '1)))
                        (if (eq? _%owner126249%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126249%_)
                                (let () (##thread-yield!) (_%again126240%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126255%_
                 (eqv-table-set! _%tab126230%_ _%key126231%_ _%value126232%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126235%_ '1 '#f)
                (##vector-cas! _%lock126235%_ '0 '0 '1)))
            _%$r126255%_))))
    (define __eqv-table-update!
      (lambda (_%tab126181%_
               _%key126182%_
               _%eqv-table-update!126183%_
               _%default126184%_)
        (let ((_%table126186%_ (&raw-table-table _%tab126181%_))
              (_%seed126187%_ (&raw-table-seed _%tab126181%_)))
          (let* ((_%h126189%_ (fxxor (eqv-hash _%key126182%_) _%seed126187%_))
                 (_%size126192%_ (vector-length _%table126186%_))
                 (_%entries126195%_ (##fxquotient _%size126192%_ '2))
                 (_%start126198%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126189%_ _%entries126195%_)
                   '1)))
            (let _%loop126202%_ ((_%probe126205%_ _%start126198%_)
                                 (_%i126207%_ '1)
                                 (_%deleted126209%_ '#f))
              (let ((_%k126212%_ (vector-ref _%table126186%_ _%probe126205%_)))
                (if (eq? _%k126212%_ (macro-unused-obj))
                    (if _%deleted126209%_
                        (begin
                          (vector-set!
                           _%table126186%_
                           _%deleted126209%_
                           _%key126182%_)
                          (vector-set!
                           _%table126186%_
                           (##fx+ _%deleted126209%_ '1)
                           (_%eqv-table-update!126183%_ _%default126184%_))
                          (&raw-table-count-set!
                           _%tab126181%_
                           (##fx+ (&raw-table-count _%tab126181%_) '1)))
                        (begin
                          (vector-set!
                           _%table126186%_
                           _%probe126205%_
                           _%key126182%_)
                          (vector-set!
                           _%table126186%_
                           (##fx+ _%probe126205%_ '1)
                           (_%eqv-table-update!126183%_ _%default126184%_))
                          (let ()
                            (&raw-table-free-set!
                             _%tab126181%_
                             (##fx- (&raw-table-free _%tab126181%_) '1))
                            (&raw-table-count-set!
                             _%tab126181%_
                             (##fx+ (&raw-table-count _%tab126181%_) '1)))))
                    (if (eq? _%k126212%_ (macro-deleted-obj))
                        (_%loop126202%_
                         (let ((_%next-probe126219%_
                                (fx+ _%start126198%_
                                     _%i126207%_
                                     (fx* _%i126207%_ _%i126207%_))))
                           (##fxmodulo _%next-probe126219%_ _%size126192%_))
                         (##fx+ _%i126207%_ '1)
                         (let ((_%$e126222%_ _%deleted126209%_))
                           (if _%$e126222%_ _%$e126222%_ _%probe126205%_)))
                        (if (eqv? _%key126182%_ _%k126212%_)
                            (let ()
                              (vector-set!
                               _%table126186%_
                               _%probe126205%_
                               _%key126182%_)
                              (vector-set!
                               _%table126186%_
                               (##fx+ _%probe126205%_ '1)
                               (_%eqv-table-update!126183%_
                                (vector-ref
                                 _%table126186%_
                                 (##fx+ _%probe126205%_ '1)))))
                            (_%loop126202%_
                             (let ((_%next-probe126227%_
                                    (fx+ _%start126198%_
                                         _%i126207%_
                                         (fx* _%i126207%_ _%i126207%_))))
                               (##fxmodulo
                                _%next-probe126227%_
                                _%size126192%_))
                             (##fx+ _%i126207%_ '1)
                             _%deleted126209%_))))))))))
    (define eqv-table-update!
      (lambda (_%tab126176%_
               _%key126177%_
               _%eqv-table-update!126178%_
               _%default126179%_)
        (if (##fx< (&raw-table-free _%tab126176%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab126176%_))
                    '4))
            (__raw-table-rehash! _%tab126176%_)
            '#!void)
        (__eqv-table-update!
         _%tab126176%_
         _%key126177%_
         _%eqv-table-update!126178%_
         _%default126179%_)))
    (define eqv-table-update!/lock
      (lambda (_%tab126145%_
               _%key126146%_
               _%eqv-table-update!126147%_
               _%default126148%_)
        (let ((_%lock126151%_ (&raw-table-lock _%tab126145%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126156%_ ((_%spin126159%_ '0))
              (if (##fx= (##vector-cas! _%lock126151%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126151%_ '1 (current-thread))
                  (if (##fx< _%spin126159%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126156%_ (##fx+ _%spin126159%_ '1)))
                      (let ((_%owner126165%_ (##vector-ref _%lock126151%_ '1)))
                        (if (eq? _%owner126165%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126165%_)
                                (let () (##thread-yield!) (_%again126156%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126171%_
                 (_%eqv-table-update!126147%_
                  _%tab126145%_
                  _%key126146%_
                  _%eqv-table-update!126147%_
                  _%default126148%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126151%_ '1 '#f)
                (##vector-cas! _%lock126151%_ '0 '0 '1)))
            _%$r126171%_))))
    (define eqv-table-delete!
      (lambda (_%tab126102%_ _%key126103%_)
        (let ((_%table126105%_ (&raw-table-table _%tab126102%_))
              (_%seed126107%_ (&raw-table-seed _%tab126102%_)))
          (let* ((_%h126110%_ (fxxor (eqv-hash _%key126103%_) _%seed126107%_))
                 (_%size126113%_ (vector-length _%table126105%_))
                 (_%entries126116%_ (##fxquotient _%size126113%_ '2))
                 (_%start126119%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h126110%_ _%entries126116%_)
                   '1)))
            (let _%loop126123%_ ((_%probe126126%_ _%start126119%_)
                                 (_%i126128%_ '1))
              (let ((_%k126131%_ (vector-ref _%table126105%_ _%probe126126%_)))
                (if (eq? _%k126131%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k126131%_ (macro-deleted-obj))
                        (_%loop126123%_
                         (let ((_%next-probe126136%_
                                (fx+ _%start126119%_
                                     _%i126128%_
                                     (fx* _%i126128%_ _%i126128%_))))
                           (##fxmodulo _%next-probe126136%_ _%size126113%_))
                         (##fx+ _%i126128%_ '1))
                        (if (eqv? _%key126103%_ _%k126131%_)
                            (let ()
                              (vector-set!
                               _%table126105%_
                               _%probe126126%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table126105%_
                               (##fx+ _%probe126126%_ '1)
                               (macro-absent-obj))
                              (&raw-table-count-set!
                               _%tab126102%_
                               (##fx- (&raw-table-count _%tab126102%_) '1)))
                            (_%loop126123%_
                             (let ((_%next-probe126142%_
                                    (fx+ _%start126119%_
                                         _%i126128%_
                                         (fx* _%i126128%_ _%i126128%_))))
                               (##fxmodulo
                                _%next-probe126142%_
                                _%size126113%_))
                             (##fx+ _%i126128%_ '1)))))))))))
    (define eqv-table-delete!/lock
      (lambda (_%tab126072%_ _%key126074%_)
        (let ((_%lock126077%_ (&raw-table-lock _%tab126072%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again126082%_ ((_%spin126085%_ '0))
              (if (##fx= (##vector-cas! _%lock126077%_ '0 '1 '0) '0)
                  (##vector-set! _%lock126077%_ '1 (current-thread))
                  (if (##fx< _%spin126085%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again126082%_ (##fx+ _%spin126085%_ '1)))
                      (let ((_%owner126091%_ (##vector-ref _%lock126077%_ '1)))
                        (if (eq? _%owner126091%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner126091%_)
                                (let () (##thread-yield!) (_%again126082%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r126097%_ (eqv-table-delete! _%tab126072%_ _%key126074%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock126077%_ '1 '#f)
                (##vector-cas! _%lock126077%_ '0 '0 '1)))
            _%$r126097%_))))
    (define make-symbolic-table__%
      (lambda (_%size-hint126054%_ _%seed126055%_)
        (make-raw-table__1
         _%size-hint126054%_
         symbolic-hash
         eq?
         _%seed126055%_)))
    (define make-symbolic-table__0
      (lambda ()
        (let* ((_%size-hint126061%_ '#f) (_%seed126063%_ '0))
          (make-symbolic-table__% _%size-hint126061%_ _%seed126063%_))))
    (define make-symbolic-table__1
      (lambda (_%size-hint126065%_)
        (let ((_%seed126067%_ '0))
          (make-symbolic-table__% _%size-hint126065%_ _%seed126067%_))))
    (define make-symbolic-table
      (lambda _g127410_
        (let ((_g127411_ (##length _g127410_)))
          (cond ((##fx= _g127411_ 0) (apply make-symbolic-table__0 _g127410_))
                ((##fx= _g127411_ 1) (apply make-symbolic-table__1 _g127410_))
                ((##fx= _g127411_ 2) (apply make-symbolic-table__% _g127410_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-symbolic-table
                  _g127410_))))))
    (define make-symbolic-table/lock__%
      (lambda (_%size-hint126034%_ _%seed126036%_)
        (make-raw-table/lock__%
         _%size-hint126034%_
         symbolic-hash
         eq?
         _%seed126036%_)))
    (define make-symbolic-table/lock__0
      (lambda ()
        (let* ((_%size-hint126042%_ '#f) (_%seed126044%_ '0))
          (make-symbolic-table/lock__% _%size-hint126042%_ _%seed126044%_))))
    (define make-symbolic-table/lock__1
      (lambda (_%size-hint126046%_)
        (let ((_%seed126048%_ '0))
          (make-symbolic-table/lock__% _%size-hint126046%_ _%seed126048%_))))
    (define make-symbolic-table/lock
      (lambda _g127412_
        (let ((_g127413_ (##length _g127412_)))
          (cond ((##fx= _g127413_ 0)
                 (apply make-symbolic-table/lock__0 _g127412_))
                ((##fx= _g127413_ 1)
                 (apply make-symbolic-table/lock__1 _g127412_))
                ((##fx= _g127413_ 2)
                 (apply make-symbolic-table/lock__% _g127412_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-symbolic-table/lock
                  _g127412_))))))
    (define symbolic-table-ref
      (lambda (_%tab125987%_ _%key125988%_ _%default125989%_)
        (let ((_%table125991%_ (&raw-table-table _%tab125987%_))
              (_%seed125992%_ (&raw-table-seed _%tab125987%_)))
          (let* ((_%h125994%_
                  (fxxor (##symbol-hash _%key125988%_) _%seed125992%_))
                 (_%size125997%_ (vector-length _%table125991%_))
                 (_%entries126000%_ (##fxquotient _%size125997%_ '2))
                 (_%start126003%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125994%_ _%entries126000%_)
                   '1)))
            (let _%loop126007%_ ((_%probe126010%_ _%start126003%_)
                                 (_%i126012%_ '1)
                                 (_%deleted126014%_ '#f))
              (let ((_%k126017%_ (vector-ref _%table125991%_ _%probe126010%_)))
                (if (eq? _%k126017%_ (macro-unused-obj))
                    _%default125989%_
                    (if (eq? _%k126017%_ (macro-deleted-obj))
                        (_%loop126007%_
                         (let ((_%next-probe126022%_
                                (fx+ _%start126003%_
                                     _%i126012%_
                                     (fx* _%i126012%_ _%i126012%_))))
                           (##fxmodulo _%next-probe126022%_ _%size125997%_))
                         (##fx+ _%i126012%_ '1)
                         (let ((_%$e126025%_ _%deleted126014%_))
                           (if _%$e126025%_ _%$e126025%_ _%probe126010%_)))
                        (if (eq? _%key125988%_ _%k126017%_)
                            (vector-ref
                             _%table125991%_
                             (##fx+ _%probe126010%_ '1))
                            (_%loop126007%_
                             (let ((_%next-probe126030%_
                                    (fx+ _%start126003%_
                                         _%i126012%_
                                         (fx* _%i126012%_ _%i126012%_))))
                               (##fxmodulo
                                _%next-probe126030%_
                                _%size125997%_))
                             (##fx+ _%i126012%_ '1)
                             _%deleted126014%_))))))))))
    (define symbolic-table-ref/lock
      (lambda (_%tab125958%_ _%key125959%_ _%default125960%_)
        (let ((_%lock125962%_ (&raw-table-lock _%tab125958%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125967%_ ((_%spin125970%_ '0))
              (if (##fx= (##vector-cas! _%lock125962%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125962%_ '1 (current-thread))
                  (if (##fx< _%spin125970%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125967%_ (##fx+ _%spin125970%_ '1)))
                      (let ((_%owner125976%_ (##vector-ref _%lock125962%_ '1)))
                        (if (eq? _%owner125976%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125976%_)
                                (let () (##thread-yield!) (_%again125967%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125982%_
                 (symbolic-table-ref
                  _%tab125958%_
                  _%key125959%_
                  _%default125960%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125962%_ '1 '#f)
                (##vector-cas! _%lock125962%_ '0 '0 '1)))
            _%$r125982%_))))
    (define __symbolic-table-set!
      (lambda (_%tab125910%_ _%key125911%_ _%value125912%_)
        (let ((_%table125914%_ (&raw-table-table _%tab125910%_))
              (_%seed125915%_ (&raw-table-seed _%tab125910%_)))
          (let* ((_%h125917%_
                  (fxxor (##symbol-hash _%key125911%_) _%seed125915%_))
                 (_%size125920%_ (vector-length _%table125914%_))
                 (_%entries125923%_ (##fxquotient _%size125920%_ '2))
                 (_%start125926%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125917%_ _%entries125923%_)
                   '1)))
            (let _%loop125930%_ ((_%probe125933%_ _%start125926%_)
                                 (_%i125935%_ '1)
                                 (_%deleted125937%_ '#f))
              (let ((_%k125940%_ (vector-ref _%table125914%_ _%probe125933%_)))
                (if (eq? _%k125940%_ (macro-unused-obj))
                    (if _%deleted125937%_
                        (begin
                          (vector-set!
                           _%table125914%_
                           _%deleted125937%_
                           _%key125911%_)
                          (vector-set!
                           _%table125914%_
                           (##fx+ _%deleted125937%_ '1)
                           _%value125912%_)
                          (&raw-table-count-set!
                           _%tab125910%_
                           (##fx+ (&raw-table-count _%tab125910%_) '1)))
                        (begin
                          (vector-set!
                           _%table125914%_
                           _%probe125933%_
                           _%key125911%_)
                          (vector-set!
                           _%table125914%_
                           (##fx+ _%probe125933%_ '1)
                           _%value125912%_)
                          (let ()
                            (&raw-table-free-set!
                             _%tab125910%_
                             (##fx- (&raw-table-free _%tab125910%_) '1))
                            (&raw-table-count-set!
                             _%tab125910%_
                             (##fx+ (&raw-table-count _%tab125910%_) '1)))))
                    (if (eq? _%k125940%_ (macro-deleted-obj))
                        (_%loop125930%_
                         (let ((_%next-probe125947%_
                                (fx+ _%start125926%_
                                     _%i125935%_
                                     (fx* _%i125935%_ _%i125935%_))))
                           (##fxmodulo _%next-probe125947%_ _%size125920%_))
                         (##fx+ _%i125935%_ '1)
                         (let ((_%$e125950%_ _%deleted125937%_))
                           (if _%$e125950%_ _%$e125950%_ _%probe125933%_)))
                        (if (eq? _%key125911%_ _%k125940%_)
                            (let ()
                              (vector-set!
                               _%table125914%_
                               _%probe125933%_
                               _%key125911%_)
                              (vector-set!
                               _%table125914%_
                               (##fx+ _%probe125933%_ '1)
                               _%value125912%_))
                            (_%loop125930%_
                             (let ((_%next-probe125955%_
                                    (fx+ _%start125926%_
                                         _%i125935%_
                                         (fx* _%i125935%_ _%i125935%_))))
                               (##fxmodulo
                                _%next-probe125955%_
                                _%size125920%_))
                             (##fx+ _%i125935%_ '1)
                             _%deleted125937%_))))))))))
    (define symbolic-table-set!
      (lambda (_%tab125906%_ _%key125907%_ _%value125908%_)
        (if (##fx< (&raw-table-free _%tab125906%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab125906%_))
                    '4))
            (__raw-table-rehash! _%tab125906%_)
            '#!void)
        (__symbolic-table-set! _%tab125906%_ _%key125907%_ _%value125908%_)))
    (define symbolic-table-set!/lock
      (lambda (_%tab125876%_ _%key125877%_ _%value125878%_)
        (let ((_%lock125881%_ (&raw-table-lock _%tab125876%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125886%_ ((_%spin125889%_ '0))
              (if (##fx= (##vector-cas! _%lock125881%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125881%_ '1 (current-thread))
                  (if (##fx< _%spin125889%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125886%_ (##fx+ _%spin125889%_ '1)))
                      (let ((_%owner125895%_ (##vector-ref _%lock125881%_ '1)))
                        (if (eq? _%owner125895%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125895%_)
                                (let () (##thread-yield!) (_%again125886%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125901%_
                 (symbolic-table-set!
                  _%tab125876%_
                  _%key125877%_
                  _%value125878%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125881%_ '1 '#f)
                (##vector-cas! _%lock125881%_ '0 '0 '1)))
            _%$r125901%_))))
    (define __symbolic-table-update!
      (lambda (_%tab125827%_
               _%key125828%_
               _%symbolic-table-update!125829%_
               _%default125830%_)
        (let ((_%table125832%_ (&raw-table-table _%tab125827%_))
              (_%seed125833%_ (&raw-table-seed _%tab125827%_)))
          (let* ((_%h125835%_
                  (fxxor (##symbol-hash _%key125828%_) _%seed125833%_))
                 (_%size125838%_ (vector-length _%table125832%_))
                 (_%entries125841%_ (##fxquotient _%size125838%_ '2))
                 (_%start125844%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125835%_ _%entries125841%_)
                   '1)))
            (let _%loop125848%_ ((_%probe125851%_ _%start125844%_)
                                 (_%i125853%_ '1)
                                 (_%deleted125855%_ '#f))
              (let ((_%k125858%_ (vector-ref _%table125832%_ _%probe125851%_)))
                (if (eq? _%k125858%_ (macro-unused-obj))
                    (if _%deleted125855%_
                        (begin
                          (vector-set!
                           _%table125832%_
                           _%deleted125855%_
                           _%key125828%_)
                          (vector-set!
                           _%table125832%_
                           (##fx+ _%deleted125855%_ '1)
                           (_%symbolic-table-update!125829%_
                            _%default125830%_))
                          (&raw-table-count-set!
                           _%tab125827%_
                           (##fx+ (&raw-table-count _%tab125827%_) '1)))
                        (begin
                          (vector-set!
                           _%table125832%_
                           _%probe125851%_
                           _%key125828%_)
                          (vector-set!
                           _%table125832%_
                           (##fx+ _%probe125851%_ '1)
                           (_%symbolic-table-update!125829%_
                            _%default125830%_))
                          (let ()
                            (&raw-table-free-set!
                             _%tab125827%_
                             (##fx- (&raw-table-free _%tab125827%_) '1))
                            (&raw-table-count-set!
                             _%tab125827%_
                             (##fx+ (&raw-table-count _%tab125827%_) '1)))))
                    (if (eq? _%k125858%_ (macro-deleted-obj))
                        (_%loop125848%_
                         (let ((_%next-probe125865%_
                                (fx+ _%start125844%_
                                     _%i125853%_
                                     (fx* _%i125853%_ _%i125853%_))))
                           (##fxmodulo _%next-probe125865%_ _%size125838%_))
                         (##fx+ _%i125853%_ '1)
                         (let ((_%$e125868%_ _%deleted125855%_))
                           (if _%$e125868%_ _%$e125868%_ _%probe125851%_)))
                        (if (eq? _%key125828%_ _%k125858%_)
                            (let ()
                              (vector-set!
                               _%table125832%_
                               _%probe125851%_
                               _%key125828%_)
                              (vector-set!
                               _%table125832%_
                               (##fx+ _%probe125851%_ '1)
                               (_%symbolic-table-update!125829%_
                                (vector-ref
                                 _%table125832%_
                                 (##fx+ _%probe125851%_ '1)))))
                            (_%loop125848%_
                             (let ((_%next-probe125873%_
                                    (fx+ _%start125844%_
                                         _%i125853%_
                                         (fx* _%i125853%_ _%i125853%_))))
                               (##fxmodulo
                                _%next-probe125873%_
                                _%size125838%_))
                             (##fx+ _%i125853%_ '1)
                             _%deleted125855%_))))))))))
    (define symbolic-table-update!
      (lambda (_%tab125822%_
               _%key125823%_
               _%symbolic-table-update!125824%_
               _%default125825%_)
        (if (##fx< (&raw-table-free _%tab125822%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab125822%_))
                    '4))
            (__raw-table-rehash! _%tab125822%_)
            '#!void)
        (__symbolic-table-update!
         _%tab125822%_
         _%key125823%_
         _%symbolic-table-update!125824%_
         _%default125825%_)))
    (define symbolic-table-update!/lock
      (lambda (_%tab125791%_
               _%key125792%_
               _%symbolic-table-update!125793%_
               _%default125794%_)
        (let ((_%lock125797%_ (&raw-table-lock _%tab125791%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125802%_ ((_%spin125805%_ '0))
              (if (##fx= (##vector-cas! _%lock125797%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125797%_ '1 (current-thread))
                  (if (##fx< _%spin125805%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125802%_ (##fx+ _%spin125805%_ '1)))
                      (let ((_%owner125811%_ (##vector-ref _%lock125797%_ '1)))
                        (if (eq? _%owner125811%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125811%_)
                                (let () (##thread-yield!) (_%again125802%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125817%_
                 (_%symbolic-table-update!125793%_
                  _%tab125791%_
                  _%key125792%_
                  _%symbolic-table-update!125793%_
                  _%default125794%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125797%_ '1 '#f)
                (##vector-cas! _%lock125797%_ '0 '0 '1)))
            _%$r125817%_))))
    (define symbolic-table-delete!
      (lambda (_%tab125748%_ _%key125749%_)
        (let ((_%table125751%_ (&raw-table-table _%tab125748%_))
              (_%seed125753%_ (&raw-table-seed _%tab125748%_)))
          (let* ((_%h125756%_
                  (fxxor (##symbol-hash _%key125749%_) _%seed125753%_))
                 (_%size125759%_ (vector-length _%table125751%_))
                 (_%entries125762%_ (##fxquotient _%size125759%_ '2))
                 (_%start125765%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125756%_ _%entries125762%_)
                   '1)))
            (let _%loop125769%_ ((_%probe125772%_ _%start125765%_)
                                 (_%i125774%_ '1))
              (let ((_%k125777%_ (vector-ref _%table125751%_ _%probe125772%_)))
                (if (eq? _%k125777%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k125777%_ (macro-deleted-obj))
                        (_%loop125769%_
                         (let ((_%next-probe125782%_
                                (fx+ _%start125765%_
                                     _%i125774%_
                                     (fx* _%i125774%_ _%i125774%_))))
                           (##fxmodulo _%next-probe125782%_ _%size125759%_))
                         (##fx+ _%i125774%_ '1))
                        (if (eq? _%key125749%_ _%k125777%_)
                            (let ()
                              (vector-set!
                               _%table125751%_
                               _%probe125772%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table125751%_
                               (##fx+ _%probe125772%_ '1)
                               (macro-absent-obj))
                              (&raw-table-count-set!
                               _%tab125748%_
                               (##fx- (&raw-table-count _%tab125748%_) '1)))
                            (_%loop125769%_
                             (let ((_%next-probe125788%_
                                    (fx+ _%start125765%_
                                         _%i125774%_
                                         (fx* _%i125774%_ _%i125774%_))))
                               (##fxmodulo
                                _%next-probe125788%_
                                _%size125759%_))
                             (##fx+ _%i125774%_ '1)))))))))))
    (define symbolic-table-delete!/lock
      (lambda (_%tab125718%_ _%key125720%_)
        (let ((_%lock125723%_ (&raw-table-lock _%tab125718%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125728%_ ((_%spin125731%_ '0))
              (if (##fx= (##vector-cas! _%lock125723%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125723%_ '1 (current-thread))
                  (if (##fx< _%spin125731%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125728%_ (##fx+ _%spin125731%_ '1)))
                      (let ((_%owner125737%_ (##vector-ref _%lock125723%_ '1)))
                        (if (eq? _%owner125737%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125737%_)
                                (let () (##thread-yield!) (_%again125728%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125743%_
                 (symbolic-table-delete! _%tab125718%_ _%key125720%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125723%_ '1 '#f)
                (##vector-cas! _%lock125723%_ '0 '0 '1)))
            _%$r125743%_))))
    (define make-string-table__%
      (lambda (_%size-hint125700%_ _%seed125701%_)
        (make-raw-table__1
         _%size-hint125700%_
         string-hash
         ##string=?
         _%seed125701%_)))
    (define make-string-table__0
      (lambda ()
        (let* ((_%size-hint125707%_ '#f) (_%seed125709%_ '0))
          (make-string-table__% _%size-hint125707%_ _%seed125709%_))))
    (define make-string-table__1
      (lambda (_%size-hint125711%_)
        (let ((_%seed125713%_ '0))
          (make-string-table__% _%size-hint125711%_ _%seed125713%_))))
    (define make-string-table
      (lambda _g127414_
        (let ((_g127415_ (##length _g127414_)))
          (cond ((##fx= _g127415_ 0) (apply make-string-table__0 _g127414_))
                ((##fx= _g127415_ 1) (apply make-string-table__1 _g127414_))
                ((##fx= _g127415_ 2) (apply make-string-table__% _g127414_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-string-table
                  _g127414_))))))
    (define make-string-table/lock__%
      (lambda (_%size-hint125680%_ _%seed125682%_)
        (make-raw-table/lock__%
         _%size-hint125680%_
         string-hash
         ##string=?
         _%seed125682%_)))
    (define make-string-table/lock__0
      (lambda ()
        (let* ((_%size-hint125688%_ '#f) (_%seed125690%_ '0))
          (make-string-table/lock__% _%size-hint125688%_ _%seed125690%_))))
    (define make-string-table/lock__1
      (lambda (_%size-hint125692%_)
        (let ((_%seed125694%_ '0))
          (make-string-table/lock__% _%size-hint125692%_ _%seed125694%_))))
    (define make-string-table/lock
      (lambda _g127416_
        (let ((_g127417_ (##length _g127416_)))
          (cond ((##fx= _g127417_ 0)
                 (apply make-string-table/lock__0 _g127416_))
                ((##fx= _g127417_ 1)
                 (apply make-string-table/lock__1 _g127416_))
                ((##fx= _g127417_ 2)
                 (apply make-string-table/lock__% _g127416_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-string-table/lock
                  _g127416_))))))
    (define string-table-ref
      (lambda (_%tab125633%_ _%key125634%_ _%default125635%_)
        (let ((_%table125637%_ (&raw-table-table _%tab125633%_))
              (_%seed125638%_ (&raw-table-seed _%tab125633%_)))
          (let* ((_%h125640%_
                  (fxxor (##string=?-hash _%key125634%_) _%seed125638%_))
                 (_%size125643%_ (vector-length _%table125637%_))
                 (_%entries125646%_ (##fxquotient _%size125643%_ '2))
                 (_%start125649%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125640%_ _%entries125646%_)
                   '1)))
            (let _%loop125653%_ ((_%probe125656%_ _%start125649%_)
                                 (_%i125658%_ '1)
                                 (_%deleted125660%_ '#f))
              (let ((_%k125663%_ (vector-ref _%table125637%_ _%probe125656%_)))
                (if (eq? _%k125663%_ (macro-unused-obj))
                    _%default125635%_
                    (if (eq? _%k125663%_ (macro-deleted-obj))
                        (_%loop125653%_
                         (let ((_%next-probe125668%_
                                (fx+ _%start125649%_
                                     _%i125658%_
                                     (fx* _%i125658%_ _%i125658%_))))
                           (##fxmodulo _%next-probe125668%_ _%size125643%_))
                         (##fx+ _%i125658%_ '1)
                         (let ((_%$e125671%_ _%deleted125660%_))
                           (if _%$e125671%_ _%$e125671%_ _%probe125656%_)))
                        (if (##string=? _%key125634%_ _%k125663%_)
                            (vector-ref
                             _%table125637%_
                             (##fx+ _%probe125656%_ '1))
                            (_%loop125653%_
                             (let ((_%next-probe125676%_
                                    (fx+ _%start125649%_
                                         _%i125658%_
                                         (fx* _%i125658%_ _%i125658%_))))
                               (##fxmodulo
                                _%next-probe125676%_
                                _%size125643%_))
                             (##fx+ _%i125658%_ '1)
                             _%deleted125660%_))))))))))
    (define string-table-ref/lock
      (lambda (_%tab125604%_ _%key125605%_ _%default125606%_)
        (let ((_%lock125608%_ (&raw-table-lock _%tab125604%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125613%_ ((_%spin125616%_ '0))
              (if (##fx= (##vector-cas! _%lock125608%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125608%_ '1 (current-thread))
                  (if (##fx< _%spin125616%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125613%_ (##fx+ _%spin125616%_ '1)))
                      (let ((_%owner125622%_ (##vector-ref _%lock125608%_ '1)))
                        (if (eq? _%owner125622%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125622%_)
                                (let () (##thread-yield!) (_%again125613%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125628%_
                 (string-table-ref
                  _%tab125604%_
                  _%key125605%_
                  _%default125606%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125608%_ '1 '#f)
                (##vector-cas! _%lock125608%_ '0 '0 '1)))
            _%$r125628%_))))
    (define __string-table-set!
      (lambda (_%tab125556%_ _%key125557%_ _%value125558%_)
        (let ((_%table125560%_ (&raw-table-table _%tab125556%_))
              (_%seed125561%_ (&raw-table-seed _%tab125556%_)))
          (let* ((_%h125563%_
                  (fxxor (##string=?-hash _%key125557%_) _%seed125561%_))
                 (_%size125566%_ (vector-length _%table125560%_))
                 (_%entries125569%_ (##fxquotient _%size125566%_ '2))
                 (_%start125572%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125563%_ _%entries125569%_)
                   '1)))
            (let _%loop125576%_ ((_%probe125579%_ _%start125572%_)
                                 (_%i125581%_ '1)
                                 (_%deleted125583%_ '#f))
              (let ((_%k125586%_ (vector-ref _%table125560%_ _%probe125579%_)))
                (if (eq? _%k125586%_ (macro-unused-obj))
                    (if _%deleted125583%_
                        (begin
                          (vector-set!
                           _%table125560%_
                           _%deleted125583%_
                           _%key125557%_)
                          (vector-set!
                           _%table125560%_
                           (##fx+ _%deleted125583%_ '1)
                           _%value125558%_)
                          (&raw-table-count-set!
                           _%tab125556%_
                           (##fx+ (&raw-table-count _%tab125556%_) '1)))
                        (begin
                          (vector-set!
                           _%table125560%_
                           _%probe125579%_
                           _%key125557%_)
                          (vector-set!
                           _%table125560%_
                           (##fx+ _%probe125579%_ '1)
                           _%value125558%_)
                          (let ()
                            (&raw-table-free-set!
                             _%tab125556%_
                             (##fx- (&raw-table-free _%tab125556%_) '1))
                            (&raw-table-count-set!
                             _%tab125556%_
                             (##fx+ (&raw-table-count _%tab125556%_) '1)))))
                    (if (eq? _%k125586%_ (macro-deleted-obj))
                        (_%loop125576%_
                         (let ((_%next-probe125593%_
                                (fx+ _%start125572%_
                                     _%i125581%_
                                     (fx* _%i125581%_ _%i125581%_))))
                           (##fxmodulo _%next-probe125593%_ _%size125566%_))
                         (##fx+ _%i125581%_ '1)
                         (let ((_%$e125596%_ _%deleted125583%_))
                           (if _%$e125596%_ _%$e125596%_ _%probe125579%_)))
                        (if (##string=? _%key125557%_ _%k125586%_)
                            (let ()
                              (vector-set!
                               _%table125560%_
                               _%probe125579%_
                               _%key125557%_)
                              (vector-set!
                               _%table125560%_
                               (##fx+ _%probe125579%_ '1)
                               _%value125558%_))
                            (_%loop125576%_
                             (let ((_%next-probe125601%_
                                    (fx+ _%start125572%_
                                         _%i125581%_
                                         (fx* _%i125581%_ _%i125581%_))))
                               (##fxmodulo
                                _%next-probe125601%_
                                _%size125566%_))
                             (##fx+ _%i125581%_ '1)
                             _%deleted125583%_))))))))))
    (define string-table-set!
      (lambda (_%tab125552%_ _%key125553%_ _%value125554%_)
        (if (##fx< (&raw-table-free _%tab125552%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab125552%_))
                    '4))
            (__raw-table-rehash! _%tab125552%_)
            '#!void)
        (__string-table-set! _%tab125552%_ _%key125553%_ _%value125554%_)))
    (define string-table-set!/lock
      (lambda (_%tab125522%_ _%key125523%_ _%value125524%_)
        (let ((_%lock125527%_ (&raw-table-lock _%tab125522%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125532%_ ((_%spin125535%_ '0))
              (if (##fx= (##vector-cas! _%lock125527%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125527%_ '1 (current-thread))
                  (if (##fx< _%spin125535%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125532%_ (##fx+ _%spin125535%_ '1)))
                      (let ((_%owner125541%_ (##vector-ref _%lock125527%_ '1)))
                        (if (eq? _%owner125541%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125541%_)
                                (let () (##thread-yield!) (_%again125532%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125547%_
                 (string-table-set!
                  _%tab125522%_
                  _%key125523%_
                  _%value125524%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125527%_ '1 '#f)
                (##vector-cas! _%lock125527%_ '0 '0 '1)))
            _%$r125547%_))))
    (define __string-table-update!
      (lambda (_%tab125473%_
               _%key125474%_
               _%string-table-update!125475%_
               _%default125476%_)
        (let ((_%table125478%_ (&raw-table-table _%tab125473%_))
              (_%seed125479%_ (&raw-table-seed _%tab125473%_)))
          (let* ((_%h125481%_
                  (fxxor (##string=?-hash _%key125474%_) _%seed125479%_))
                 (_%size125484%_ (vector-length _%table125478%_))
                 (_%entries125487%_ (##fxquotient _%size125484%_ '2))
                 (_%start125490%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125481%_ _%entries125487%_)
                   '1)))
            (let _%loop125494%_ ((_%probe125497%_ _%start125490%_)
                                 (_%i125499%_ '1)
                                 (_%deleted125501%_ '#f))
              (let ((_%k125504%_ (vector-ref _%table125478%_ _%probe125497%_)))
                (if (eq? _%k125504%_ (macro-unused-obj))
                    (if _%deleted125501%_
                        (begin
                          (vector-set!
                           _%table125478%_
                           _%deleted125501%_
                           _%key125474%_)
                          (vector-set!
                           _%table125478%_
                           (##fx+ _%deleted125501%_ '1)
                           (_%string-table-update!125475%_ _%default125476%_))
                          (&raw-table-count-set!
                           _%tab125473%_
                           (##fx+ (&raw-table-count _%tab125473%_) '1)))
                        (begin
                          (vector-set!
                           _%table125478%_
                           _%probe125497%_
                           _%key125474%_)
                          (vector-set!
                           _%table125478%_
                           (##fx+ _%probe125497%_ '1)
                           (_%string-table-update!125475%_ _%default125476%_))
                          (let ()
                            (&raw-table-free-set!
                             _%tab125473%_
                             (##fx- (&raw-table-free _%tab125473%_) '1))
                            (&raw-table-count-set!
                             _%tab125473%_
                             (##fx+ (&raw-table-count _%tab125473%_) '1)))))
                    (if (eq? _%k125504%_ (macro-deleted-obj))
                        (_%loop125494%_
                         (let ((_%next-probe125511%_
                                (fx+ _%start125490%_
                                     _%i125499%_
                                     (fx* _%i125499%_ _%i125499%_))))
                           (##fxmodulo _%next-probe125511%_ _%size125484%_))
                         (##fx+ _%i125499%_ '1)
                         (let ((_%$e125514%_ _%deleted125501%_))
                           (if _%$e125514%_ _%$e125514%_ _%probe125497%_)))
                        (if (##string=? _%key125474%_ _%k125504%_)
                            (let ()
                              (vector-set!
                               _%table125478%_
                               _%probe125497%_
                               _%key125474%_)
                              (vector-set!
                               _%table125478%_
                               (##fx+ _%probe125497%_ '1)
                               (_%string-table-update!125475%_
                                (vector-ref
                                 _%table125478%_
                                 (##fx+ _%probe125497%_ '1)))))
                            (_%loop125494%_
                             (let ((_%next-probe125519%_
                                    (fx+ _%start125490%_
                                         _%i125499%_
                                         (fx* _%i125499%_ _%i125499%_))))
                               (##fxmodulo
                                _%next-probe125519%_
                                _%size125484%_))
                             (##fx+ _%i125499%_ '1)
                             _%deleted125501%_))))))))))
    (define string-table-update!
      (lambda (_%tab125468%_
               _%key125469%_
               _%string-table-update!125470%_
               _%default125471%_)
        (if (##fx< (&raw-table-free _%tab125468%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab125468%_))
                    '4))
            (__raw-table-rehash! _%tab125468%_)
            '#!void)
        (__string-table-update!
         _%tab125468%_
         _%key125469%_
         _%string-table-update!125470%_
         _%default125471%_)))
    (define string-table-update!/lock
      (lambda (_%tab125437%_
               _%key125438%_
               _%string-table-update!125439%_
               _%default125440%_)
        (let ((_%lock125443%_ (&raw-table-lock _%tab125437%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125448%_ ((_%spin125451%_ '0))
              (if (##fx= (##vector-cas! _%lock125443%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125443%_ '1 (current-thread))
                  (if (##fx< _%spin125451%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125448%_ (##fx+ _%spin125451%_ '1)))
                      (let ((_%owner125457%_ (##vector-ref _%lock125443%_ '1)))
                        (if (eq? _%owner125457%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125457%_)
                                (let () (##thread-yield!) (_%again125448%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125463%_
                 (_%string-table-update!125439%_
                  _%tab125437%_
                  _%key125438%_
                  _%string-table-update!125439%_
                  _%default125440%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125443%_ '1 '#f)
                (##vector-cas! _%lock125443%_ '0 '0 '1)))
            _%$r125463%_))))
    (define string-table-delete!
      (lambda (_%tab125394%_ _%key125395%_)
        (let ((_%table125397%_ (&raw-table-table _%tab125394%_))
              (_%seed125399%_ (&raw-table-seed _%tab125394%_)))
          (let* ((_%h125402%_
                  (fxxor (##string=?-hash _%key125395%_) _%seed125399%_))
                 (_%size125405%_ (vector-length _%table125397%_))
                 (_%entries125408%_ (##fxquotient _%size125405%_ '2))
                 (_%start125411%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125402%_ _%entries125408%_)
                   '1)))
            (let _%loop125415%_ ((_%probe125418%_ _%start125411%_)
                                 (_%i125420%_ '1))
              (let ((_%k125423%_ (vector-ref _%table125397%_ _%probe125418%_)))
                (if (eq? _%k125423%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k125423%_ (macro-deleted-obj))
                        (_%loop125415%_
                         (let ((_%next-probe125428%_
                                (fx+ _%start125411%_
                                     _%i125420%_
                                     (fx* _%i125420%_ _%i125420%_))))
                           (##fxmodulo _%next-probe125428%_ _%size125405%_))
                         (##fx+ _%i125420%_ '1))
                        (if (##string=? _%key125395%_ _%k125423%_)
                            (let ()
                              (vector-set!
                               _%table125397%_
                               _%probe125418%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table125397%_
                               (##fx+ _%probe125418%_ '1)
                               (macro-absent-obj))
                              (&raw-table-count-set!
                               _%tab125394%_
                               (##fx- (&raw-table-count _%tab125394%_) '1)))
                            (_%loop125415%_
                             (let ((_%next-probe125434%_
                                    (fx+ _%start125411%_
                                         _%i125420%_
                                         (fx* _%i125420%_ _%i125420%_))))
                               (##fxmodulo
                                _%next-probe125434%_
                                _%size125405%_))
                             (##fx+ _%i125420%_ '1)))))))))))
    (define string-table-delete!/lock
      (lambda (_%tab125364%_ _%key125366%_)
        (let ((_%lock125369%_ (&raw-table-lock _%tab125364%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125374%_ ((_%spin125377%_ '0))
              (if (##fx= (##vector-cas! _%lock125369%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125369%_ '1 (current-thread))
                  (if (##fx< _%spin125377%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125374%_ (##fx+ _%spin125377%_ '1)))
                      (let ((_%owner125383%_ (##vector-ref _%lock125369%_ '1)))
                        (if (eq? _%owner125383%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125383%_)
                                (let () (##thread-yield!) (_%again125374%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125389%_
                 (string-table-delete! _%tab125364%_ _%key125366%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125369%_ '1 '#f)
                (##vector-cas! _%lock125369%_ '0 '0 '1)))
            _%$r125389%_))))
    (define make-immediate-table__%
      (lambda (_%size-hint125346%_ _%seed125347%_)
        (make-raw-table__1
         _%size-hint125346%_
         immediate-hash
         eq?
         _%seed125347%_)))
    (define make-immediate-table__0
      (lambda ()
        (let* ((_%size-hint125353%_ '#f) (_%seed125355%_ '0))
          (make-immediate-table__% _%size-hint125353%_ _%seed125355%_))))
    (define make-immediate-table__1
      (lambda (_%size-hint125357%_)
        (let ((_%seed125359%_ '0))
          (make-immediate-table__% _%size-hint125357%_ _%seed125359%_))))
    (define make-immediate-table
      (lambda _g127418_
        (let ((_g127419_ (##length _g127418_)))
          (cond ((##fx= _g127419_ 0) (apply make-immediate-table__0 _g127418_))
                ((##fx= _g127419_ 1) (apply make-immediate-table__1 _g127418_))
                ((##fx= _g127419_ 2) (apply make-immediate-table__% _g127418_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-immediate-table
                  _g127418_))))))
    (define make-immediate-table/lock__%
      (lambda (_%size-hint125326%_ _%seed125328%_)
        (make-raw-table/lock__%
         _%size-hint125326%_
         immediate-hash
         eq?
         _%seed125328%_)))
    (define make-immediate-table/lock__0
      (lambda ()
        (let* ((_%size-hint125334%_ '#f) (_%seed125336%_ '0))
          (make-immediate-table/lock__% _%size-hint125334%_ _%seed125336%_))))
    (define make-immediate-table/lock__1
      (lambda (_%size-hint125338%_)
        (let ((_%seed125340%_ '0))
          (make-immediate-table/lock__% _%size-hint125338%_ _%seed125340%_))))
    (define make-immediate-table/lock
      (lambda _g127420_
        (let ((_g127421_ (##length _g127420_)))
          (cond ((##fx= _g127421_ 0)
                 (apply make-immediate-table/lock__0 _g127420_))
                ((##fx= _g127421_ 1)
                 (apply make-immediate-table/lock__1 _g127420_))
                ((##fx= _g127421_ 2)
                 (apply make-immediate-table/lock__% _g127420_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-immediate-table/lock
                  _g127420_))))))
    (define immediate-table-ref
      (lambda (_%tab125279%_ _%key125280%_ _%default125281%_)
        (let ((_%table125283%_ (&raw-table-table _%tab125279%_))
              (_%seed125284%_ (&raw-table-seed _%tab125279%_)))
          (let* ((_%h125286%_
                  (fxxor (immediate-hash _%key125280%_) _%seed125284%_))
                 (_%size125289%_ (vector-length _%table125283%_))
                 (_%entries125292%_ (##fxquotient _%size125289%_ '2))
                 (_%start125295%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125286%_ _%entries125292%_)
                   '1)))
            (let _%loop125299%_ ((_%probe125302%_ _%start125295%_)
                                 (_%i125304%_ '1)
                                 (_%deleted125306%_ '#f))
              (let ((_%k125309%_ (vector-ref _%table125283%_ _%probe125302%_)))
                (if (eq? _%k125309%_ (macro-unused-obj))
                    _%default125281%_
                    (if (eq? _%k125309%_ (macro-deleted-obj))
                        (_%loop125299%_
                         (let ((_%next-probe125314%_
                                (fx+ _%start125295%_
                                     _%i125304%_
                                     (fx* _%i125304%_ _%i125304%_))))
                           (##fxmodulo _%next-probe125314%_ _%size125289%_))
                         (##fx+ _%i125304%_ '1)
                         (let ((_%$e125317%_ _%deleted125306%_))
                           (if _%$e125317%_ _%$e125317%_ _%probe125302%_)))
                        (if (eq? _%key125280%_ _%k125309%_)
                            (vector-ref
                             _%table125283%_
                             (##fx+ _%probe125302%_ '1))
                            (_%loop125299%_
                             (let ((_%next-probe125322%_
                                    (fx+ _%start125295%_
                                         _%i125304%_
                                         (fx* _%i125304%_ _%i125304%_))))
                               (##fxmodulo
                                _%next-probe125322%_
                                _%size125289%_))
                             (##fx+ _%i125304%_ '1)
                             _%deleted125306%_))))))))))
    (define immediate-table-ref/lock
      (lambda (_%tab125250%_ _%key125251%_ _%default125252%_)
        (let ((_%lock125254%_ (&raw-table-lock _%tab125250%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125259%_ ((_%spin125262%_ '0))
              (if (##fx= (##vector-cas! _%lock125254%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125254%_ '1 (current-thread))
                  (if (##fx< _%spin125262%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125259%_ (##fx+ _%spin125262%_ '1)))
                      (let ((_%owner125268%_ (##vector-ref _%lock125254%_ '1)))
                        (if (eq? _%owner125268%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125268%_)
                                (let () (##thread-yield!) (_%again125259%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125274%_
                 (immediate-table-ref
                  _%tab125250%_
                  _%key125251%_
                  _%default125252%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125254%_ '1 '#f)
                (##vector-cas! _%lock125254%_ '0 '0 '1)))
            _%$r125274%_))))
    (define __immediate-table-set!
      (lambda (_%tab125202%_ _%key125203%_ _%value125204%_)
        (let ((_%table125206%_ (&raw-table-table _%tab125202%_))
              (_%seed125207%_ (&raw-table-seed _%tab125202%_)))
          (let* ((_%h125209%_
                  (fxxor (immediate-hash _%key125203%_) _%seed125207%_))
                 (_%size125212%_ (vector-length _%table125206%_))
                 (_%entries125215%_ (##fxquotient _%size125212%_ '2))
                 (_%start125218%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125209%_ _%entries125215%_)
                   '1)))
            (let _%loop125222%_ ((_%probe125225%_ _%start125218%_)
                                 (_%i125227%_ '1)
                                 (_%deleted125229%_ '#f))
              (let ((_%k125232%_ (vector-ref _%table125206%_ _%probe125225%_)))
                (if (eq? _%k125232%_ (macro-unused-obj))
                    (if _%deleted125229%_
                        (begin
                          (vector-set!
                           _%table125206%_
                           _%deleted125229%_
                           _%key125203%_)
                          (vector-set!
                           _%table125206%_
                           (##fx+ _%deleted125229%_ '1)
                           _%value125204%_)
                          (&raw-table-count-set!
                           _%tab125202%_
                           (##fx+ (&raw-table-count _%tab125202%_) '1)))
                        (begin
                          (vector-set!
                           _%table125206%_
                           _%probe125225%_
                           _%key125203%_)
                          (vector-set!
                           _%table125206%_
                           (##fx+ _%probe125225%_ '1)
                           _%value125204%_)
                          (let ()
                            (&raw-table-free-set!
                             _%tab125202%_
                             (##fx- (&raw-table-free _%tab125202%_) '1))
                            (&raw-table-count-set!
                             _%tab125202%_
                             (##fx+ (&raw-table-count _%tab125202%_) '1)))))
                    (if (eq? _%k125232%_ (macro-deleted-obj))
                        (_%loop125222%_
                         (let ((_%next-probe125239%_
                                (fx+ _%start125218%_
                                     _%i125227%_
                                     (fx* _%i125227%_ _%i125227%_))))
                           (##fxmodulo _%next-probe125239%_ _%size125212%_))
                         (##fx+ _%i125227%_ '1)
                         (let ((_%$e125242%_ _%deleted125229%_))
                           (if _%$e125242%_ _%$e125242%_ _%probe125225%_)))
                        (if (eq? _%key125203%_ _%k125232%_)
                            (let ()
                              (vector-set!
                               _%table125206%_
                               _%probe125225%_
                               _%key125203%_)
                              (vector-set!
                               _%table125206%_
                               (##fx+ _%probe125225%_ '1)
                               _%value125204%_))
                            (_%loop125222%_
                             (let ((_%next-probe125247%_
                                    (fx+ _%start125218%_
                                         _%i125227%_
                                         (fx* _%i125227%_ _%i125227%_))))
                               (##fxmodulo
                                _%next-probe125247%_
                                _%size125212%_))
                             (##fx+ _%i125227%_ '1)
                             _%deleted125229%_))))))))))
    (define immediate-table-set!
      (lambda (_%tab125198%_ _%key125199%_ _%value125200%_)
        (if (##fx< (&raw-table-free _%tab125198%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab125198%_))
                    '4))
            (__raw-table-rehash! _%tab125198%_)
            '#!void)
        (__immediate-table-set! _%tab125198%_ _%key125199%_ _%value125200%_)))
    (define immediate-table-set!/lock
      (lambda (_%tab125168%_ _%key125169%_ _%value125170%_)
        (let ((_%lock125173%_ (&raw-table-lock _%tab125168%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125178%_ ((_%spin125181%_ '0))
              (if (##fx= (##vector-cas! _%lock125173%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125173%_ '1 (current-thread))
                  (if (##fx< _%spin125181%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125178%_ (##fx+ _%spin125181%_ '1)))
                      (let ((_%owner125187%_ (##vector-ref _%lock125173%_ '1)))
                        (if (eq? _%owner125187%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125187%_)
                                (let () (##thread-yield!) (_%again125178%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125193%_
                 (immediate-table-set!
                  _%tab125168%_
                  _%key125169%_
                  _%value125170%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125173%_ '1 '#f)
                (##vector-cas! _%lock125173%_ '0 '0 '1)))
            _%$r125193%_))))
    (define __immediate-table-update!
      (lambda (_%tab125119%_
               _%key125120%_
               _%immediate-table-update!125121%_
               _%default125122%_)
        (let ((_%table125124%_ (&raw-table-table _%tab125119%_))
              (_%seed125125%_ (&raw-table-seed _%tab125119%_)))
          (let* ((_%h125127%_
                  (fxxor (immediate-hash _%key125120%_) _%seed125125%_))
                 (_%size125130%_ (vector-length _%table125124%_))
                 (_%entries125133%_ (##fxquotient _%size125130%_ '2))
                 (_%start125136%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125127%_ _%entries125133%_)
                   '1)))
            (let _%loop125140%_ ((_%probe125143%_ _%start125136%_)
                                 (_%i125145%_ '1)
                                 (_%deleted125147%_ '#f))
              (let ((_%k125150%_ (vector-ref _%table125124%_ _%probe125143%_)))
                (if (eq? _%k125150%_ (macro-unused-obj))
                    (if _%deleted125147%_
                        (begin
                          (vector-set!
                           _%table125124%_
                           _%deleted125147%_
                           _%key125120%_)
                          (vector-set!
                           _%table125124%_
                           (##fx+ _%deleted125147%_ '1)
                           (_%immediate-table-update!125121%_
                            _%default125122%_))
                          (&raw-table-count-set!
                           _%tab125119%_
                           (##fx+ (&raw-table-count _%tab125119%_) '1)))
                        (begin
                          (vector-set!
                           _%table125124%_
                           _%probe125143%_
                           _%key125120%_)
                          (vector-set!
                           _%table125124%_
                           (##fx+ _%probe125143%_ '1)
                           (_%immediate-table-update!125121%_
                            _%default125122%_))
                          (let ()
                            (&raw-table-free-set!
                             _%tab125119%_
                             (##fx- (&raw-table-free _%tab125119%_) '1))
                            (&raw-table-count-set!
                             _%tab125119%_
                             (##fx+ (&raw-table-count _%tab125119%_) '1)))))
                    (if (eq? _%k125150%_ (macro-deleted-obj))
                        (_%loop125140%_
                         (let ((_%next-probe125157%_
                                (fx+ _%start125136%_
                                     _%i125145%_
                                     (fx* _%i125145%_ _%i125145%_))))
                           (##fxmodulo _%next-probe125157%_ _%size125130%_))
                         (##fx+ _%i125145%_ '1)
                         (let ((_%$e125160%_ _%deleted125147%_))
                           (if _%$e125160%_ _%$e125160%_ _%probe125143%_)))
                        (if (eq? _%key125120%_ _%k125150%_)
                            (let ()
                              (vector-set!
                               _%table125124%_
                               _%probe125143%_
                               _%key125120%_)
                              (vector-set!
                               _%table125124%_
                               (##fx+ _%probe125143%_ '1)
                               (_%immediate-table-update!125121%_
                                (vector-ref
                                 _%table125124%_
                                 (##fx+ _%probe125143%_ '1)))))
                            (_%loop125140%_
                             (let ((_%next-probe125165%_
                                    (fx+ _%start125136%_
                                         _%i125145%_
                                         (fx* _%i125145%_ _%i125145%_))))
                               (##fxmodulo
                                _%next-probe125165%_
                                _%size125130%_))
                             (##fx+ _%i125145%_ '1)
                             _%deleted125147%_))))))))))
    (define immediate-table-update!
      (lambda (_%tab125114%_
               _%key125115%_
               _%immediate-table-update!125116%_
               _%default125117%_)
        (if (##fx< (&raw-table-free _%tab125114%_)
                   (##fxquotient
                    (vector-length (&raw-table-table _%tab125114%_))
                    '4))
            (__raw-table-rehash! _%tab125114%_)
            '#!void)
        (__immediate-table-update!
         _%tab125114%_
         _%key125115%_
         _%immediate-table-update!125116%_
         _%default125117%_)))
    (define immediate-table-update!/lock
      (lambda (_%tab125083%_
               _%key125084%_
               _%immediate-table-update!125085%_
               _%default125086%_)
        (let ((_%lock125089%_ (&raw-table-lock _%tab125083%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125094%_ ((_%spin125097%_ '0))
              (if (##fx= (##vector-cas! _%lock125089%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125089%_ '1 (current-thread))
                  (if (##fx< _%spin125097%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125094%_ (##fx+ _%spin125097%_ '1)))
                      (let ((_%owner125103%_ (##vector-ref _%lock125089%_ '1)))
                        (if (eq? _%owner125103%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125103%_)
                                (let () (##thread-yield!) (_%again125094%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125109%_
                 (_%immediate-table-update!125085%_
                  _%tab125083%_
                  _%key125084%_
                  _%immediate-table-update!125085%_
                  _%default125086%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125089%_ '1 '#f)
                (##vector-cas! _%lock125089%_ '0 '0 '1)))
            _%$r125109%_))))
    (define immediate-table-delete!
      (lambda (_%tab125040%_ _%key125041%_)
        (let ((_%table125043%_ (&raw-table-table _%tab125040%_))
              (_%seed125045%_ (&raw-table-seed _%tab125040%_)))
          (let* ((_%h125048%_
                  (fxxor (immediate-hash _%key125041%_) _%seed125045%_))
                 (_%size125051%_ (vector-length _%table125043%_))
                 (_%entries125054%_ (##fxquotient _%size125051%_ '2))
                 (_%start125057%_
                  (##fxarithmetic-shift-left
                   (##fxmodulo _%h125048%_ _%entries125054%_)
                   '1)))
            (let _%loop125061%_ ((_%probe125064%_ _%start125057%_)
                                 (_%i125066%_ '1))
              (let ((_%k125069%_ (vector-ref _%table125043%_ _%probe125064%_)))
                (if (eq? _%k125069%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k125069%_ (macro-deleted-obj))
                        (_%loop125061%_
                         (let ((_%next-probe125074%_
                                (fx+ _%start125057%_
                                     _%i125066%_
                                     (fx* _%i125066%_ _%i125066%_))))
                           (##fxmodulo _%next-probe125074%_ _%size125051%_))
                         (##fx+ _%i125066%_ '1))
                        (if (eq? _%key125041%_ _%k125069%_)
                            (let ()
                              (vector-set!
                               _%table125043%_
                               _%probe125064%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table125043%_
                               (##fx+ _%probe125064%_ '1)
                               (macro-absent-obj))
                              (&raw-table-count-set!
                               _%tab125040%_
                               (##fx- (&raw-table-count _%tab125040%_) '1)))
                            (_%loop125061%_
                             (let ((_%next-probe125080%_
                                    (fx+ _%start125057%_
                                         _%i125066%_
                                         (fx* _%i125066%_ _%i125066%_))))
                               (##fxmodulo
                                _%next-probe125080%_
                                _%size125051%_))
                             (##fx+ _%i125066%_ '1)))))))))))
    (define immediate-table-delete!/lock
      (lambda (_%tab125010%_ _%key125012%_)
        (let ((_%lock125015%_ (&raw-table-lock _%tab125010%_)))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again125020%_ ((_%spin125023%_ '0))
              (if (##fx= (##vector-cas! _%lock125015%_ '0 '1 '0) '0)
                  (##vector-set! _%lock125015%_ '1 (current-thread))
                  (if (##fx< _%spin125023%_ '10)
                      (let ()
                        (##thread-yield!)
                        (_%again125020%_ (##fx+ _%spin125023%_ '1)))
                      (let ((_%owner125029%_ (##vector-ref _%lock125015%_ '1)))
                        (if (eq? _%owner125029%_ (macro-current-thread))
                            (##thread-deadlock-action!)
                            (if (macro-thread-end-condvar _%owner125029%_)
                                (let () (##thread-yield!) (_%again125020%_ '0))
                                (##thread-deadlock-action!))))))))
          (let ((_%$r125035%_
                 (immediate-table-delete! _%tab125010%_ _%key125012%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (##vector-set! _%lock125015%_ '1 '#f)
                (##vector-cas! _%lock125015%_ '0 '0 '1)))
            _%$r125035%_))))
    (define unused-obj (values (macro-unused-obj)))
    (define __gc-table::t.id 'gerbil#__gc-table::t)
    (define __gc-table::t
      (##structure
       ##type-type
       __gc-table::t.id
       'gc-table
       '26
       '#f
       '#(gcht 5 #f immediate 5 #f lock 5 #f)))
    (define __gc-table-loads '#f64(.45 .6363961030678927 .9))
    (define &gc-table-gcht
      (lambda (_%tab125008%_)
        (##unchecked-structure-ref
         _%tab125008%_
         '1
         __gc-table::t
         'gc-table-gcht)))
    (define &gc-table-immediate
      (lambda (_%tab125006%_)
        (##unchecked-structure-ref
         _%tab125006%_
         '2
         __gc-table::t
         'gc-table-immediate)))
    (define &gc-table-lock
      (lambda (_%tab125004%_)
        (##unchecked-structure-ref
         _%tab125004%_
         '3
         __gc-table::t
         'gc-table-lock)))
    (define &gc-table-gcht-set!
      (lambda (_%tab125001%_ _%val125002%_)
        (##unchecked-structure-set!
         _%tab125001%_
         _%val125002%_
         '1
         __gc-table::t
         'gc-table-gcht-set!)))
    (define &gc-table-immediate-set!
      (lambda (_%tab124998%_ _%val124999%_)
        (##unchecked-structure-set!
         _%tab124998%_
         _%val124999%_
         '2
         __gc-table::t
         'gc-table-immediate-set!)))
    (define &gc-table-lock-set!
      (lambda (_%tab124995%_ _%val124996%_)
        (##unchecked-structure-set!
         _%tab124995%_
         _%val124996%_
         '3
         __gc-table::t
         'gc-table-lock-set!)))
    (define make-gc-table__%
      (lambda (_%size-hint124959%_
               _%klass124960%_
               _%flags124961%_
               _%lock124962%_)
        (let ((_%gcht124964%_
               (__gc-table-new
                (if (fixnum? _%size-hint124959%_) _%size-hint124959%_ '16)
                _%flags124961%_)))
          (##structure _%klass124960%_ _%gcht124964%_ '#f _%lock124962%_))))
    (define make-gc-table__0
      (lambda (_%size-hint124969%_)
        (let* ((_%klass124971%_ __gc-table::t)
               (_%flags124973%_ '0)
               (_%lock124975%_ '#f))
          (make-gc-table__%
           _%size-hint124969%_
           _%klass124971%_
           _%flags124973%_
           _%lock124975%_))))
    (define make-gc-table__1
      (lambda (_%size-hint124977%_ _%klass124978%_)
        (let* ((_%flags124980%_ '0) (_%lock124982%_ '#f))
          (make-gc-table__%
           _%size-hint124977%_
           _%klass124978%_
           _%flags124980%_
           _%lock124982%_))))
    (define make-gc-table__2
      (lambda (_%size-hint124984%_ _%klass124985%_ _%flags124986%_)
        (let ((_%lock124988%_ '#f))
          (make-gc-table__%
           _%size-hint124984%_
           _%klass124985%_
           _%flags124986%_
           _%lock124988%_))))
    (define make-gc-table
      (lambda _g127422_
        (let ((_g127423_ (##length _g127422_)))
          (cond ((##fx= _g127423_ 1) (apply make-gc-table__0 _g127422_))
                ((##fx= _g127423_ 2) (apply make-gc-table__1 _g127422_))
                ((##fx= _g127423_ 3) (apply make-gc-table__2 _g127422_))
                ((##fx= _g127423_ 4) (apply make-gc-table__% _g127422_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-gc-table
                  _g127422_))))))
    (define make-gc-table/lock__%
      (lambda (_%size-hint124936%_ _%klass124937%_ _%flags124938%_)
        (make-gc-table__%
         _%size-hint124936%_
         _%klass124937%_
         _%flags124938%_
         (vector '0 '#f))))
    (define make-gc-table/lock__0
      (lambda (_%size-hint124943%_)
        (let* ((_%klass124945%_ __gc-table::t) (_%flags124947%_ '0))
          (make-gc-table/lock__%
           _%size-hint124943%_
           _%klass124945%_
           _%flags124947%_))))
    (define make-gc-table/lock__1
      (lambda (_%size-hint124949%_ _%klass124950%_)
        (let ((_%flags124952%_ '0))
          (make-gc-table/lock__%
           _%size-hint124949%_
           _%klass124950%_
           _%flags124952%_))))
    (define make-gc-table/lock
      (lambda _g127424_
        (let ((_g127425_ (##length _g127424_)))
          (cond ((##fx= _g127425_ 1) (apply make-gc-table/lock__0 _g127424_))
                ((##fx= _g127425_ 2) (apply make-gc-table/lock__1 _g127424_))
                ((##fx= _g127425_ 3) (apply make-gc-table/lock__% _g127424_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-gc-table/lock
                  _g127424_))))))
    (define __gc-table-immediate
      (lambda (_%tab124927%_)
        (let ((_%$e124929%_ (&gc-table-immediate _%tab124927%_)))
          (if _%$e124929%_
              _%$e124929%_
              (let ((_%immediate124933%_ (make-immediate-table__% '#f '0)))
                (&gc-table-immediate-set! _%tab124927%_ _%immediate124933%_)
                _%immediate124933%_)))))
    (define __gc-table-new
      (lambda (_%size124917%_ _%flags124918%_)
        (let* ((_%flags124920%_
                (##fxand _%flags124918%_
                         (fxnot (macro-gc-hash-table-flag-need-rehash))))
               (_%flags124922%_
                (fxior _%flags124920%_
                       (macro-gc-hash-table-flag-mem-alloc-keys)))
               (_%gcht124924%_
                (##gc-hash-table-allocate
                 _%size124917%_
                 _%flags124922%_
                 __gc-table-loads)))
          _%gcht124924%_)))
    (define __gc-table-e
      (lambda (_%tab124912%_)
        (declare (not interrupts-enabled))
        (let ((_%gcht124915%_ (&gc-table-gcht _%tab124912%_)))
          (if (##fx= '0
                     (fxand (macro-gc-hash-table-flags _%gcht124915%_)
                            (macro-gc-hash-table-flag-need-rehash)))
              _%gcht124915%_
              (begin
                (__gc-table-rehash! _%tab124912%_)
                (&gc-table-gcht _%tab124912%_))))))
    (define __gc-table-rehash!
      (lambda (_%tab124903%_)
        (let* ((_%old-table124905%_ (&gc-table-gcht _%tab124903%_))
               (_%new-table124907%_
                (##gc-hash-table-resize! _%old-table124905%_ __gc-table-loads))
               (_%gcht124909%_
                (##gc-hash-table-rehash!
                 _%old-table124905%_
                 _%new-table124907%_)))
          (&gc-table-gcht-set! _%tab124903%_ _%gcht124909%_))))
    (define gc-table-ref
      (lambda (_%tab124887%_ _%key124888%_ _%default124889%_)
        (declare (not interrupts-enabled))
        (if (##mem-allocated? _%key124888%_)
            (let* ((_%gcht124893%_ (__gc-table-e _%tab124887%_))
                   (_%value124895%_
                    (##gc-hash-table-ref _%gcht124893%_ _%key124888%_)))
              (if (eq? _%value124895%_ (macro-unused-obj))
                  _%default124889%_
                  _%value124895%_))
            (let ((_%$e124897%_ (&gc-table-immediate _%tab124887%_)))
              (if _%$e124897%_
                  (immediate-table-ref
                   _%$e124897%_
                   _%key124888%_
                   _%default124889%_)
                  _%default124889%_)))))
    (define gc-table-ref/lock
      (lambda (_%tab124861%_ _%key124862%_ _%default124863%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124867%_ ((_%spin124870%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124861%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124861%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124870%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124867%_ (##fx+ _%spin124870%_ '1)))
                    (let ((_%owner124876%_
                           (##vector-ref (&gc-table-lock _%tab124861%_) '1)))
                      (if (eq? _%owner124876%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124876%_)
                              (let () (##thread-yield!) (_%again124867%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124882%_
               (gc-table-ref _%tab124861%_ _%key124862%_ _%default124863%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124861%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124861%_) '0 '0 '1)))
          _%$r124882%_)))
    (define gc-table-set!
      (lambda (_%tab124854%_ _%key124855%_ _%value124856%_)
        (declare (not interrupts-enabled))
        (if (##mem-allocated? _%key124855%_)
            (let ((_%gcht124859%_ (__gc-table-e _%tab124854%_)))
              (if (##gc-hash-table-set!
                   _%gcht124859%_
                   _%key124855%_
                   _%value124856%_)
                  (begin
                    (__gc-table-rehash! _%tab124854%_)
                    (gc-table-set!
                     _%tab124854%_
                     _%key124855%_
                     _%value124856%_))
                  '#!void))
            (immediate-table-set!
             (__gc-table-immediate _%tab124854%_)
             _%key124855%_
             _%value124856%_))))
    (define gc-table-set/lock!
      (lambda (_%tab124828%_ _%key124829%_ _%value124830%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124834%_ ((_%spin124837%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124828%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124828%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124837%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124834%_ (##fx+ _%spin124837%_ '1)))
                    (let ((_%owner124843%_
                           (##vector-ref (&gc-table-lock _%tab124828%_) '1)))
                      (if (eq? _%owner124843%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124843%_)
                              (let () (##thread-yield!) (_%again124834%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124849%_
               (gc-table-set! _%tab124828%_ _%key124829%_ _%value124830%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124828%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124828%_) '0 '0 '1)))
          _%$r124849%_)))
    (define gc-table-update!
      (lambda (_%tab124821%_ _%key124822%_ _%update124823%_ _%default124824%_)
        (if (##mem-allocated? _%key124822%_)
            (let ((_%value124826%_
                   (gc-table-ref
                    _%tab124821%_
                    _%key124822%_
                    _%default124824%_)))
              (gc-table-set!
               _%tab124821%_
               _%key124822%_
               (_%update124823%_ _%value124826%_)))
            (immediate-table-update!
             (__gc-table-immediate _%tab124821%_)
             _%key124822%_
             _%update124823%_
             _%default124824%_))))
    (define gc-table-update!/lock
      (lambda (_%tab124794%_ _%key124795%_ _%update124796%_ _%default124797%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124801%_ ((_%spin124804%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124794%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124794%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124804%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124801%_ (##fx+ _%spin124804%_ '1)))
                    (let ((_%owner124810%_
                           (##vector-ref (&gc-table-lock _%tab124794%_) '1)))
                      (if (eq? _%owner124810%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124810%_)
                              (let () (##thread-yield!) (_%again124801%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124816%_
               (gc-table-update!
                _%tab124794%_
                _%key124795%_
                _%update124796%_
                _%default124797%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124794%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124794%_) '0 '0 '1)))
          _%$r124816%_)))
    (define gc-table-delete!
      (lambda (_%tab124782%_ _%key124783%_)
        (declare (not interrupts-enabled))
        (if (##mem-allocated? _%key124783%_)
            (let ((_%gcht124787%_ (__gc-table-e _%tab124782%_)))
              (if (##gc-hash-table-set!
                   _%gcht124787%_
                   _%key124783%_
                   (macro-absent-obj))
                  (begin
                    (__gc-table-rehash! _%tab124782%_)
                    (gc-table-delete! _%tab124782%_ _%key124783%_))
                  '#!void))
            (let ((_%$e124789%_ (&gc-table-immediate _%tab124782%_)))
              (if _%$e124789%_
                  (immediate-table-delete! _%$e124789%_ _%key124783%_)
                  '#!void)))))
    (define gc-table-delete!/lock
      (lambda (_%tab124757%_ _%key124758%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124762%_ ((_%spin124765%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124757%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124757%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124765%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124762%_ (##fx+ _%spin124765%_ '1)))
                    (let ((_%owner124771%_
                           (##vector-ref (&gc-table-lock _%tab124757%_) '1)))
                      (if (eq? _%owner124771%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124771%_)
                              (let () (##thread-yield!) (_%again124762%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124777%_ (gc-table-delete! _%tab124757%_ _%key124758%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124757%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124757%_) '0 '0 '1)))
          _%$r124777%_)))
    (define gc-table-for-each
      (lambda (_%tab124746%_ _%proc124747%_)
        (declare (not interrupts-enabled))
        (begin
          (let ((_%gcht124750%_ (__gc-table-e _%tab124746%_)))
            (##gc-hash-table-for-each _%proc124747%_ _%gcht124750%_))
          (let ((_%$e124752%_ (&gc-table-immediate _%tab124746%_)))
            (if _%$e124752%_
                (raw-table-for-each _%$e124752%_ _%proc124747%_)
                '#!void)))))
    (define gc-table-for-each/lock
      (lambda (_%tab124721%_ _%proc124722%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124726%_ ((_%spin124729%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124721%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124721%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124729%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124726%_ (##fx+ _%spin124729%_ '1)))
                    (let ((_%owner124735%_
                           (##vector-ref (&gc-table-lock _%tab124721%_) '1)))
                      (if (eq? _%owner124735%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124735%_)
                              (let () (##thread-yield!) (_%again124726%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124741%_ (gc-table-for-each _%tab124721%_ _%proc124722%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124721%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124721%_) '0 '0 '1)))
          _%$r124741%_)))
    (define table-new__%
      (lambda (_%tab124703%_ _%size-hint124704%_)
        (if (table? _%tab124703%_)
            '#!void
            (error '"table-new: expected table" _%tab124703%_))
        (letrec* ((_%loads124706%_ (macro-table-loads _%tab124703%_)))
          (make-table
           'size:
           (let ((_%$e124708%_ _%size-hint124704%_))
             (if _%$e124708%_ _%$e124708%_ '16))
           'init:
           (macro-table-init _%tab124703%_)
           'weak-keys:
           (##fx< '0
                  (fxand (macro-table-flags _%tab124703%_)
                         (macro-gc-hash-table-flag-weak-keys)))
           'weak-values:
           (##fx< '0
                  (fxand (macro-table-flags _%tab124703%_)
                         (macro-gc-hash-table-flag-weak-vals)))
           'test:
           (macro-table-test _%tab124703%_)
           'hash:
           (macro-table-hash _%tab124703%_)
           'min-load:
           (##f64vector-ref _%loads124706%_ '0)
           'max-load:
           (##f64vector-ref _%loads124706%_ '2)))))
    (define table-new__0
      (lambda (_%tab124714%_)
        (let ((_%size-hint124716%_ '#f))
          (table-new__% _%tab124714%_ _%size-hint124716%_))))
    (define table-new
      (lambda _g127426_
        (let ((_g127427_ (##length _g127426_)))
          (cond ((##fx= _g127427_ 1) (apply table-new__0 _g127426_))
                ((##fx= _g127427_ 2) (apply table-new__% _g127426_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  table-new
                  _g127426_))))))
    (define gc-table-new__%
      (lambda (_%tab124689%_ _%size-hint124690%_)
        (make-gc-table__%
         (if (eq? _%size-hint124690%_ '#t)
             (macro-gc-hash-table-count (__gc-table-e _%tab124689%_))
             _%size-hint124690%_)
         (##structure-type _%tab124689%_)
         (macro-gc-hash-table-flags (&gc-table-gcht _%tab124689%_))
         (if (&gc-table-lock _%tab124689%_) '#t '#f))))
    (define gc-table-new__0
      (lambda (_%tab124695%_)
        (let ((_%size-hint124697%_ '#f))
          (gc-table-new__% _%tab124695%_ _%size-hint124697%_))))
    (define gc-table-new
      (lambda _g127428_
        (let ((_g127429_ (##length _g127428_)))
          (cond ((##fx= _g127429_ 1) (apply gc-table-new__0 _g127428_))
                ((##fx= _g127429_ 2) (apply gc-table-new__% _g127428_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gc-table-new
                  _g127428_))))))
    (define gc-table-copy
      (lambda (_%tab124681%_)
        (let ((_%result124683%_ (gc-table-new__% _%tab124681%_ '#t)))
          (gc-table-for-each
           _%tab124681%_
           (lambda (_%k124685%_ _%v124686%_)
             (gc-table-set! _%result124683%_ _%k124685%_ _%v124686%_)))
          _%result124683%_)))
    (define gc-table-copy/lock
      (lambda (_%tab124657%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124661%_ ((_%spin124664%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124657%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124657%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124664%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124661%_ (##fx+ _%spin124664%_ '1)))
                    (let ((_%owner124670%_
                           (##vector-ref (&gc-table-lock _%tab124657%_) '1)))
                      (if (eq? _%owner124670%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124670%_)
                              (let () (##thread-yield!) (_%again124661%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124676%_ (gc-table-copy _%tab124657%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124657%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124657%_) '0 '0 '1)))
          _%$r124676%_)))
    (define gc-table-clear!
      (lambda (_%tab124650%_)
        (let* ((_%gcht124652%_ (__gc-table-e _%tab124650%_))
               (_%new-table124654%_
                (__gc-table-new
                 '16
                 (macro-gc-hash-table-flags _%gcht124652%_))))
          (&gc-table-gcht-set! _%tab124650%_ _%new-table124654%_)
          (&gc-table-immediate-set! _%tab124650%_ '#f))))
    (define gc-table-clear!/lock
      (lambda (_%tab124626%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124630%_ ((_%spin124633%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124626%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124626%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124633%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124630%_ (##fx+ _%spin124633%_ '1)))
                    (let ((_%owner124639%_
                           (##vector-ref (&gc-table-lock _%tab124626%_) '1)))
                      (if (eq? _%owner124639%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124639%_)
                              (let () (##thread-yield!) (_%again124630%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124645%_ (gc-table-clear! _%tab124626%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124626%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124626%_) '0 '0 '1)))
          _%$r124645%_)))
    (define gc-table-length
      (lambda (_%tab124618%_)
        (let ((_%gcht124620%_ (__gc-table-e _%tab124618%_)))
          (fx+ (macro-gc-hash-table-count _%gcht124620%_)
               (let ((_%$e124622%_ (&gc-table-immediate _%tab124618%_)))
                 (if _%$e124622%_ (&raw-table-count _%$e124622%_) '0))))))
    (define gc-table-length/lock
      (lambda (_%tab124594%_)
        (let ()
          (declare (not interrupts-enabled))
          (let _%again124598%_ ((_%spin124601%_ '0))
            (if (##fx= (##vector-cas! (&gc-table-lock _%tab124594%_) '0 '1 '0)
                       '0)
                (##vector-set!
                 (&gc-table-lock _%tab124594%_)
                 '1
                 (current-thread))
                (if (##fx< _%spin124601%_ '10)
                    (let ()
                      (##thread-yield!)
                      (_%again124598%_ (##fx+ _%spin124601%_ '1)))
                    (let ((_%owner124607%_
                           (##vector-ref (&gc-table-lock _%tab124594%_) '1)))
                      (if (eq? _%owner124607%_ (macro-current-thread))
                          (##thread-deadlock-action!)
                          (if (macro-thread-end-condvar _%owner124607%_)
                              (let () (##thread-yield!) (_%again124598%_ '0))
                              (##thread-deadlock-action!))))))))
        (let ((_%$r124613%_ (gc-table-length _%tab124594%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (##vector-set! (&gc-table-lock _%tab124594%_) '1 '#f)
              (##vector-cas! (&gc-table-lock _%tab124594%_) '0 '0 '1)))
          _%$r124613%_)))
    (define __object-eq-hash-lock (vector '0 '#f))
    (define __object-eq-hash-next '0)
    (define __object-eq-hash
      (make-gc-table__2
       '1024
       __gc-table::t
       (macro-gc-hash-table-flag-weak-keys)))
    (define __object->eq-hash
      (lambda (_%obj124560%_)
        (declare (not interrupts-enabled))
        (let ((_%val124563%_
               (gc-table-ref __object-eq-hash _%obj124560%_ '#f)))
          (if _%val124563%_
              _%val124563%_
              (begin
                (let ()
                  (declare (not interrupts-enabled))
                  (let _%again124567%_ ((_%spin124570%_ '0))
                    (if (##fx= (##vector-cas! __object-eq-hash-lock '0 '1 '0)
                               '0)
                        (##vector-set!
                         __object-eq-hash-lock
                         '1
                         (current-thread))
                        (if (##fx< _%spin124570%_ '10)
                            (let ()
                              (##thread-yield!)
                              (_%again124567%_ (##fx+ _%spin124570%_ '1)))
                            (let ((_%owner124576%_
                                   (##vector-ref __object-eq-hash-lock '1)))
                              (if (eq? _%owner124576%_ (macro-current-thread))
                                  (##thread-deadlock-action!)
                                  (if (macro-thread-end-condvar
                                       _%owner124576%_)
                                      (let ()
                                        (##thread-yield!)
                                        (_%again124567%_ '0))
                                      (##thread-deadlock-action!))))))))
                (let ((_%$r124589%_
                       (let ((_%val124582%_
                              (gc-table-ref
                               __object-eq-hash
                               _%obj124560%_
                               '#f)))
                         (if _%val124582%_
                             _%val124582%_
                             (let ((_%h124584%_
                                    (fxand __object-eq-hash
                                           (macro-max-fixnum32))))
                               (set! __object-eq-hash-next
                                     (let ((_%$e124586%_
                                            (##fx+? __object-eq-hash-next '1)))
                                       (if _%$e124586%_ _%$e124586%_ '0)))
                               (gc-table-set!
                                __object-eq-hash
                                _%obj124560%_
                                _%h124584%_)
                               _%h124584%_)))))
                  (let ()
                    (declare (not interrupts-enabled))
                    (begin
                      (##vector-set! __object-eq-hash-lock '1 '#f)
                      (##vector-cas! __object-eq-hash-lock '0 '0 '1)))
                  _%$r124589%_))))))))
