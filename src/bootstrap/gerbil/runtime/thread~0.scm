(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/thread::timestamp 1795039815)
  (begin
    (define __system_thread-group (make-thread-group 'system))
    (define system-thread-group (lambda () __system_thread-group))
    (define __make-system-thread
      (lambda (_%thunk175990%_ _%name175991%_)
        (let* ((_%thunk175994%_ _%thunk175990%_)
               (_%name176002%_ _%name175991%_))
          (make-thread
           (lambda () (thread-main _%thunk175994%_))
           _%name176002%_
           (system-thread-group)))))
    (define make-system-thread
      (lambda (_%thunk175965%_ _%name175966%_)
        (if (procedure? _%thunk175965%_)
            (let ((_%thunk175970%_ _%thunk175965%_))
              (if (symbol? _%name175966%_)
                  (let ((_%name175980%_ _%name175966%_))
                    (__make-system-thread _%thunk175970%_ _%name175980%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@18.48-18.52"
                     'contract:
                     'symbol?
                     'value:
                     _%name175966%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@18.27-18.32"
               'contract:
               'procedure?
               'value:
               _%thunk175965%_)
              '#!void))))
    (define __system-thread!
      (lambda (_%thunk175912%_ _%name175913%_)
        (let* ((_%thunk175916%_ _%thunk175912%_)
               (_%name175924%_ _%name175913%_))
          (thread-start!
           (let* ((_%thunk175933%_ _%thunk175916%_)
                  (_%name175936%_ _%name175924%_)
                  (_%thunk175941%_ _%thunk175933%_)
                  (_%name175955%_ _%name175936%_))
             (__make-system-thread _%thunk175941%_ _%name175955%_))))))
    (define system-thread!
      (lambda (_%thunk175887%_ _%name175888%_)
        (if (procedure? _%thunk175887%_)
            (let ((_%thunk175892%_ _%thunk175887%_))
              (if (symbol? _%name175888%_)
                  (let ((_%name175902%_ _%name175888%_))
                    (__system-thread! _%thunk175892%_ _%name175902%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@21.44-21.48"
                     'contract:
                     'symbol?
                     'value:
                     _%name175888%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@21.23-21.28"
               'contract:
               'procedure?
               'value:
               _%thunk175887%_)
              '#!void))))
    (define __system-actor!
      (lambda (_%thunk175800%_ _%name175801%_)
        (let* ((_%thunk175804%_ _%thunk175800%_)
               (_%name175812%_ _%name175801%_)
               (_%f175821%_ _%thunk175804%_)
               (_%args175824%_ '())
               (_%name175827%_ _%name175812%_)
               (_%tgroup175830%_ (system-thread-group))
               (_%f175835%_ _%f175821%_)
               (_%args175851%_ _%args175824%_)
               (_%name175861%_ _%name175827%_))
          (if (or (not _%tgroup175830%_) '#t)
              (let ((_%tgroup175877%_ _%tgroup175830%_))
                (__spawn-actor
                 _%f175835%_
                 _%args175851%_
                 _%name175861%_
                 _%tgroup175877%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/thread
                 'contract:
                 '(? (or not thread-group?))
                 'value:
                 _%tgroup175830%_)
                '#!void)))))
    (define system-actor!
      (lambda (_%thunk175775%_ _%name175776%_)
        (if (procedure? _%thunk175775%_)
            (let ((_%thunk175780%_ _%thunk175775%_))
              (if (symbol? _%name175776%_)
                  (let ((_%name175790%_ _%name175776%_))
                    (__system-actor! _%thunk175780%_ _%name175790%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@24.43-24.47"
                     'contract:
                     'symbol?
                     'value:
                     _%name175776%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@24.22-24.27"
               'contract:
               'procedure?
               'value:
               _%thunk175775%_)
              '#!void))))
    (define __spawn
      (lambda (_%f175696%_ . _%args175697%_)
        (let* ((_%f175700%_ _%f175696%_)
               (_%f175709%_ _%f175700%_)
               (_%args175712%_ _%args175697%_)
               (_%name175715%_ '#!void)
               (_%tgroup175718%_ '#f)
               (_%f175723%_ _%f175709%_)
               (_%args175739%_ _%args175712%_)
               (_%name175749%_ _%name175715%_))
          (if (let ((_%$e175761%_ '#t)) (and _%$e175761%_ _%$e175761%_))
              (let ((_%tgroup175765%_ _%tgroup175718%_))
                (__spawn-actor
                 _%f175723%_
                 _%args175739%_
                 _%name175749%_
                 _%tgroup175765%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/thread
                 'contract:
                 '(? (or not thread-group?))
                 'value:
                 _%tgroup175718%_)
                '#!void)))))
    (define spawn
      (lambda (_%f175681%_ . _%args175682%_)
        (if (procedure? _%f175681%_)
            (let ((_%f175686%_ _%f175681%_))
              (declare (not safe))
              (##apply __spawn _%f175686%_ _%args175682%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@28.14-28.15"
               'contract:
               'procedure?
               'value:
               _%f175681%_)
              '#!void))))
    (define __spawn/name
      (lambda (_%name175601%_ _%f175602%_ . _%args175603%_)
        (let* ((_%f175606%_ _%f175602%_)
               (_%f175615%_ _%f175606%_)
               (_%args175618%_ _%args175603%_)
               (_%name175621%_ _%name175601%_)
               (_%tgroup175624%_ '#f)
               (_%f175629%_ _%f175615%_)
               (_%args175645%_ _%args175618%_)
               (_%name175655%_ _%name175621%_))
          (if (let ((_%$e175667%_ '#t)) (and _%$e175667%_ _%$e175667%_))
              (let ((_%tgroup175671%_ _%tgroup175624%_))
                (__spawn-actor
                 _%f175629%_
                 _%args175645%_
                 _%name175655%_
                 _%tgroup175671%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/thread
                 'contract:
                 '(? (or not thread-group?))
                 'value:
                 _%tgroup175624%_)
                '#!void)))))
    (define spawn/name
      (lambda (_%name175585%_ _%f175586%_ . _%args175587%_)
        (if (procedure? _%f175586%_)
            (let ((_%f175591%_ _%f175586%_))
              (declare (not safe))
              (##apply __spawn/name _%name175585%_ _%f175591%_ _%args175587%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@33.24-33.25"
               'contract:
               'procedure?
               'value:
               _%f175586%_)
              '#!void))))
    (define __spawn/group
      (lambda (_%name175502%_ _%f175503%_ . _%args175504%_)
        (let* ((_%f175507%_ _%f175503%_)
               (_%tgroup175516%_ (make-thread-group _%name175502%_))
               (_%f175518%_ _%f175507%_)
               (_%args175521%_ _%args175504%_)
               (_%name175524%_ _%name175502%_)
               (_%tgroup175527%_ _%tgroup175516%_)
               (_%f175532%_ _%f175518%_)
               (_%args175549%_ _%args175521%_)
               (_%name175559%_ _%name175524%_))
          (if (or (not _%tgroup175527%_) '#t)
              (let ((_%tgroup175575%_ _%tgroup175527%_))
                (__spawn-actor
                 _%f175532%_
                 _%args175549%_
                 _%name175559%_
                 _%tgroup175575%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/thread
                 'contract:
                 '(? (or not thread-group?))
                 'value:
                 _%tgroup175527%_)
                '#!void)))))
    (define spawn/group
      (lambda (_%name175486%_ _%f175487%_ . _%args175488%_)
        (if (procedure? _%f175487%_)
            (let ((_%f175492%_ _%f175487%_))
              (declare (not safe))
              (##apply __spawn/group
                       _%name175486%_
                       _%f175492%_
                       _%args175488%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@38.25-38.26"
               'contract:
               'procedure?
               'value:
               _%f175487%_)
              '#!void))))
    (define __spawn-actor
      (lambda (_%f175400%_ _%args175401%_ _%name175402%_ _%tgroup175403%_)
        (let* ((_%f175406%_ _%f175400%_)
               (_%args175414%_ _%args175401%_)
               (_%name175422%_ _%name175402%_)
               (_%tgroup175430%_ _%tgroup175403%_)
               (_%thunk175440%_
                (if (null? _%args175414%_)
                    _%f175406%_
                    (lambda ()
                      (let ()
                        (declare (not safe))
                        (##apply _%f175406%_ _%args175414%_)))))
               (_%thunk175477%_
                (lambda ()
                  (let* ((_%thunk175443%_ _%thunk175440%_)
                         (_%error-port175446%_ (current-error-port))
                         (_%thunk175451%_ _%thunk175443%_)
                         (_%error-port175467%_ _%error-port175446%_))
                    (__with-exception-stack-trace__%
                     _%thunk175451%_
                     _%error-port175467%_))))
               (_%tgroup175482%_
                (let ((_%$e175479%_ _%tgroup175430%_))
                  (if _%$e175479%_ _%$e175479%_ (current-thread-group)))))
          (thread-start!
           (thread-init!
            (construct-actor-thread '#f '#f)
            (lambda () (thread-main _%thunk175477%_))
            _%name175422%_
            _%tgroup175482%_)))))
    (define spawn-actor
      (lambda (_%f175347%_ _%args175348%_ _%name175349%_ _%tgroup175350%_)
        (if (procedure? _%f175347%_)
            (let ((_%f175354%_ _%f175347%_))
              (if (list? _%args175348%_)
                  (let* ((_%args175364%_ _%args175348%_)
                         (_%name175374%_ _%name175349%_))
                    (if (or (not _%tgroup175350%_)
                            (thread-group? _%tgroup175350%_))
                        (let ((_%tgroup175390%_ _%tgroup175350%_))
                          (__spawn-actor
                           _%f175354%_
                           _%args175364%_
                           _%name175374%_
                           _%tgroup175390%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/thread.ss\"@46.20-46.26"
                           'contract:
                           '(? (or not thread-group?))
                           'value:
                           _%tgroup175350%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@44.20-44.24"
                     'contract:
                     'list?
                     'value:
                     _%args175348%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@43.20-43.21"
               'contract:
               'procedure?
               'value:
               _%f175347%_)
              '#!void))))
    (define spawn-thread__%
      (lambda (_%thunk175324%_ _%name175325%_ _%tgroup175326%_)
        (thread-start!
         (make-thread
          (lambda () (thread-main _%thunk175324%_))
          _%name175325%_
          _%tgroup175326%_))))
    (define spawn-thread__0
      (lambda (_%thunk175332%_)
        (let* ((_%name175334%_ absent-obj) (_%tgroup175336%_ absent-obj))
          (spawn-thread__% _%thunk175332%_ _%name175334%_ _%tgroup175336%_))))
    (define spawn-thread__1
      (lambda (_%thunk175338%_ _%name175339%_)
        (let ((_%tgroup175341%_ absent-obj))
          (spawn-thread__% _%thunk175338%_ _%name175339%_ _%tgroup175341%_))))
    (define spawn-thread
      (lambda _g176325_
        (let ((_g176326_ (let () (declare (not safe)) (##length _g176325_))))
          (cond ((let () (declare (not safe)) (##fx= _g176326_ 1))
                 (apply spawn-thread__0 _g176325_))
                ((let () (declare (not safe)) (##fx= _g176326_ 2))
                 (apply spawn-thread__1 _g176325_))
                ((let () (declare (not safe)) (##fx= _g176326_ 3))
                 (apply spawn-thread__% _g176325_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  spawn-thread
                  _g176325_))))))
    (define thread-main
      (lambda (_%thunk175255%_)
        (let* ((_%handler175294%_
                (lambda (_%exn175257%_)
                  (let ((__tmp176327
                         (lambda (_%cont175259%_)
                           (if (procedure? __unhandled-actor-exception-hook)
                               (let* ((_%handler175261%_ void)
                                      (_%thunk175265%_
                                       (lambda ()
                                         (__unhandled-actor-exception-hook
                                          _%cont175259%_
                                          _%exn175257%_)))
                                      (_%handler175270%_ _%handler175261%_)
                                      (_%thunk175284%_ _%thunk175265%_))
                                 (declare (not safe))
                                 (__with-catch
                                  _%handler175270%_
                                  _%thunk175284%_))
                               '#!void)
                           (let ((__tmp176328
                                  (let ()
                                    (declare (not safe))
                                    (##continuation-last _%cont175259%_))))
                             (declare (not safe))
                             (##continuation-graft
                              __tmp176328
                              ##primordial-exception-handler
                              _%exn175257%_)))))
                    (declare (not safe))
                    (##continuation-capture __tmp176327))))
               (_%thunk175297%_ _%thunk175255%_)
               (_%handler175302%_ _%handler175294%_))
          (if (procedure? _%thunk175297%_)
              (let ((_%thunk175313%_ _%thunk175297%_))
                (declare (not safe))
                (__with-exception-handler _%handler175302%_ _%thunk175313%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/thread
                 'contract:
                 'procedure?
                 'value:
                 _%thunk175297%_)
                '#!void)))))
    (define thread-local-ref__%
      (lambda (_%key175214%_ _%default175215%_)
        (let* ((_%tab175217%_ (thread-local-table))
               (_%h175219%_ _%tab175217%_)
               (_%key175222%_ _%key175214%_)
               (_%default175225%_ _%default175215%_)
               (_%h175229%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h175219%_)))
               (_%h175231%_ _%h175229%_))
          (declare (not safe))
          (__hash-ref__% _%h175231%_ _%key175222%_ _%default175225%_))))
    (define thread-local-ref__0
      (lambda (_%key175248%_)
        (let ((_%default175250%_ absent-obj))
          (thread-local-ref__% _%key175248%_ _%default175250%_))))
    (define thread-local-ref
      (lambda _g176329_
        (let ((_g176330_ (let () (declare (not safe)) (##length _g176329_))))
          (cond ((let () (declare (not safe)) (##fx= _g176330_ 1))
                 (apply thread-local-ref__0 _g176329_))
                ((let () (declare (not safe)) (##fx= _g176330_ 2))
                 (apply thread-local-ref__% _g176329_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  thread-local-ref
                  _g176329_))))))
    (define thread-local-get
      (lambda (_%key175211%_) (thread-local-ref__% _%key175211%_ '#f)))
    (define thread-local-set!
      (lambda (_%key175180%_ _%value175181%_)
        (let* ((_%tab175183%_ (thread-local-table))
               (_%h175185%_ _%tab175183%_)
               (_%key175188%_ _%key175180%_)
               (_%value175191%_ _%value175181%_)
               (_%h175195%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h175185%_)))
               (_%h175197%_ _%h175195%_))
          (declare (not safe))
          (__hash-put! _%h175197%_ _%key175188%_ _%value175191%_))))
    (define thread-local-delete!
      (lambda (_%key175154%_)
        (let* ((_%tab175156%_ (thread-local-table))
               (_%h175158%_ _%tab175156%_)
               (_%key175161%_ _%key175154%_)
               (_%h175165%_
                (let ()
                  (declare (not safe))
                  (cast HashTable::interface _%h175158%_)))
               (_%h175167%_ _%h175165%_))
          (declare (not safe))
          (__hash-remove! _%h175167%_ _%key175161%_))))
    (define thread-local-table
      (lambda ()
        (let ((_%thr175085%_ (current-thread)))
          (if (actor-thread? _%thr175085%_)
              (let ((_%$e175088%_ (actor-thread-locals _%thr175085%_)))
                (if _%$e175088%_
                    _%$e175088%_
                    (let ((_%tab175092%_
                           (let () (declare (not safe)) (make-hash-table-eq))))
                      (actor-thread-locals-set! _%thr175085%_ _%tab175092%_)
                      _%tab175092%_)))
              (if (eq? _%thr175085%_ ##primordial-thread)
                  __primordial-thread-locals
                  (let ()
                    (mutex-lock! __thread-locals-mutex)
                    (let ((_%$e175119%_
                           (let* ((_%h175096%_ __thread-locals)
                                  (_%key175099%_ _%thr175085%_)
                                  (_%h175103%_ _%h175096%_)
                                  (_%h175105%_ _%h175103%_))
                             (declare (not safe))
                             (__hash-get _%h175105%_ _%key175099%_))))
                      (if _%$e175119%_
                          (let ()
                            (mutex-unlock! __thread-locals-mutex)
                            _%$e175119%_)
                          (let ((_%tab175125%_
                                 (let ()
                                   (declare (not safe))
                                   (make-hash-table-eq))))
                            (let* ((_%h175127%_ __thread-locals)
                                   (_%key175130%_ _%thr175085%_)
                                   (_%value175133%_ _%tab175125%_)
                                   (_%h175137%_ _%h175127%_)
                                   (_%h175139%_ _%h175137%_))
                              (declare (not safe))
                              (__hash-put!
                               _%h175139%_
                               _%key175130%_
                               _%value175133%_))
                            (mutex-unlock! __thread-locals-mutex)
                            _%tab175125%_)))))))))
    (define __primordial-thread-locals
      (let () (declare (not safe)) (make-hash-table-eq)))
    (define __thread-locals
      (let () (declare (not safe)) (make-hash-table-eq 'weak-keys: '#t)))
    (define __thread-locals-mutex (make-mutex 'thread-locals))
    (define __unhandled-actor-exception-hook '#f)
    (define unhandled-actor-exception-hook
      (lambda () __unhandled-actor-exception-hook))
    (define __unhandled-actor-exception-hook-set!
      (lambda (_%new-value175071%_)
        (let ((_%new-value175074%_ _%new-value175071%_))
          (set! __unhandled-actor-exception-hook _%new-value175074%_))))
    (define unhandled-actor-exception-hook-set!
      (lambda (_%new-value175050%_)
        (if (or (not _%new-value175050%_) (procedure? _%new-value175050%_))
            (let ((_%new-value175061%_ _%new-value175050%_))
              (__unhandled-actor-exception-hook-set! _%new-value175061%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/runtime/thread
               'contract:
               '(? (or not procedure?))
               'value:
               _%new-value175050%_)
              '#!void))))
    (define current-thread-group
      (lambda () (thread-thread-group (current-thread))))
    (define __with-lock
      (lambda (_%mx174957%_ _%proc174958%_)
        (let* ((_%mx174961%_ _%mx174957%_)
               (_%proc174969%_ _%proc174958%_)
               (_%handler174978%_ (current-exception-handler))
               (_%handler175017%_
                (lambda (_%e174980%_)
                  (let* ((_%handler174982%_ void)
                         (_%thunk174986%_
                          (lambda ()
                            (mutex-unlock! _%mx174961%_)
                            (let ()
                              (declare (not safe))
                              (_%handler174978%_ _%e174980%_))))
                         (_%handler174991%_ _%handler174982%_)
                         (_%thunk175007%_ _%thunk174986%_))
                    (declare (not safe))
                    (__with-catch _%handler174991%_ _%thunk175007%_))
                  (let ()
                    (declare (not safe))
                    (##thread-end-with-uncaught-exception! _%e174980%_))))
               (_%thunk175023%_
                (lambda ()
                  (mutex-lock! _%mx174961%_)
                  (let ((_%result175021%_
                         (let () (declare (not safe)) (_%proc174969%_))))
                    (mutex-unlock! _%mx174961%_)
                    _%result175021%_)))
               (_%handler175028%_ _%handler175017%_)
               (_%thunk175039%_ _%thunk175023%_))
          (declare (not safe))
          (__with-exception-handler _%handler175028%_ _%thunk175039%_))))
    (define with-lock
      (lambda (_%mx174932%_ _%proc174933%_)
        (if (mutex? _%mx174932%_)
            (let ((_%mx174937%_ _%mx174932%_))
              (if (procedure? _%proc174933%_)
                  (let ((_%proc174947%_ _%proc174933%_))
                    (__with-lock _%mx174937%_ _%proc174947%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@138.32-138.36"
                     'contract:
                     'procedure?
                     'value:
                     _%proc174933%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@138.18-138.20"
               'contract:
               'mutex?
               'value:
               _%mx174932%_)
              '#!void))))
    (define __with-dynamic-lock
      (lambda (_%mx174909%_ _%proc174910%_)
        (let* ((_%mx174913%_ _%mx174909%_) (_%proc174921%_ _%proc174910%_))
          (let ((__tmp176332 (lambda () (mutex-lock! _%mx174913%_)))
                (__tmp176331 (lambda () (mutex-unlock! _%mx174913%_))))
            (declare (not safe))
            (##dynamic-wind __tmp176332 _%proc174921%_ __tmp176331)))))
    (define with-dynamic-lock
      (lambda (_%mx174884%_ _%proc174885%_)
        (if (mutex? _%mx174884%_)
            (let ((_%mx174889%_ _%mx174884%_))
              (if (procedure? _%proc174885%_)
                  (let ((_%proc174899%_ _%proc174885%_))
                    (__with-dynamic-lock _%mx174889%_ _%proc174899%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@154.40-154.44"
                     'contract:
                     'procedure?
                     'value:
                     _%proc174885%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@154.26-154.28"
               'contract:
               'mutex?
               'value:
               _%mx174884%_)
              '#!void))))
    (define __with-exception-stack-trace__%
      (lambda (_%thunk174815%_ _%error-port174816%_)
        (let* ((_%thunk174819%_ _%thunk174815%_)
               (_%error-port174827%_ _%error-port174816%_)
               (_%handler174842%_
                (let ((_%E174836%_ (current-exception-handler)))
                  (lambda (_%exn174838%_)
                    (let ((__tmp176333
                           (lambda (_%cont174840%_)
                             (if (let ()
                                   (declare (not safe))
                                   (dump-stack-trace?))
                                 (dump-stack-trace!__%
                                  _%cont174840%_
                                  _%exn174838%_
                                  _%error-port174827%_)
                                 '#!void)
                             (let ()
                               (declare (not safe))
                               (_%E174836%_ _%exn174838%_)))))
                      (declare (not safe))
                      (##continuation-capture __tmp176333)))))
               (_%thunk174845%_ _%thunk174819%_)
               (_%handler174850%_ _%handler174842%_)
               (_%thunk174864%_ _%thunk174845%_))
          (declare (not safe))
          (__with-exception-handler _%handler174850%_ _%thunk174864%_))))
    (define __with-exception-stack-trace__0
      (lambda (_%thunk174877%_)
        (let ((_%error-port174879%_ (current-error-port)))
          (__with-exception-stack-trace__%
           _%thunk174877%_
           _%error-port174879%_))))
    (define __with-exception-stack-trace
      (lambda _g176334_
        (let ((_g176335_ (let () (declare (not safe)) (##length _g176334_))))
          (cond ((let () (declare (not safe)) (##fx= _g176335_ 1))
                 (apply __with-exception-stack-trace__0 _g176334_))
                ((let () (declare (not safe)) (##fx= _g176335_ 2))
                 (apply __with-exception-stack-trace__% _g176334_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __with-exception-stack-trace
                  _g176334_))))))
    (define with-exception-stack-trace__%
      (lambda (_%thunk174779%_ _%error-port174780%_)
        (if (procedure? _%thunk174779%_)
            (let ((_%thunk174784%_ _%thunk174779%_))
              (if (port? _%error-port174780%_)
                  (let ((_%error-port174794%_ _%error-port174780%_))
                    (__with-exception-stack-trace__%
                     _%thunk174784%_
                     _%error-port174794%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/thread.ss\"@162.35-162.45"
                     'contract:
                     'port?
                     'value:
                     _%error-port174780%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@161.35-161.40"
               'contract:
               'procedure?
               'value:
               _%thunk174779%_)
              '#!void))))
    (define with-exception-stack-trace__0
      (lambda (_%thunk174807%_)
        (let ((_%error-port174809%_ (current-error-port)))
          (with-exception-stack-trace__%
           _%thunk174807%_
           _%error-port174809%_))))
    (define with-exception-stack-trace
      (lambda _g176336_
        (let ((_g176337_ (let () (declare (not safe)) (##length _g176336_))))
          (cond ((let () (declare (not safe)) (##fx= _g176337_ 1))
                 (apply with-exception-stack-trace__0 _g176336_))
                ((let () (declare (not safe)) (##fx= _g176337_ 2))
                 (apply with-exception-stack-trace__% _g176336_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  with-exception-stack-trace
                  _g176336_))))))
    (define dump-stack-trace!__%
      (lambda (_%cont174760%_ _%exn174761%_ _%error-port174762%_)
        (let ((_%out174764%_ (open-output-string)))
          (let () (declare (not safe)) (fix-port-width! _%out174764%_))
          (display '"*** Unhandled exception in " _%out174764%_)
          (display (current-thread) _%out174764%_)
          (newline _%out174764%_)
          (let ()
            (declare (not safe))
            (display-exception__% _%exn174761%_ _%out174764%_))
          (if (let ()
                (declare (not safe))
                (class-instance? StackTrace::t _%exn174761%_))
              '#!void
              (begin
                (display '"Continuation backtrace: " _%out174764%_)
                (newline _%out174764%_)
                (display-continuation-backtrace _%cont174760%_ _%out174764%_)))
          (let ((__tmp176338 (get-output-string _%out174764%_)))
            (declare (not safe))
            (##write-string __tmp176338 _%error-port174762%_)))))
    (define dump-stack-trace!__0
      (lambda (_%cont174769%_ _%exn174770%_)
        (let ((_%error-port174772%_ (current-error-port)))
          (dump-stack-trace!__%
           _%cont174769%_
           _%exn174770%_
           _%error-port174772%_))))
    (define dump-stack-trace!
      (lambda _g176339_
        (let ((_g176340_ (let () (declare (not safe)) (##length _g176339_))))
          (cond ((let () (declare (not safe)) (##fx= _g176340_ 2))
                 (apply dump-stack-trace!__0 _g176339_))
                ((let () (declare (not safe)) (##fx= _g176340_ 3))
                 (apply dump-stack-trace!__% _g176339_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  dump-stack-trace!
                  _g176339_))))))
    (define __thread-dead?
      (lambda (_%thread174747%_)
        (let ((_%thread174750%_ _%thread174747%_))
          (not (macro-thread-end-condvar _%thread174750%_)))))
    (define thread-dead?
      (lambda (_%thread174733%_)
        (if (thread? _%thread174733%_)
            (let ((_%thread174737%_ _%thread174733%_))
              (__thread-dead? _%thread174737%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/thread.ss\"@188.21-188.27"
               'contract:
               'thread?
               'value:
               _%thread174733%_)
              '#!void))))
    (define-type-of-thread
     actor-thread
     constructor:
     construct-actor-thread
     id:
     actor::t
     state
     locals)))
