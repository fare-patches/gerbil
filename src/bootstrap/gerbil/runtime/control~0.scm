(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/control::timestamp 1795039813)
  (begin
    (define __make-promise
      (lambda (_%thunk128266%_)
        (let ((_%thunk128269%_ _%thunk128266%_))
          (declare (not safe))
          (##make-delay-promise _%thunk128269%_))))
    (define make-promise
      (lambda (_%thunk128252%_)
        (if (procedure? _%thunk128252%_)
            (let ((_%thunk128256%_ _%thunk128252%_))
              (__make-promise _%thunk128256%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@11.21-11.26"
               'contract:
               'procedure?
               'value:
               _%thunk128252%_)
              '#!void))))
    (define __make-atomic-promise
      (lambda (_%thunk128196%_)
        (let ((_%thunk128199%_ _%thunk128196%_))
          (let ((_%mx128226%_ (make-mutex 'promise))
                (_%inner128227%_
                 (let* ((_%thunk128208%_ _%thunk128199%_)
                        (_%thunk128213%_ _%thunk128208%_))
                   (__make-promise _%thunk128213%_))))
            (let* ((_%thunk128236%_
                    (lambda ()
                      (let ((_%once128230%_ (vector '0)))
                        (let ((__tmp128383
                               (lambda ()
                                 (declare (not interrupts-enabled))
                                 (begin
                                   (if (let ((__tmp128384
                                              (let ()
                                                (declare (not safe))
                                                (##vector-cas!
                                                 _%once128230%_
                                                 '0
                                                 '1
                                                 '0))))
                                         (declare (not safe))
                                         (##fx= __tmp128384 '0))
                                       '#!void
                                       (error '"Cannot reenter atomic block"))
                                   (mutex-lock! _%mx128226%_))))
                              (__tmp128382
                               (lambda ()
                                 (let ()
                                   (declare (not safe))
                                   (##force-out-of-line _%inner128227%_))))
                              (__tmp128381
                               (lambda () (mutex-unlock! _%mx128226%_))))
                          (declare (not safe))
                          (##dynamic-wind
                           __tmp128383
                           __tmp128382
                           __tmp128381)))))
                   (_%thunk128241%_ _%thunk128236%_))
              (__make-promise _%thunk128241%_))))))
    (define make-atomic-promise
      (lambda (_%thunk128182%_)
        (if (procedure? _%thunk128182%_)
            (let ((_%thunk128186%_ _%thunk128182%_))
              (__make-atomic-promise _%thunk128186%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@15.28-15.33"
               'contract:
               'procedure?
               'value:
               _%thunk128182%_)
              '#!void))))
    (define call-with-parameters__0
      (lambda (_%thunk128134%_)
        (if (procedure? _%thunk128134%_)
            (let ((_%thunk128138%_ _%thunk128134%_))
              (declare (not safe))
              (_%thunk128138%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@32.6-32.11"
               'contract:
               'procedure?
               'value:
               _%thunk128134%_)
              '#!void))))
    (define call-with-parameters__1
      (lambda (_%thunk128148%_ _%param128149%_ _%val128150%_)
        (if (procedure? _%thunk128148%_)
            (let ((_%thunk128154%_ _%thunk128148%_))
              (declare (not safe))
              (##parameterize1 _%param128149%_ _%val128150%_ _%thunk128154%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@33.6-33.11"
               'contract:
               'procedure?
               'value:
               _%thunk128148%_)
              '#!void))))
    (define call-with-parameters__2
      (lambda (_%thunk128164%_ _%param128165%_ _%val128166%_ . _%rest128167%_)
        (if (procedure? _%thunk128164%_)
            (let ((_%thunk128171%_ _%thunk128164%_))
              (call-with-parameters__1
               (lambda ()
                 (apply call-with-parameters _%thunk128171%_ _%rest128167%_))
               _%param128165%_
               _%val128166%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@35.6-35.11"
               'contract:
               'procedure?
               'value:
               _%thunk128164%_)
              '#!void))))
    (define call-with-parameters
      (lambda _g128385_
        (let ((_g128386_ (let () (declare (not safe)) (##length _g128385_))))
          (cond ((let () (declare (not safe)) (##fx= _g128386_ 1))
                 (apply call-with-parameters__0 _g128385_))
                ((let () (declare (not safe)) (##fx= _g128386_ 3))
                 (apply call-with-parameters__1 _g128385_))
                ((let () (declare (not safe)) (##fx>= _g128386_ 3))
                 (apply call-with-parameters__2 _g128385_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  call-with-parameters
                  _g128385_))))))
    (define __with-unwind-protect
      (lambda (_%K128109%_ _%fini128110%_)
        (let* ((_%K128113%_ _%K128109%_)
               (_%fini128121%_ _%fini128110%_)
               (_%once128130%_ (vector '0))
               (__tmp128387
                (lambda ()
                  (declare (not interrupts-enabled))
                  (if (let ((__tmp128388
                             (let ()
                               (declare (not safe))
                               (##vector-cas! _%once128130%_ '0 '1 '0))))
                        (declare (not safe))
                        (##fx= __tmp128388 '0))
                      '#!void
                      (error '"Cannot re-enter unwind protected block")))))
          (declare (not safe))
          (##dynamic-wind __tmp128387 _%K128113%_ _%fini128121%_))))
    (define with-unwind-protect
      (lambda (_%K128084%_ _%fini128085%_)
        (if (procedure? _%K128084%_)
            (let ((_%K128089%_ _%K128084%_))
              (if (procedure? _%fini128085%_)
                  (let ((_%fini128099%_ _%fini128085%_))
                    (__with-unwind-protect _%K128089%_ _%fini128099%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/control.ss\"@40.45-40.49"
                     'contract:
                     'procedure?
                     'value:
                     _%fini128085%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@40.28-40.29"
               'contract:
               'procedure?
               'value:
               _%K128084%_)
              '#!void))))
    (define __with-unwind-protect!
      (lambda (_%K128053%_ _%fini128054%_)
        (let* ((_%K128057%_ _%K128053%_)
               (_%fini128065%_ _%fini128054%_)
               (_%unwinding128074%_ '#f)
               (_%E128076%_ (current-exception-handler)))
          (with-exception-handler
           (lambda (_%e128078%_)
             (let ((__tmp128389
                    (lambda ()
                      (if _%unwinding128074%_
                          '#!void
                          (begin
                            (set! _%unwinding128074%_ '#t)
                            (let () (declare (not safe)) (_%fini128065%_))))
                      (let ()
                        (declare (not safe))
                        (_%E128076%_ _%e128078%_)))))
               (declare (not safe))
               (##with-exception-handler _%E128076%_ __tmp128389)))
           (lambda ()
             (let ((_%result128082%_
                    (let () (declare (not safe)) (_%K128057%_))))
               (if _%unwinding128074%_
                   '#!void
                   (begin
                     (set! _%unwinding128074%_ '#t)
                     (let () (declare (not safe)) (_%fini128065%_))))
               _%result128082%_))))))
    (define with-unwind-protect!
      (lambda (_%K128028%_ _%fini128029%_)
        (if (procedure? _%K128028%_)
            (let ((_%K128033%_ _%K128028%_))
              (if (procedure? _%fini128029%_)
                  (let ((_%fini128043%_ _%fini128029%_))
                    (__with-unwind-protect! _%K128033%_ _%fini128043%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/control.ss\"@53.46-53.50"
                     'contract:
                     'procedure?
                     'value:
                     _%fini128029%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/control.ss\"@53.29-53.30"
               'contract:
               'procedure?
               'value:
               _%K128028%_)
              '#!void))))
    (define keyword-dispatch
      (lambda (_%kwt127921%_ _%K127922%_ . _%all-args127923%_)
        (if _%kwt127921%_
            (if (vector? _%kwt127921%_)
                '#!void
                (error '"keyword-dispatch: expected vector" _%kwt127921%_))
            '#!void)
        (if (procedure? _%K127922%_)
            '#!void
            (error '"keyword-dispatch: expected procedure" _%K127922%_))
        (let ((_%keys127925%_
               (let () (declare (not safe)) (make-symbolic-table__% '#f '0))))
          (let _%lp127927%_ ((_%rest127929%_ _%all-args127923%_)
                             (_%args127930%_ '#f)
                             (_%tail127931%_ '#f))
            (let* ((_%$%rest127932127940%_ _%rest127929%_)
                   (_%$%else127934127948%_
                    (lambda ()
                      (if _%args127930%_
                          (begin
                            (let ()
                              (declare (not safe))
                              (##set-cdr! _%tail127931%_ '()))
                            (let ((__tmp128390
                                   (cons _%keys127925%_ _%args127930%_)))
                              (declare (not safe))
                              (##apply _%K127922%_ __tmp128390)))
                          (_%K127922%_ _%keys127925%_))))
                   (_%$%K127936128016%_
                    (lambda (_%hd-rest127951%_ _%hd127952%_)
                      (if (keyword? _%hd127952%_)
                          (let* ((_%$%hd-rest127954127961%_ _%hd-rest127951%_)
                                 (_%$%E127956127965%_
                                  (lambda ()
                                    (error '"No clause matching"
                                           _%$%hd-rest127954127961%_
                                           '([val . rest]))
                                    '#!void))
                                 (_%$%K127957127973%_
                                  (lambda (_%rest127968%_ _%val127969%_)
                                    (if _%kwt127921%_
                                        (let ((_%pos127971%_
                                               (let ((__tmp128392
                                                      (let ()
                                                        (declare (not safe))
                                                        (##keyword-hash
                                                         _%hd127952%_)))
                                                     (__tmp128391
                                                      (let ()
                                                        (declare (not safe))
                                                        (##vector-length
                                                         _%kwt127921%_))))
                                                 (declare (not safe))
                                                 (##fxmodulo
                                                  __tmp128392
                                                  __tmp128391))))
                                          (if (eq? _%hd127952%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%kwt127921%_
                                                      _%pos127971%_)))
                                              '#!void
                                              (error '"Unexpected keyword argument"
                                                     _%K127922%_
                                                     _%hd127952%_)))
                                        '#!void)
                                    (if (eq? (let ()
                                               (declare (not safe))
                                               (symbolic-table-ref
                                                _%keys127925%_
                                                _%hd127952%_
                                                absent-value))
                                             absent-value)
                                        '#!void
                                        (error '"Duplicate keyword argument"
                                               _%K127922%_
                                               _%hd127952%_))
                                    (let ()
                                      (declare (not safe))
                                      (symbolic-table-set!
                                       _%keys127925%_
                                       _%hd127952%_
                                       _%val127969%_))
                                    (_%lp127927%_
                                     _%rest127968%_
                                     _%args127930%_
                                     _%tail127931%_))))
                            (if (pair? _%$%hd-rest127954127961%_)
                                (let ((_%$%hd127958127976%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%hd-rest127954127961%_)))
                                      (_%$%tl127959127978%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%hd-rest127954127961%_))))
                                  (let* ((_%val127981%_ _%$%hd127958127976%_)
                                         (_%rest127983%_ _%$%tl127959127978%_))
                                    (_%$%K127957127973%_
                                     _%rest127983%_
                                     _%val127981%_)))
                                (_%$%E127956127965%_)))
                          (if (eq? _%hd127952%_ '#!key)
                              (let* ((_%$%hd-rest127985127992%_
                                      _%hd-rest127951%_)
                                     (_%$%E127987127996%_
                                      (lambda ()
                                        (error '"No clause matching"
                                               _%$%hd-rest127985127992%_
                                               '([val . rest]))
                                        '#!void))
                                     (_%$%K127988128002%_
                                      (lambda (_%rest127999%_ _%val128000%_)
                                        (if _%args127930%_
                                            (begin
                                              (let ()
                                                (declare (not safe))
                                                (##set-cdr!
                                                 _%tail127931%_
                                                 _%hd-rest127951%_))
                                              (_%lp127927%_
                                               _%rest127999%_
                                               _%args127930%_
                                               _%hd-rest127951%_))
                                            (_%lp127927%_
                                             _%rest127999%_
                                             _%hd-rest127951%_
                                             _%hd-rest127951%_)))))
                                (if (pair? _%$%hd-rest127985127992%_)
                                    (let ((_%$%hd127989128005%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%hd-rest127985127992%_)))
                                          (_%$%tl127990128007%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%hd-rest127985127992%_))))
                                      (let* ((_%val128010%_
                                              _%$%hd127989128005%_)
                                             (_%rest128012%_
                                              _%$%tl127990128007%_))
                                        (_%$%K127988128002%_
                                         _%rest128012%_
                                         _%val128010%_)))
                                    (_%$%E127987127996%_)))
                              (if (eq? _%hd127952%_ '#!rest)
                                  (if _%args127930%_
                                      (begin
                                        (let ()
                                          (declare (not safe))
                                          (##set-cdr!
                                           _%tail127931%_
                                           _%hd-rest127951%_))
                                        (let ((__tmp128393
                                               (cons _%keys127925%_
                                                     _%args127930%_)))
                                          (declare (not safe))
                                          (##apply _%K127922%_ __tmp128393)))
                                      (let ((__tmp128394
                                             (cons _%keys127925%_
                                                   _%hd-rest127951%_)))
                                        (declare (not safe))
                                        (##apply _%K127922%_ __tmp128394)))
                                  (if _%args127930%_
                                      (begin
                                        (let ()
                                          (declare (not safe))
                                          (##set-cdr!
                                           _%tail127931%_
                                           _%rest127929%_))
                                        (_%lp127927%_
                                         _%hd-rest127951%_
                                         _%args127930%_
                                         _%rest127929%_))
                                      (_%lp127927%_
                                       _%hd-rest127951%_
                                       _%rest127929%_
                                       _%rest127929%_))))))))
              (if (pair? _%$%rest127932127940%_)
                  (let ((_%$%hd127937128019%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest127932127940%_)))
                        (_%$%tl127938128021%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest127932127940%_))))
                    (let* ((_%hd128024%_ _%$%hd127937128019%_)
                           (_%hd-rest128026%_ _%$%tl127938128021%_))
                      (_%$%K127936128016%_ _%hd-rest128026%_ _%hd128024%_)))
                  (_%$%else127934127948%_)))))))
    (define keyword-rest
      (lambda (_%kwt127913%_ . _%drop127914%_)
        (let ((_%rest127916%_ '()))
          (let ((__tmp128395
                 (lambda (_%k127918%_ _%v127919%_)
                   (if (let ()
                         (declare (not safe))
                         (##memq _%k127918%_ _%drop127914%_))
                       '#!void
                       (set! _%rest127916%_
                             (cons _%k127918%_
                                   (cons _%v127919%_ _%rest127916%_)))))))
            (declare (not safe))
            (raw-table-for-each _%kwt127913%_ __tmp128395))
          _%rest127916%_)))))
