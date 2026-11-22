(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |[1]#_g128396_|
    (gx#core-deserialize-mark
     '(0
       (id . _%id127475%_)
       ($%arg127450 . _%$%arg127450127508%_)
       ($%arg127451 . _%$%arg127451127522%_)
       (arg . _%arg127538%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g128397_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g128396_|)))
  (define |[1]#_g128399_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g128400_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g128399_|)))
  (define |[1]#_g128401_|
    (gx#core-deserialize-mark
     '(0
       (id . _%id127595%_)
       ($%arg127572 . _%$%arg127572127642%_)
       ($%arg127571 . _%$%arg127571127628%_)
       (arg . _%arg127658%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g128402_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g128401_|)))
  (define |[1]#_g128404_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g128405_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g128404_|)))
  (define |[1]#_g128406_|
    (gx#core-deserialize-mark
     '(0
       (id . _%id127715%_)
       ($%arg127691 . _%$%arg127691127748%_)
       ($%arg127692 . _%$%arg127692127762%_)
       (arg . _%arg127778%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g128407_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g128406_|)))
  (define |[1]#_g128409_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g128410_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g128409_|)))
  (define |[1]#_g128411_|
    (gx#core-deserialize-mark
     '(0
       (id . _%id127835%_)
       ($%arg127811 . _%$%arg127811127868%_)
       ($%arg127812 . _%$%arg127812127882%_)
       (arg . _%arg127898%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g128412_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g128411_|)))
  (define |[1]#_g128414_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g128415_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g128414_|)))
  (begin
    (define |[:0:]#@make-promise|
      (lambda (_%$stx127432%_)
        (let* ((_%__stx128278128279%_ _%$stx127432%_)
               (_%$%g127437127458%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx128278128279%_))))
          (let ((_%__kont128281128282%_
                 (lambda (_%$%g127439127524%_)
                   (cons (gx#datum->syntax
                          |[1]#_g128397_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'thunk) '())
                                     (cons (let ((__tmp128398
                                                  (lambda (_%$%g127539127542%_
                                                           _%$%g127540127545%_)
                                                    (cons _%$%g127539127542%_
                                                          _%$%g127540127545%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp128398
                                              '()
                                              _%$%g127439127524%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g128400_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'thunk)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':procedure) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__make-promise)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'thunk)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont128285128286%_
                 (lambda (_%$%g127452127465%_)
                   (gx#datum->syntax '#f 'make-promise))))
            (let* ((_%$%g127436127477%_
                    (lambda ()
                      (let ((_%$%g127452127465%_ _%__stx128278128279%_))
                        (if (gx#identifier? _%$%g127452127465%_)
                            (_%__kont128285128286%_ _%$%g127452127465%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g127437127458%_))))))
                   (_%__match128301128302%_
                    (lambda (_%$%e127440127484%_
                             _%$%hd127441127488%_
                             _%$%tl127442127491%_
                             _%__splice128283128284%_
                             _%$%target127443127494%_
                             _%$%tl127445127497%_)
                      (letrec ((_%$%loop127446127500%_
                                (lambda (_%$%hd127444127504%_
                                         _%$%arg127450127507%_)
                                  (if (gx#stx-pair? _%$%hd127444127504%_)
                                      (let ((_%$%e127447127510%_
                                             (gx#syntax-e
                                              _%$%hd127444127504%_)))
                                        (let ((_%$%lp-tl127449127517%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e127447127510%_)))
                                              (_%$%lp-hd127448127514%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e127447127510%_))))
                                          (_%$%loop127446127500%_
                                           _%$%lp-tl127449127517%_
                                           (cons _%$%lp-hd127448127514%_
                                                 _%$%arg127450127507%_))))
                                      (let ((_%$%arg127451127520%_
                                             (reverse _%$%arg127450127507%_)))
                                        (_%__kont128281128282%_
                                         _%$%arg127451127520%_))))))
                        (_%$%loop127446127500%_
                         _%$%target127443127494%_
                         '())))))
              (if (gx#stx-pair? _%__stx128278128279%_)
                  (let ((_%$%e127440127484%_
                         (gx#syntax-e _%__stx128278128279%_)))
                    (let ((_%$%tl127442127491%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e127440127484%_)))
                          (_%$%hd127441127488%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e127440127484%_))))
                      (if (gx#stx-pair/null? _%$%tl127442127491%_)
                          (let ((_%__splice128283128284%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl127442127491%_
                                  '0)))
                            (let ((_%$%tl127445127497%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128283128284%_
                                      '1)))
                                  (_%$%target127443127494%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128283128284%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl127445127497%_)
                                  (_%__match128301128302%_
                                   _%$%e127440127484%_
                                   _%$%hd127441127488%_
                                   _%$%tl127442127491%_
                                   _%__splice128283128284%_
                                   _%$%target127443127494%_
                                   _%$%tl127445127497%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g127436127477%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g127436127477%_)))))
                  (let () (declare (not safe)) (_%$%g127436127477%_))))))))
    (define |[:0:]#@make-atomic-promise|
      (lambda (_%$stx127553%_)
        (let* ((_%__stx128304128305%_ _%$stx127553%_)
               (_%$%g127558127579%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx128304128305%_))))
          (let ((_%__kont128307128308%_
                 (lambda (_%$%g127560127644%_)
                   (cons (gx#datum->syntax
                          |[1]#_g128402_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'thunk) '())
                                     (cons (let ((__tmp128403
                                                  (lambda (_%$%g127659127662%_
                                                           _%$%g127660127665%_)
                                                    (cons _%$%g127659127662%_
                                                          _%$%g127660127665%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp128403
                                              '()
                                              _%$%g127560127644%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g128405_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'thunk)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':procedure) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__make-atomic-promise)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'thunk)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont128311128312%_
                 (lambda (_%$%g127573127586%_)
                   (gx#datum->syntax '#f 'make-atomic-promise))))
            (let* ((_%$%g127557127597%_
                    (lambda ()
                      (let ((_%$%g127573127586%_ _%__stx128304128305%_))
                        (if (gx#identifier? _%$%g127573127586%_)
                            (_%__kont128311128312%_ _%$%g127573127586%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g127558127579%_))))))
                   (_%__match128327128328%_
                    (lambda (_%$%e127561127604%_
                             _%$%hd127562127608%_
                             _%$%tl127563127611%_
                             _%__splice128309128310%_
                             _%$%target127564127614%_
                             _%$%tl127566127617%_)
                      (letrec ((_%$%loop127567127620%_
                                (lambda (_%$%hd127565127624%_
                                         _%$%arg127571127627%_)
                                  (if (gx#stx-pair? _%$%hd127565127624%_)
                                      (let ((_%$%e127568127630%_
                                             (gx#syntax-e
                                              _%$%hd127565127624%_)))
                                        (let ((_%$%lp-tl127570127637%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e127568127630%_)))
                                              (_%$%lp-hd127569127634%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e127568127630%_))))
                                          (_%$%loop127567127620%_
                                           _%$%lp-tl127570127637%_
                                           (cons _%$%lp-hd127569127634%_
                                                 _%$%arg127571127627%_))))
                                      (let ((_%$%arg127572127640%_
                                             (reverse _%$%arg127571127627%_)))
                                        (_%__kont128307128308%_
                                         _%$%arg127572127640%_))))))
                        (_%$%loop127567127620%_
                         _%$%target127564127614%_
                         '())))))
              (if (gx#stx-pair? _%__stx128304128305%_)
                  (let ((_%$%e127561127604%_
                         (gx#syntax-e _%__stx128304128305%_)))
                    (let ((_%$%tl127563127611%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e127561127604%_)))
                          (_%$%hd127562127608%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e127561127604%_))))
                      (if (gx#stx-pair/null? _%$%tl127563127611%_)
                          (let ((_%__splice128309128310%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl127563127611%_
                                  '0)))
                            (let ((_%$%tl127566127617%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128309128310%_
                                      '1)))
                                  (_%$%target127564127614%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128309128310%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl127566127617%_)
                                  (_%__match128327128328%_
                                   _%$%e127561127604%_
                                   _%$%hd127562127608%_
                                   _%$%tl127563127611%_
                                   _%__splice128309128310%_
                                   _%$%target127564127614%_
                                   _%$%tl127566127617%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g127557127597%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g127557127597%_)))))
                  (let () (declare (not safe)) (_%$%g127557127597%_))))))))
    (define |[:0:]#@with-unwind-protect|
      (lambda (_%$stx127673%_)
        (let* ((_%__stx128330128331%_ _%$stx127673%_)
               (_%$%g127678127699%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx128330128331%_))))
          (let ((_%__kont128333128334%_
                 (lambda (_%$%g127680127764%_)
                   (cons (gx#datum->syntax
                          |[1]#_g128407_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'K)
                                           (cons (gx#datum->syntax '#f 'fini)
                                                 '()))
                                     (cons (let ((__tmp128408
                                                  (lambda (_%$%g127779127782%_
                                                           _%$%g127780127785%_)
                                                    (cons _%$%g127779127782%_
                                                          _%$%g127780127785%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp128408
                                              '()
                                              _%$%g127680127764%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g128410_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'K)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':procedure) '())))
               (cons (cons (gx#datum->syntax '#f 'fini)
                           (cons (gx#datum->syntax '#f ':)
                                 (cons (gx#datum->syntax '#f ':procedure)
                                       '())))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__with-unwind-protect)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'K)
                           (cons (gx#datum->syntax '#f 'fini) '())))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont128337128338%_
                 (lambda (_%$%g127693127706%_)
                   (gx#datum->syntax '#f 'with-unwind-protect))))
            (let* ((_%$%g127677127717%_
                    (lambda ()
                      (let ((_%$%g127693127706%_ _%__stx128330128331%_))
                        (if (gx#identifier? _%$%g127693127706%_)
                            (_%__kont128337128338%_ _%$%g127693127706%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g127678127699%_))))))
                   (_%__match128353128354%_
                    (lambda (_%$%e127681127724%_
                             _%$%hd127682127728%_
                             _%$%tl127683127731%_
                             _%__splice128335128336%_
                             _%$%target127684127734%_
                             _%$%tl127686127737%_)
                      (letrec ((_%$%loop127687127740%_
                                (lambda (_%$%hd127685127744%_
                                         _%$%arg127691127747%_)
                                  (if (gx#stx-pair? _%$%hd127685127744%_)
                                      (let ((_%$%e127688127750%_
                                             (gx#syntax-e
                                              _%$%hd127685127744%_)))
                                        (let ((_%$%lp-tl127690127757%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e127688127750%_)))
                                              (_%$%lp-hd127689127754%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e127688127750%_))))
                                          (_%$%loop127687127740%_
                                           _%$%lp-tl127690127757%_
                                           (cons _%$%lp-hd127689127754%_
                                                 _%$%arg127691127747%_))))
                                      (let ((_%$%arg127692127760%_
                                             (reverse _%$%arg127691127747%_)))
                                        (_%__kont128333128334%_
                                         _%$%arg127692127760%_))))))
                        (_%$%loop127687127740%_
                         _%$%target127684127734%_
                         '())))))
              (if (gx#stx-pair? _%__stx128330128331%_)
                  (let ((_%$%e127681127724%_
                         (gx#syntax-e _%__stx128330128331%_)))
                    (let ((_%$%tl127683127731%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e127681127724%_)))
                          (_%$%hd127682127728%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e127681127724%_))))
                      (if (gx#stx-pair/null? _%$%tl127683127731%_)
                          (let ((_%__splice128335128336%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl127683127731%_
                                  '0)))
                            (let ((_%$%tl127686127737%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128335128336%_
                                      '1)))
                                  (_%$%target127684127734%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128335128336%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl127686127737%_)
                                  (_%__match128353128354%_
                                   _%$%e127681127724%_
                                   _%$%hd127682127728%_
                                   _%$%tl127683127731%_
                                   _%__splice128335128336%_
                                   _%$%target127684127734%_
                                   _%$%tl127686127737%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g127677127717%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g127677127717%_)))))
                  (let () (declare (not safe)) (_%$%g127677127717%_))))))))
    (define |[:0:]#@with-unwind-protect!|
      (lambda (_%$stx127793%_)
        (let* ((_%__stx128356128357%_ _%$stx127793%_)
               (_%$%g127798127819%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx128356128357%_))))
          (let ((_%__kont128359128360%_
                 (lambda (_%$%g127800127884%_)
                   (cons (gx#datum->syntax
                          |[1]#_g128412_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'K)
                                           (cons (gx#datum->syntax '#f 'fini)
                                                 '()))
                                     (cons (let ((__tmp128413
                                                  (lambda (_%$%g127899127902%_
                                                           _%$%g127900127905%_)
                                                    (cons _%$%g127899127902%_
                                                          _%$%g127900127905%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp128413
                                              '()
                                              _%$%g127800127884%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g128415_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'K)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':procedure) '())))
               (cons (cons (gx#datum->syntax '#f 'fini)
                           (cons (gx#datum->syntax '#f ':)
                                 (cons (gx#datum->syntax '#f ':procedure)
                                       '())))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__with-unwind-protect!)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'K)
                           (cons (gx#datum->syntax '#f 'fini) '())))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont128363128364%_
                 (lambda (_%$%g127813127826%_)
                   (gx#datum->syntax '#f 'with-unwind-protect!))))
            (let* ((_%$%g127797127837%_
                    (lambda ()
                      (let ((_%$%g127813127826%_ _%__stx128356128357%_))
                        (if (gx#identifier? _%$%g127813127826%_)
                            (_%__kont128363128364%_ _%$%g127813127826%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g127798127819%_))))))
                   (_%__match128379128380%_
                    (lambda (_%$%e127801127844%_
                             _%$%hd127802127848%_
                             _%$%tl127803127851%_
                             _%__splice128361128362%_
                             _%$%target127804127854%_
                             _%$%tl127806127857%_)
                      (letrec ((_%$%loop127807127860%_
                                (lambda (_%$%hd127805127864%_
                                         _%$%arg127811127867%_)
                                  (if (gx#stx-pair? _%$%hd127805127864%_)
                                      (let ((_%$%e127808127870%_
                                             (gx#syntax-e
                                              _%$%hd127805127864%_)))
                                        (let ((_%$%lp-tl127810127877%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e127808127870%_)))
                                              (_%$%lp-hd127809127874%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e127808127870%_))))
                                          (_%$%loop127807127860%_
                                           _%$%lp-tl127810127877%_
                                           (cons _%$%lp-hd127809127874%_
                                                 _%$%arg127811127867%_))))
                                      (let ((_%$%arg127812127880%_
                                             (reverse _%$%arg127811127867%_)))
                                        (_%__kont128359128360%_
                                         _%$%arg127812127880%_))))))
                        (_%$%loop127807127860%_
                         _%$%target127804127854%_
                         '())))))
              (if (gx#stx-pair? _%__stx128356128357%_)
                  (let ((_%$%e127801127844%_
                         (gx#syntax-e _%__stx128356128357%_)))
                    (let ((_%$%tl127803127851%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e127801127844%_)))
                          (_%$%hd127802127848%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e127801127844%_))))
                      (if (gx#stx-pair/null? _%$%tl127803127851%_)
                          (let ((_%__splice128361128362%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl127803127851%_
                                  '0)))
                            (let ((_%$%tl127806127857%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128361128362%_
                                      '1)))
                                  (_%$%target127804127854%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice128361128362%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl127806127857%_)
                                  (_%__match128379128380%_
                                   _%$%e127801127844%_
                                   _%$%hd127802127848%_
                                   _%$%tl127803127851%_
                                   _%__splice128361128362%_
                                   _%$%target127804127854%_
                                   _%$%tl127806127857%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g127797127837%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g127797127837%_)))))
                  (let () (declare (not safe)) (_%$%g127797127837%_))))))))))
