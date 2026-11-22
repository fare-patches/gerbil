(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gerbil/core/contract~Using[1]#_g107430_|
    (##structure gx#syntax-quote::t ':~ #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107431_|
    (##structure gx#syntax-quote::t ':~ #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107432_|
    (##structure gx#syntax-quote::t ':~ #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107435_|
    (##structure gx#syntax-quote::t ':~ #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107436_|
    (##structure gx#syntax-quote::t ':~ #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107441_|
    (##structure gx#syntax-quote::t ': #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107442_|
    (##structure gx#syntax-quote::t ':? #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107443_|
    (##structure gx#syntax-quote::t ':- #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107444_|
    (##structure gx#syntax-quote::t '::- #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107446_|
    (##structure gx#syntax-quote::t ':? #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107449_|
    (##structure gx#syntax-quote::t ': #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107450_|
    (##structure gx#syntax-quote::t ':? #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107451_|
    (##structure gx#syntax-quote::t ':- #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107452_|
    (##structure gx#syntax-quote::t '::- #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107454_|
    (##structure gx#syntax-quote::t ':? #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~Using[1]#_g107457_|
    (##structure
     gx#syntax-quote::t
     '%%ref-dotted
     #f
     (gx#current-expander-context)
     '()))
  (begin
    (define |gerbil/core/contract~Using[:0:]#using|
      (lambda (_%stx56444%_)
        (let* ((_%__stx100460100461%_ _%stx56444%_)
               (_%$%g5645456695%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx100460100461%_))))
          (let ((_%__kont100463100464%_
                 (lambda (_%$%g5645657739%_
                          _%$%g5645757741%_
                          _%$%g5645857742%_
                          _%$%g5645957743%_
                          _%$%g5646057744%_)
                   (if (let ((__tmp107429
                              (let ()
                                (declare (not safe))
                                (|gerbil/core/contract~TypeReference[1]#resolve-type|
                                 _%stx56444%_
                                 _%$%g5645857742%_))))
                         (declare (not safe))
                         (class-instance?
                          gerbil/core/contract~InterfaceInfo#interface-info::t
                          __tmp107429))
                       (cons (gx#datum->syntax '#f 'with-interface)
                             (cons (cons _%$%g5646057744%_
                                         (cons (gx#datum->syntax '#f ':?)
                                               (cons _%$%g5645857742%_
                                                     (cons 'unchecked: '()))))
                                   (foldr (lambda (_%$%g5777157774%_
                                                   _%$%g5777257777%_)
                                            (cons _%$%g5777157774%_
                                                  _%$%g5777257777%_))
                                          '()
                                          _%$%g5645657739%_)))
                       (cons (gx#datum->syntax '#f 'with-class)
                             (cons (cons _%$%g5646057744%_
                                         (cons (gx#datum->syntax '#f ':?)
                                               (cons _%$%g5645857742%_
                                                     (cons 'unchecked: '()))))
                                   (foldr (lambda (_%$%g5777957782%_
                                                   _%$%g5778057785%_)
                                            (cons _%$%g5777957782%_
                                                  _%$%g5778057785%_))
                                          '()
                                          _%$%g5645657739%_))))))
                (_%__kont100467100468%_
                 (lambda (_%$%g5648857587%_
                          _%$%g5648957589%_
                          _%$%g5649057590%_
                          _%$%g5649157591%_
                          _%$%g5649257592%_)
                   (cons (gx#datum->syntax '#f 'let)
                         (cons (cons _%$%g5649257592%_
                                     (cons _%$%g5649157591%_ '()))
                               (cons (cons (gx#datum->syntax '#f 'using)
                                           (cons (cons _%$%g5649257592%_
                                                       (cons _%$%g5649057590%_
                                                             (cons _%$%g5648957589%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (foldr (lambda (_%$%g5763557638%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g5763657641%_)
                  (cons _%$%g5763557638%_ _%$%g5763657641%_))
                '()
                _%$%g5648857587%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont100471100472%_
                 (lambda (_%$%g5652057433%_
                          _%$%g5652157435%_
                          _%$%g5652257436%_
                          _%$%g5652357437%_
                          _%$%g5652457438%_
                          _%$%g5652557439%_)
                   (cons (gx#datum->syntax '#f 'let)
                         (cons (cons _%$%g5652557439%_
                                     (cons _%$%g5652457438%_ '()))
                               (cons (cons (gx#datum->syntax '#f 'using)
                                           (cons (cons _%$%g5652557439%_
                                                       (cons (gx#datum->syntax
                                                              '#f
                                                              ':~)
                                                             (cons _%$%g5652357437%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'using)
                                                             (cons (cons _%$%g5652557439%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons _%$%g5652257436%_
                                       (cons _%$%g5652157435%_ '())))
                           (foldr (lambda (_%$%g5748357486%_ _%$%g5748457489%_)
                                    (cons _%$%g5748357486%_ _%$%g5748457489%_))
                                  '()
                                  _%$%g5652057433%_)))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont100475100476%_
                 (lambda (_%$%g5655957252%_
                          _%$%g5656057254%_
                          _%$%g5656157255%_
                          _%$%g5656257256%_)
                   (let ((_%meta57293%_
                          (let ()
                            (declare (not safe))
                            (|gerbil/core/contract~TypeReference[1]#resolve-type|
                             _%stx56444%_
                             _%$%g5656057254%_))))
                     (if (let ()
                           (declare (not safe))
                           (class-instance?
                            gerbil/core/contract~InterfaceInfo#interface-info::t
                            _%meta57293%_))
                         (cons (gx#datum->syntax '#f 'with-interface)
                               (cons (cons _%$%g5656257256%_
                                           (cons _%$%g5656157255%_
                                                 (cons _%$%g5656057254%_ '())))
                                     (foldr (lambda (_%$%g5729757300%_
                                                     _%$%g5729857303%_)
                                              (cons _%$%g5729757300%_
                                                    _%$%g5729857303%_))
                                            '()
                                            _%$%g5655957252%_)))
                         (if (let ()
                               (declare (not safe))
                               (class-instance?
                                gerbil/core/mop~MOP-2#class-type-info::t
                                _%meta57293%_))
                             (cons (gx#datum->syntax '#f 'with-class)
                                   (cons (cons _%$%g5656257256%_
                                               (cons _%$%g5656157255%_
                                                     (cons _%$%g5656057254%_
                                                           '())))
                                         (foldr (lambda (_%$%g5730757310%_
                                                         _%$%g5730857313%_)
                                                  (cons _%$%g5730757310%_
                                                        _%$%g5730857313%_))
                                                '()
                                                _%$%g5655957252%_)))
                             (gx#raise-syntax-error
                              '#f
                              '"unexpected type; must be a class type or interface"
                              _%stx56444%_
                              _%$%g5656057254%_
                              _%meta57293%_))))))
                (_%__kont100479100480%_
                 (lambda (_%$%g5658757132%_
                          _%$%g5658857134%_
                          _%$%g5658957135%_)
                   (cons (gx#datum->syntax '#f 'with-contract)
                         (cons (cons _%$%g5658957135%_
                                     (cons (gx#datum->syntax '#f ':~)
                                           (cons _%$%g5658857134%_ '())))
                               (foldr (lambda (_%$%g5715857161%_
                                               _%$%g5715957164%_)
                                        (cons _%$%g5715857161%_
                                              _%$%g5715957164%_))
                                      '()
                                      _%$%g5658757132%_)))))
                (_%__kont100483100484%_
                 (lambda (_%$%g5661456992%_
                          _%$%g5661556994%_
                          _%$%g5661656995%_
                          _%$%g5661756996%_
                          _%$%g5661856997%_)
                   (cons (gx#datum->syntax '#f 'using)
                         (cons (cons _%$%g5661856997%_
                                     (cons (gx#datum->syntax '#f ':~)
                                           (cons _%$%g5661756996%_ '())))
                               (cons (cons (gx#datum->syntax '#f 'using)
                                           (cons (cons _%$%g5661856997%_
                                                       (cons _%$%g5661656995%_
                                                             (cons _%$%g5661556994%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (foldr (lambda (_%$%g5703857041%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g5703957044%_)
                  (cons _%$%g5703857041%_ _%$%g5703957044%_))
                '()
                _%$%g5661456992%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont100487100488%_
                 (lambda (_%$%g5664956852%_
                          _%$%g5665056854%_
                          _%$%g5665156855%_
                          _%$%g5665256856%_)
                   (cons (gx#datum->syntax '#f 'using)
                         (cons (cons _%$%g5665256856%_ _%$%g5665156855%_)
                               (cons (cons (gx#datum->syntax '#f 'using)
                                           (cons _%$%g5665056854%_
                                                 (foldr (lambda (_%$%g5687856881%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g5687956884%_)
                  (cons _%$%g5687856881%_ _%$%g5687956884%_))
                '()
                _%$%g5664956852%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont100491100492%_
                 (lambda (_%$%g5667456750%_)
                   (cons (gx#datum->syntax '#f 'let)
                         (cons '()
                               (foldr (lambda (_%$%g5676856771%_
                                               _%$%g5676956774%_)
                                        (cons _%$%g5676856771%_
                                              _%$%g5676956774%_))
                                      '()
                                      _%$%g5667456750%_))))))
            (let* ((_%__match100843100844%_
                    (lambda (_%$%e5667556702%_
                             _%$%hd5667656706%_
                             _%$%tl5667756709%_
                             _%$%e5667856712%_
                             _%$%hd5667956716%_
                             _%$%tl5668056719%_
                             _%__splice100493100494%_
                             _%$%target5668156722%_
                             _%$%tl5668356725%_)
                      (letrec ((_%$%loop5668456728%_
                                (lambda (_%$%hd5668256732%_
                                         _%$%body5668856735%_)
                                  (if (gx#stx-pair? _%$%hd5668256732%_)
                                      (let ((_%$%e5668556737%_
                                             (gx#syntax-e _%$%hd5668256732%_)))
                                        (let ((_%$%lp-tl5668756744%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5668556737%_)))
                                              (_%$%lp-hd5668656741%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5668556737%_))))
                                          (_%$%loop5668456728%_
                                           _%$%lp-tl5668756744%_
                                           (cons _%$%lp-hd5668656741%_
                                                 _%$%body5668856735%_))))
                                      (let ((_%$%body5668956747%_
                                             (reverse _%$%body5668856735%_)))
                                        (_%__kont100491100492%_
                                         _%$%body5668956747%_))))))
                        (_%$%loop5668456728%_ _%$%target5668156722%_ '()))))
                   (_%__match100821100822%_
                    (lambda (_%$%e5665356784%_
                             _%$%hd5665456788%_
                             _%$%tl5665556791%_
                             _%$%e5665656794%_
                             _%$%hd5665756798%_
                             _%$%tl5665856801%_
                             _%$%e5665956804%_
                             _%$%hd5666056808%_
                             _%$%tl5666156811%_
                             _%$%e5666256814%_
                             _%$%hd5666356818%_
                             _%$%tl5666456821%_
                             _%__splice100489100490%_
                             _%$%target5666556824%_
                             _%$%tl5666756827%_)
                      (letrec ((_%$%loop5666856830%_
                                (lambda (_%$%hd5666656834%_
                                         _%$%body5667256837%_)
                                  (if (gx#stx-pair? _%$%hd5666656834%_)
                                      (let ((_%$%e5666956839%_
                                             (gx#syntax-e _%$%hd5666656834%_)))
                                        (let ((_%$%lp-tl5667156846%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666956839%_)))
                                              (_%$%lp-hd5667056843%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666956839%_))))
                                          (_%$%loop5666856830%_
                                           _%$%lp-tl5667156846%_
                                           (cons _%$%lp-hd5667056843%_
                                                 _%$%body5667256837%_))))
                                      (let ((_%$%body5667356849%_
                                             (reverse _%$%body5667256837%_)))
                                        (let ((_%$%g5664956852%_
                                               _%$%body5667356849%_)
                                              (_%$%g5665056854%_
                                               _%$%tl5666156811%_)
                                              (_%$%g5665156855%_
                                               _%$%tl5666456821%_)
                                              (_%$%g5665256856%_
                                               _%$%hd5666356818%_))
                                          (if (gx#identifier?
                                               _%$%g5665256856%_)
                                              (_%__kont100487100488%_
                                               _%$%g5664956852%_
                                               _%$%g5665056854%_
                                               _%$%g5665156855%_
                                               _%$%g5665256856%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_)))))))))
                        (_%$%loop5666856830%_ _%$%target5666556824%_ '()))))
                   (_%__match100807100808%_
                    (lambda (_%$%e5665356784%_
                             _%$%hd5665456788%_
                             _%$%tl5665556791%_
                             _%$%e5665656794%_
                             _%$%hd5665756798%_
                             _%$%tl5665856801%_
                             _%$%e5665956804%_
                             _%$%hd5666056808%_
                             _%$%tl5666156811%_)
                      (if (gx#stx-pair? _%$%hd5666056808%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5666056808%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (if (gx#stx-pair/null? _%$%tl5665856801%_)
                                  (let ((_%__splice100489100490%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5665856801%_
                                          '0)))
                                    (let ((_%$%tl5666756827%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '1)))
                                          (_%$%target5666556824%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5666756827%_)
                                          (_%__match100821100822%_
                                           _%$%e5665356784%_
                                           _%$%hd5665456788%_
                                           _%$%tl5665556791%_
                                           _%$%e5665656794%_
                                           _%$%hd5665756798%_
                                           _%$%tl5665856801%_
                                           _%$%e5665956804%_
                                           _%$%hd5666056808%_
                                           _%$%tl5666156811%_
                                           _%$%e5666256814%_
                                           _%$%hd5666356818%_
                                           _%$%tl5666456821%_
                                           _%__splice100489100490%_
                                           _%$%target5666556824%_
                                           _%$%tl5666756827%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                   (_%__match100789100790%_
                    (lambda (_%$%e5661956894%_
                             _%$%hd5662056898%_
                             _%$%tl5662156901%_
                             _%$%e5662256904%_
                             _%$%hd5662356908%_
                             _%$%tl5662456911%_
                             _%$%e5662556914%_
                             _%$%hd5662656918%_
                             _%$%tl5662756921%_
                             _%$%e5662856924%_
                             _%$%hd5662956928%_
                             _%$%tl5663056931%_
                             _%$%e5663156934%_
                             _%$%hd5663256938%_
                             _%$%tl5663356941%_
                             _%$%e5663456944%_
                             _%$%hd5663556948%_
                             _%$%tl5663656951%_
                             _%$%e5663756954%_
                             _%$%hd5663856958%_
                             _%$%tl5663956961%_
                             _%__splice100485100486%_
                             _%$%target5664056964%_
                             _%$%tl5664256967%_)
                      (letrec ((_%$%loop5664356970%_
                                (lambda (_%$%hd5664156974%_
                                         _%$%body5664756977%_)
                                  (if (gx#stx-pair? _%$%hd5664156974%_)
                                      (let ((_%$%e5664456979%_
                                             (gx#syntax-e _%$%hd5664156974%_)))
                                        (let ((_%$%lp-tl5664656986%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5664456979%_)))
                                              (_%$%lp-hd5664556983%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5664456979%_))))
                                          (_%$%loop5664356970%_
                                           _%$%lp-tl5664656986%_
                                           (cons _%$%lp-hd5664556983%_
                                                 _%$%body5664756977%_))))
                                      (let ((_%$%body5664856989%_
                                             (reverse _%$%body5664756977%_)))
                                        (let ((_%$%g5661456992%_
                                               _%$%body5664856989%_)
                                              (_%$%g5661556994%_
                                               _%$%hd5663856958%_)
                                              (_%$%g5661656995%_
                                               _%$%hd5663556948%_)
                                              (_%$%g5661756996%_
                                               _%$%hd5663256938%_)
                                              (_%$%g5661856997%_
                                               _%$%hd5662656918%_))
                                          (if (and (gx#identifier?
                                                    _%$%g5661856997%_)
                                                   (gx#identifier?
                                                    _%$%g5661556994%_)
                                                   (gx#identifier?
                                                    _%$%g5661656995%_)
                                                   (or (gx#free-identifier=?
                                                        _%$%g5661656995%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':))
                                                       (gx#free-identifier=?
                                                        _%$%g5661656995%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':-))
                                                       (gx#free-identifier=?
                                                        _%$%g5661656995%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         '::-))
                                                       (gx#free-identifier=?
                                                        _%$%g5661656995%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':?))))
                                              (_%__kont100483100484%_
                                               _%$%g5661456992%_
                                               _%$%g5661556994%_
                                               _%$%g5661656995%_
                                               _%$%g5661756996%_
                                               _%$%g5661856997%_)
                                              (_%__match100807100808%_
                                               _%$%e5661956894%_
                                               _%$%hd5662056898%_
                                               _%$%tl5662156901%_
                                               _%$%e5662256904%_
                                               _%$%hd5662356908%_
                                               _%$%tl5662456911%_
                                               _%$%e5662556914%_
                                               _%$%hd5662656918%_
                                               _%$%tl5662756921%_))))))))
                        (_%$%loop5664356970%_ _%$%target5664056964%_ '()))))
                   (_%__match100733100734%_
                    (lambda (_%$%e5659057054%_
                             _%$%hd5659157058%_
                             _%$%tl5659257061%_
                             _%$%e5659357064%_
                             _%$%hd5659457068%_
                             _%$%tl5659557071%_
                             _%$%e5659657074%_
                             _%$%hd5659757078%_
                             _%$%tl5659857081%_
                             _%$%e5659957084%_
                             _%$%hd5660057088%_
                             _%$%tl5660157091%_
                             _%$%e5660257094%_
                             _%$%hd5660357098%_
                             _%$%tl5660457101%_
                             _%__splice100481100482%_
                             _%$%target5660557104%_
                             _%$%tl5660757107%_)
                      (letrec ((_%$%loop5660857110%_
                                (lambda (_%$%hd5660657114%_
                                         _%$%body5661257117%_)
                                  (if (gx#stx-pair? _%$%hd5660657114%_)
                                      (let ((_%$%e5660957119%_
                                             (gx#syntax-e _%$%hd5660657114%_)))
                                        (let ((_%$%lp-tl5661157126%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5660957119%_)))
                                              (_%$%lp-hd5661057123%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5660957119%_))))
                                          (_%$%loop5660857110%_
                                           _%$%lp-tl5661157126%_
                                           (cons _%$%lp-hd5661057123%_
                                                 _%$%body5661257117%_))))
                                      (let ((_%$%body5661357129%_
                                             (reverse _%$%body5661257117%_)))
                                        (let ((_%$%g5658757132%_
                                               _%$%body5661357129%_)
                                              (_%$%g5658857134%_
                                               _%$%hd5660357098%_)
                                              (_%$%g5658957135%_
                                               _%$%hd5659757078%_))
                                          (if (gx#identifier?
                                               _%$%g5658957135%_)
                                              (_%__kont100479100480%_
                                               _%$%g5658757132%_
                                               _%$%g5658857134%_
                                               _%$%g5658957135%_)
                                              (_%__match100807100808%_
                                               _%$%e5659057054%_
                                               _%$%hd5659157058%_
                                               _%$%tl5659257061%_
                                               _%$%e5659357064%_
                                               _%$%hd5659457068%_
                                               _%$%tl5659557071%_
                                               _%$%e5659657074%_
                                               _%$%hd5659757078%_
                                               _%$%tl5659857081%_))))))))
                        (_%$%loop5660857110%_ _%$%target5660557104%_ '()))))
                   (_%__match100713100714%_
                    (lambda (_%$%e5659057054%_
                             _%$%hd5659157058%_
                             _%$%tl5659257061%_
                             _%$%e5659357064%_
                             _%$%hd5659457068%_
                             _%$%tl5659557071%_
                             _%$%e5659657074%_
                             _%$%hd5659757078%_
                             _%$%tl5659857081%_
                             _%$%e5659957084%_
                             _%$%hd5660057088%_
                             _%$%tl5660157091%_)
                      (if (gx#identifier? _%$%hd5660057088%_)
                          (if (gx#free-identifier=?
                               |gerbil/core/contract~Using[1]#_g107430_|
                               _%$%hd5660057088%_)
                              (if (gx#stx-pair? _%$%tl5660157091%_)
                                  (let ((_%$%e5660257094%_
                                         (gx#syntax-e _%$%tl5660157091%_)))
                                    (let ((_%$%tl5660457101%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5660257094%_)))
                                          (_%$%hd5660357098%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5660257094%_))))
                                      (if (gx#stx-null? _%$%tl5660457101%_)
                                          (if (gx#stx-pair/null?
                                               _%$%tl5659557071%_)
                                              (let ((_%__splice100481100482%_
                                                     (gx#syntax-split-splice->vector
                                                      _%$%tl5659557071%_
                                                      '0)))
                                                (let ((_%$%tl5660757107%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100481100482%_
                                                          '1)))
                                                      (_%$%target5660557104%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100481100482%_
                                                          '0))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5660757107%_)
                                                      (_%__match100733100734%_
                                                       _%$%e5659057054%_
                                                       _%$%hd5659157058%_
                                                       _%$%tl5659257061%_
                                                       _%$%e5659357064%_
                                                       _%$%hd5659457068%_
                                                       _%$%tl5659557071%_
                                                       _%$%e5659657074%_
                                                       _%$%hd5659757078%_
                                                       _%$%tl5659857081%_
                                                       _%$%e5659957084%_
                                                       _%$%hd5660057088%_
                                                       _%$%tl5660157091%_
                                                       _%$%e5660257094%_
                                                       _%$%hd5660357098%_
                                                       _%$%tl5660457101%_
                                                       _%__splice100481100482%_
                                                       _%$%target5660557104%_
                                                       _%$%tl5660757107%_)
                                                      (if (gx#stx-pair?
                                                           _%$%hd5659757078%_)
                                                          (let ((_%$%e5666256814%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%hd5659757078%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#stx-pair?
                                                   _%$%hd5659757078%_)
                                                  (let ((_%$%e5666256814%_
                                                         (gx#syntax-e
                                                          _%$%hd5659757078%_)))
                                                    (let ((_%$%tl5666456821%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5666256814%_)))
                                                          (_%$%hd5666356818%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5666256814%_))))
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g5645456695%_))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_))))
                                          (if (gx#stx-pair? _%$%tl5660457101%_)
                                              (let ((_%$%e5663456944%_
                                                     (gx#syntax-e
                                                      _%$%tl5660457101%_)))
                                                (let ((_%$%tl5663656951%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5663456944%_)))
                                                      (_%$%hd5663556948%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5663456944%_))))
                                                  (if (gx#stx-pair?
                                                       _%$%tl5663656951%_)
                                                      (let ((_%$%e5663756954%_
                                                             (gx#syntax-e
                                                              _%$%tl5663656951%_)))
                                                        (let ((_%$%tl5663956961%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5663756954%_)))
                      (_%$%hd5663856958%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5663756954%_))))
                  (if (gx#stx-null? _%$%tl5663956961%_)
                      (if (gx#stx-pair/null? _%$%tl5659557071%_)
                          (let ((_%__splice100485100486%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5659557071%_
                                  '0)))
                            (let ((_%$%tl5664256967%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100485100486%_
                                      '1)))
                                  (_%$%target5664056964%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100485100486%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5664256967%_)
                                  (_%__match100789100790%_
                                   _%$%e5659057054%_
                                   _%$%hd5659157058%_
                                   _%$%tl5659257061%_
                                   _%$%e5659357064%_
                                   _%$%hd5659457068%_
                                   _%$%tl5659557071%_
                                   _%$%e5659657074%_
                                   _%$%hd5659757078%_
                                   _%$%tl5659857081%_
                                   _%$%e5659957084%_
                                   _%$%hd5660057088%_
                                   _%$%tl5660157091%_
                                   _%$%e5660257094%_
                                   _%$%hd5660357098%_
                                   _%$%tl5660457101%_
                                   _%$%e5663456944%_
                                   _%$%hd5663556948%_
                                   _%$%tl5663656951%_
                                   _%$%e5663756954%_
                                   _%$%hd5663856958%_
                                   _%$%tl5663956961%_
                                   _%__splice100485100486%_
                                   _%$%target5664056964%_
                                   _%$%tl5664256967%_)
                                  (if (gx#stx-pair? _%$%hd5659757078%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5659757078%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))
                          (if (gx#stx-pair? _%$%hd5659757078%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5659757078%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                      (if (gx#stx-pair? _%$%hd5659757078%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5659757078%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (if (gx#stx-pair/null? _%$%tl5659557071%_)
                                  (let ((_%__splice100489100490%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5659557071%_
                                          '0)))
                                    (let ((_%$%tl5666756827%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '1)))
                                          (_%$%target5666556824%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5666756827%_)
                                          (_%__match100821100822%_
                                           _%$%e5659057054%_
                                           _%$%hd5659157058%_
                                           _%$%tl5659257061%_
                                           _%$%e5659357064%_
                                           _%$%hd5659457068%_
                                           _%$%tl5659557071%_
                                           _%$%e5659657074%_
                                           _%$%hd5659757078%_
                                           _%$%tl5659857081%_
                                           _%$%e5666256814%_
                                           _%$%hd5666356818%_
                                           _%$%tl5666456821%_
                                           _%__splice100489100490%_
                                           _%$%target5666556824%_
                                           _%$%tl5666756827%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))))
              (if (gx#stx-pair? _%$%hd5659757078%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5659757078%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (if (gx#stx-pair/null? _%$%tl5659557071%_)
                          (let ((_%__splice100489100490%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5659557071%_
                                  '0)))
                            (let ((_%$%tl5666756827%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '1)))
                                  (_%$%target5666556824%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5666756827%_)
                                  (_%__match100821100822%_
                                   _%$%e5659057054%_
                                   _%$%hd5659157058%_
                                   _%$%tl5659257061%_
                                   _%$%e5659357064%_
                                   _%$%hd5659457068%_
                                   _%$%tl5659557071%_
                                   _%$%e5659657074%_
                                   _%$%hd5659757078%_
                                   _%$%tl5659857081%_
                                   _%$%e5666256814%_
                                   _%$%hd5666356818%_
                                   _%$%tl5666456821%_
                                   _%__splice100489100490%_
                                   _%$%target5666556824%_
                                   _%$%tl5666756827%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#stx-pair?
                                                   _%$%hd5659757078%_)
                                                  (let ((_%$%e5666256814%_
                                                         (gx#syntax-e
                                                          _%$%hd5659757078%_)))
                                                    (let ((_%$%tl5666456821%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5666256814%_)))
                                                          (_%$%hd5666356818%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5666256814%_))))
                                                      (if (gx#stx-pair/null?
                                                           _%$%tl5659557071%_)
                                                          (let ((_%__splice100489100490%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice->vector
                          _%$%tl5659557071%_
                          '0)))
                    (let ((_%$%tl5666756827%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100489100490%_ '1)))
                          (_%$%target5666556824%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100489100490%_ '0))))
                      (if (gx#stx-null? _%$%tl5666756827%_)
                          (_%__match100821100822%_
                           _%$%e5659057054%_
                           _%$%hd5659157058%_
                           _%$%tl5659257061%_
                           _%$%e5659357064%_
                           _%$%hd5659457068%_
                           _%$%tl5659557071%_
                           _%$%e5659657074%_
                           _%$%hd5659757078%_
                           _%$%tl5659857081%_
                           _%$%e5666256814%_
                           _%$%hd5666356818%_
                           _%$%tl5666456821%_
                           _%__splice100489100490%_
                           _%$%target5666556824%_
                           _%$%tl5666756827%_)
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))))
                                  (if (gx#stx-pair? _%$%hd5659757078%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5659757078%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (if (gx#stx-pair/null?
                                               _%$%tl5659557071%_)
                                              (let ((_%__splice100489100490%_
                                                     (gx#syntax-split-splice->vector
                                                      _%$%tl5659557071%_
                                                      '0)))
                                                (let ((_%$%tl5666756827%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100489100490%_
                                                          '1)))
                                                      (_%$%target5666556824%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100489100490%_
                                                          '0))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5666756827%_)
                                                      (_%__match100821100822%_
                                                       _%$%e5659057054%_
                                                       _%$%hd5659157058%_
                                                       _%$%tl5659257061%_
                                                       _%$%e5659357064%_
                                                       _%$%hd5659457068%_
                                                       _%$%tl5659557071%_
                                                       _%$%e5659657074%_
                                                       _%$%hd5659757078%_
                                                       _%$%tl5659857081%_
                                                       _%$%e5666256814%_
                                                       _%$%hd5666356818%_
                                                       _%$%tl5666456821%_
                                                       _%__splice100489100490%_
                                                       _%$%target5666556824%_
                                                       _%$%tl5666756827%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g5645456695%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))
                              (if (gx#stx-pair? _%$%hd5659757078%_)
                                  (let ((_%$%e5666256814%_
                                         (gx#syntax-e _%$%hd5659757078%_)))
                                    (let ((_%$%tl5666456821%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5666256814%_)))
                                          (_%$%hd5666356818%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5666256814%_))))
                                      (if (gx#stx-pair/null?
                                           _%$%tl5659557071%_)
                                          (let ((_%__splice100489100490%_
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl5659557071%_
                                                  '0)))
                                            (let ((_%$%tl5666756827%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100489100490%_
                                                      '1)))
                                                  (_%$%target5666556824%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100489100490%_
                                                      '0))))
                                              (if (gx#stx-null?
                                                   _%$%tl5666756827%_)
                                                  (_%__match100821100822%_
                                                   _%$%e5659057054%_
                                                   _%$%hd5659157058%_
                                                   _%$%tl5659257061%_
                                                   _%$%e5659357064%_
                                                   _%$%hd5659457068%_
                                                   _%$%tl5659557071%_
                                                   _%$%e5659657074%_
                                                   _%$%hd5659757078%_
                                                   _%$%tl5659857081%_
                                                   _%$%e5666256814%_
                                                   _%$%hd5666356818%_
                                                   _%$%tl5666456821%_
                                                   _%__splice100489100490%_
                                                   _%$%target5666556824%_
                                                   _%$%tl5666756827%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                          (if (gx#stx-pair? _%$%hd5659757078%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5659757078%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (if (gx#stx-pair/null? _%$%tl5659557071%_)
                                      (let ((_%__splice100489100490%_
                                             (gx#syntax-split-splice->vector
                                              _%$%tl5659557071%_
                                              '0)))
                                        (let ((_%$%tl5666756827%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice100489100490%_
                                                  '1)))
                                              (_%$%target5666556824%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice100489100490%_
                                                  '0))))
                                          (if (gx#stx-null? _%$%tl5666756827%_)
                                              (_%__match100821100822%_
                                               _%$%e5659057054%_
                                               _%$%hd5659157058%_
                                               _%$%tl5659257061%_
                                               _%$%e5659357064%_
                                               _%$%hd5659457068%_
                                               _%$%tl5659557071%_
                                               _%$%e5659657074%_
                                               _%$%hd5659757078%_
                                               _%$%tl5659857081%_
                                               _%$%e5666256814%_
                                               _%$%hd5666356818%_
                                               _%$%tl5666456821%_
                                               _%__splice100489100490%_
                                               _%$%target5666556824%_
                                               _%$%tl5666756827%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))))
                   (_%__match100689100690%_
                    (lambda (_%$%e5656357174%_
                             _%$%hd5656457178%_
                             _%$%tl5656557181%_
                             _%$%e5656657184%_
                             _%$%hd5656757188%_
                             _%$%tl5656857191%_
                             _%$%e5656957194%_
                             _%$%hd5657057198%_
                             _%$%tl5657157201%_
                             _%$%e5657257204%_
                             _%$%hd5657357208%_
                             _%$%tl5657457211%_
                             _%$%e5657557214%_
                             _%$%hd5657657218%_
                             _%$%tl5657757221%_
                             _%__splice100477100478%_
                             _%$%target5657857224%_
                             _%$%tl5658057227%_)
                      (letrec ((_%$%loop5658157230%_
                                (lambda (_%$%hd5657957234%_
                                         _%$%body5658557237%_)
                                  (if (gx#stx-pair? _%$%hd5657957234%_)
                                      (let ((_%$%e5658257239%_
                                             (gx#syntax-e _%$%hd5657957234%_)))
                                        (let ((_%$%lp-tl5658457246%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5658257239%_)))
                                              (_%$%lp-hd5658357243%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5658257239%_))))
                                          (_%$%loop5658157230%_
                                           _%$%lp-tl5658457246%_
                                           (cons _%$%lp-hd5658357243%_
                                                 _%$%body5658557237%_))))
                                      (let ((_%$%body5658657249%_
                                             (reverse _%$%body5658557237%_)))
                                        (let ((_%$%g5655957252%_
                                               _%$%body5658657249%_)
                                              (_%$%g5656057254%_
                                               _%$%hd5657657218%_)
                                              (_%$%g5656157255%_
                                               _%$%hd5657357208%_)
                                              (_%$%g5656257256%_
                                               _%$%hd5657057198%_))
                                          (if (and (gx#identifier?
                                                    _%$%g5656257256%_)
                                                   (gx#identifier?
                                                    _%$%g5656057254%_)
                                                   (gx#identifier?
                                                    _%$%g5656157255%_)
                                                   (or (gx#free-identifier=?
                                                        _%$%g5656157255%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':))
                                                       (gx#free-identifier=?
                                                        _%$%g5656157255%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':-))
                                                       (gx#free-identifier=?
                                                        _%$%g5656157255%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         '::-))
                                                       (gx#free-identifier=?
                                                        _%$%g5656157255%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':?))))
                                              (_%__kont100475100476%_
                                               _%$%g5655957252%_
                                               _%$%g5656057254%_
                                               _%$%g5656157255%_
                                               _%$%g5656257256%_)
                                              (_%__match100713100714%_
                                               _%$%e5656357174%_
                                               _%$%hd5656457178%_
                                               _%$%tl5656557181%_
                                               _%$%e5656657184%_
                                               _%$%hd5656757188%_
                                               _%$%tl5656857191%_
                                               _%$%e5656957194%_
                                               _%$%hd5657057198%_
                                               _%$%tl5657157201%_
                                               _%$%e5657257204%_
                                               _%$%hd5657357208%_
                                               _%$%tl5657457211%_))))))))
                        (_%$%loop5658157230%_ _%$%target5657857224%_ '()))))
                   (_%__match100649100650%_
                    (lambda (_%$%e5652657325%_
                             _%$%hd5652757329%_
                             _%$%tl5652857332%_
                             _%$%e5652957335%_
                             _%$%hd5653057339%_
                             _%$%tl5653157342%_
                             _%$%e5653257345%_
                             _%$%hd5653357349%_
                             _%$%tl5653457352%_
                             _%$%e5653557355%_
                             _%$%hd5653657359%_
                             _%$%tl5653757362%_
                             _%$%e5653857365%_
                             _%$%hd5653957369%_
                             _%$%tl5654057372%_
                             _%$%e5654157375%_
                             _%$%hd5654257379%_
                             _%$%tl5654357382%_
                             _%$%e5654457385%_
                             _%$%hd5654557389%_
                             _%$%tl5654657392%_
                             _%$%e5654757395%_
                             _%$%hd5654857399%_
                             _%$%tl5654957402%_
                             _%__splice100473100474%_
                             _%$%target5655057405%_
                             _%$%tl5655257408%_)
                      (letrec ((_%$%loop5655357411%_
                                (lambda (_%$%hd5655157415%_
                                         _%$%body5655757418%_)
                                  (if (gx#stx-pair? _%$%hd5655157415%_)
                                      (let ((_%$%e5655457420%_
                                             (gx#syntax-e _%$%hd5655157415%_)))
                                        (let ((_%$%lp-tl5655657427%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5655457420%_)))
                                              (_%$%lp-hd5655557424%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5655457420%_))))
                                          (_%$%loop5655357411%_
                                           _%$%lp-tl5655657427%_
                                           (cons _%$%lp-hd5655557424%_
                                                 _%$%body5655757418%_))))
                                      (let ((_%$%body5655857430%_
                                             (reverse _%$%body5655757418%_)))
                                        (let ((_%$%g5652057433%_
                                               _%$%body5655857430%_)
                                              (_%$%g5652157435%_
                                               _%$%hd5654857399%_)
                                              (_%$%g5652257436%_
                                               _%$%hd5654557389%_)
                                              (_%$%g5652357437%_
                                               _%$%hd5654257379%_)
                                              (_%$%g5652457438%_
                                               _%$%hd5653657359%_)
                                              (_%$%g5652557439%_
                                               _%$%hd5653357349%_))
                                          (if (and (gx#identifier?
                                                    _%$%g5652557439%_)
                                                   (gx#identifier?
                                                    _%$%g5652157435%_)
                                                   (gx#identifier?
                                                    _%$%g5652257436%_)
                                                   (or (gx#free-identifier=?
                                                        _%$%g5652257436%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':))
                                                       (gx#free-identifier=?
                                                        _%$%g5652257436%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':-))
                                                       (gx#free-identifier=?
                                                        _%$%g5652257436%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         '::-))
                                                       (gx#free-identifier=?
                                                        _%$%g5652257436%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':?))))
                                              (_%__kont100471100472%_
                                               _%$%g5652057433%_
                                               _%$%g5652157435%_
                                               _%$%g5652257436%_
                                               _%$%g5652357437%_
                                               _%$%g5652457438%_
                                               _%$%g5652557439%_)
                                              (_%__match100713100714%_
                                               _%$%e5652657325%_
                                               _%$%hd5652757329%_
                                               _%$%tl5652857332%_
                                               _%$%e5652957335%_
                                               _%$%hd5653057339%_
                                               _%$%tl5653157342%_
                                               _%$%e5653257345%_
                                               _%$%hd5653357349%_
                                               _%$%tl5653457352%_
                                               _%$%e5653557355%_
                                               _%$%hd5653657359%_
                                               _%$%tl5653757362%_))))))))
                        (_%$%loop5655357411%_ _%$%target5655057405%_ '()))))
                   (_%__match100617100618%_
                    (lambda (_%$%e5652657325%_
                             _%$%hd5652757329%_
                             _%$%tl5652857332%_
                             _%$%e5652957335%_
                             _%$%hd5653057339%_
                             _%$%tl5653157342%_
                             _%$%e5653257345%_
                             _%$%hd5653357349%_
                             _%$%tl5653457352%_
                             _%$%e5653557355%_
                             _%$%hd5653657359%_
                             _%$%tl5653757362%_
                             _%$%e5653857365%_
                             _%$%hd5653957369%_
                             _%$%tl5654057372%_)
                      (if (gx#identifier? _%$%hd5653957369%_)
                          (if (gx#free-identifier=?
                               |gerbil/core/contract~Using[1]#_g107431_|
                               _%$%hd5653957369%_)
                              (if (gx#stx-pair? _%$%tl5654057372%_)
                                  (let ((_%$%e5654157375%_
                                         (gx#syntax-e _%$%tl5654057372%_)))
                                    (let ((_%$%tl5654357382%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5654157375%_)))
                                          (_%$%hd5654257379%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5654157375%_))))
                                      (if (gx#stx-pair? _%$%tl5654357382%_)
                                          (let ((_%$%e5654457385%_
                                                 (gx#syntax-e
                                                  _%$%tl5654357382%_)))
                                            (let ((_%$%tl5654657392%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5654457385%_)))
                                                  (_%$%hd5654557389%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5654457385%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5654657392%_)
                                                  (let ((_%$%e5654757395%_
                                                         (gx#syntax-e
                                                          _%$%tl5654657392%_)))
                                                    (let ((_%$%tl5654957402%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5654757395%_)))
                                                          (_%$%hd5654857399%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5654757395%_))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5654957402%_)
                                                          (if (gx#stx-pair/null?
                                                               _%$%tl5653157342%_)
                                                              (let ((_%__splice100473100474%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#syntax-split-splice->vector
                              _%$%tl5653157342%_
                              '0)))
                        (let ((_%$%tl5655257408%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100473100474%_ '1)))
                              (_%$%target5655057405%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100473100474%_ '0))))
                          (if (gx#stx-null? _%$%tl5655257408%_)
                              (_%__match100649100650%_
                               _%$%e5652657325%_
                               _%$%hd5652757329%_
                               _%$%tl5652857332%_
                               _%$%e5652957335%_
                               _%$%hd5653057339%_
                               _%$%tl5653157342%_
                               _%$%e5653257345%_
                               _%$%hd5653357349%_
                               _%$%tl5653457352%_
                               _%$%e5653557355%_
                               _%$%hd5653657359%_
                               _%$%tl5653757362%_
                               _%$%e5653857365%_
                               _%$%hd5653957369%_
                               _%$%tl5654057372%_
                               _%$%e5654157375%_
                               _%$%hd5654257379%_
                               _%$%tl5654357382%_
                               _%$%e5654457385%_
                               _%$%hd5654557389%_
                               _%$%tl5654657392%_
                               _%$%e5654757395%_
                               _%$%hd5654857399%_
                               _%$%tl5654957402%_
                               _%__splice100473100474%_
                               _%$%target5655057405%_
                               _%$%tl5655257408%_)
                              (if (gx#stx-pair? _%$%hd5653357349%_)
                                  (let ((_%$%e5666256814%_
                                         (gx#syntax-e _%$%hd5653357349%_)))
                                    (let ((_%$%tl5666456821%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5666256814%_)))
                                          (_%$%hd5666356818%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5666256814%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))))
                      (if (gx#stx-pair? _%$%hd5653357349%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5653357349%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))
                  (if (gx#stx-pair? _%$%hd5653357349%_)
                      (let ((_%$%e5666256814%_
                             (gx#syntax-e _%$%hd5653357349%_)))
                        (let ((_%$%tl5666456821%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5666256814%_)))
                              (_%$%hd5666356818%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5666256814%_))))
                          (if (gx#stx-pair/null? _%$%tl5653157342%_)
                              (let ((_%__splice100489100490%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5653157342%_
                                      '0)))
                                (let ((_%$%tl5666756827%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '1)))
                                      (_%$%target5666556824%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5666756827%_)
                                      (_%__match100821100822%_
                                       _%$%e5652657325%_
                                       _%$%hd5652757329%_
                                       _%$%tl5652857332%_
                                       _%$%e5652957335%_
                                       _%$%hd5653057339%_
                                       _%$%tl5653157342%_
                                       _%$%e5653257345%_
                                       _%$%hd5653357349%_
                                       _%$%tl5653457352%_
                                       _%$%e5666256814%_
                                       _%$%hd5666356818%_
                                       _%$%tl5666456821%_
                                       _%__splice100489100490%_
                                       _%$%target5666556824%_
                                       _%$%tl5666756827%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#identifier?
                                                       _%$%hd5653657359%_)
                                                      (if (gx#free-identifier=?
                                                           |gerbil/core/contract~Using[1]#_g107430_|
                                                           _%$%hd5653657359%_)
                                                          (if (gx#stx-null?
                                                               _%$%tl5654657392%_)
                                                              (if (gx#stx-pair/null?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%tl5653157342%_)
                          (let ((_%__splice100485100486%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5653157342%_
                                  '0)))
                            (let ((_%$%tl5664256967%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100485100486%_
                                      '1)))
                                  (_%$%target5664056964%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100485100486%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5664256967%_)
                                  (_%__match100789100790%_
                                   _%$%e5652657325%_
                                   _%$%hd5652757329%_
                                   _%$%tl5652857332%_
                                   _%$%e5652957335%_
                                   _%$%hd5653057339%_
                                   _%$%tl5653157342%_
                                   _%$%e5653257345%_
                                   _%$%hd5653357349%_
                                   _%$%tl5653457352%_
                                   _%$%e5653557355%_
                                   _%$%hd5653657359%_
                                   _%$%tl5653757362%_
                                   _%$%e5653857365%_
                                   _%$%hd5653957369%_
                                   _%$%tl5654057372%_
                                   _%$%e5654157375%_
                                   _%$%hd5654257379%_
                                   _%$%tl5654357382%_
                                   _%$%e5654457385%_
                                   _%$%hd5654557389%_
                                   _%$%tl5654657392%_
                                   _%__splice100485100486%_
                                   _%$%target5664056964%_
                                   _%$%tl5664256967%_)
                                  (if (gx#stx-pair? _%$%hd5653357349%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5653357349%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))
                          (if (gx#stx-pair? _%$%hd5653357349%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5653357349%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                      (if (gx#stx-pair? _%$%hd5653357349%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5653357349%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (if (gx#stx-pair/null? _%$%tl5653157342%_)
                                  (let ((_%__splice100489100490%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5653157342%_
                                          '0)))
                                    (let ((_%$%tl5666756827%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '1)))
                                          (_%$%target5666556824%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5666756827%_)
                                          (_%__match100821100822%_
                                           _%$%e5652657325%_
                                           _%$%hd5652757329%_
                                           _%$%tl5652857332%_
                                           _%$%e5652957335%_
                                           _%$%hd5653057339%_
                                           _%$%tl5653157342%_
                                           _%$%e5653257345%_
                                           _%$%hd5653357349%_
                                           _%$%tl5653457352%_
                                           _%$%e5666256814%_
                                           _%$%hd5666356818%_
                                           _%$%tl5666456821%_
                                           _%__splice100489100490%_
                                           _%$%target5666556824%_
                                           _%$%tl5666756827%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))
                  (if (gx#stx-pair? _%$%hd5653357349%_)
                      (let ((_%$%e5666256814%_
                             (gx#syntax-e _%$%hd5653357349%_)))
                        (let ((_%$%tl5666456821%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5666256814%_)))
                              (_%$%hd5666356818%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5666256814%_))))
                          (if (gx#stx-pair/null? _%$%tl5653157342%_)
                              (let ((_%__splice100489100490%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5653157342%_
                                      '0)))
                                (let ((_%$%tl5666756827%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '1)))
                                      (_%$%target5666556824%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5666756827%_)
                                      (_%__match100821100822%_
                                       _%$%e5652657325%_
                                       _%$%hd5652757329%_
                                       _%$%tl5652857332%_
                                       _%$%e5652957335%_
                                       _%$%hd5653057339%_
                                       _%$%tl5653157342%_
                                       _%$%e5653257345%_
                                       _%$%hd5653357349%_
                                       _%$%tl5653457352%_
                                       _%$%e5666256814%_
                                       _%$%hd5666356818%_
                                       _%$%tl5666456821%_
                                       _%__splice100489100490%_
                                       _%$%target5666556824%_
                                       _%$%tl5666756827%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))
              (if (gx#stx-pair? _%$%hd5653357349%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5653357349%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (if (gx#stx-pair/null? _%$%tl5653157342%_)
                          (let ((_%__splice100489100490%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5653157342%_
                                  '0)))
                            (let ((_%$%tl5666756827%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '1)))
                                  (_%$%target5666556824%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5666756827%_)
                                  (_%__match100821100822%_
                                   _%$%e5652657325%_
                                   _%$%hd5652757329%_
                                   _%$%tl5652857332%_
                                   _%$%e5652957335%_
                                   _%$%hd5653057339%_
                                   _%$%tl5653157342%_
                                   _%$%e5653257345%_
                                   _%$%hd5653357349%_
                                   _%$%tl5653457352%_
                                   _%$%e5666256814%_
                                   _%$%hd5666356818%_
                                   _%$%tl5666456821%_
                                   _%__splice100489100490%_
                                   _%$%target5666556824%_
                                   _%$%tl5666756827%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair? _%$%hd5653357349%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5653357349%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5653157342%_)
                                                      (let ((_%__splice100489100490%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5653157342%_
                                                              '0)))
                                                        (let ((_%$%tl5666756827%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '1)))
                      (_%$%target5666556824%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '0))))
                  (if (gx#stx-null? _%$%tl5666756827%_)
                      (_%__match100821100822%_
                       _%$%e5652657325%_
                       _%$%hd5652757329%_
                       _%$%tl5652857332%_
                       _%$%e5652957335%_
                       _%$%hd5653057339%_
                       _%$%tl5653157342%_
                       _%$%e5653257345%_
                       _%$%hd5653357349%_
                       _%$%tl5653457352%_
                       _%$%e5666256814%_
                       _%$%hd5666356818%_
                       _%$%tl5666456821%_
                       _%__splice100489100490%_
                       _%$%target5666556824%_
                       _%$%tl5666756827%_)
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))))
                                  (if (gx#stx-null? _%$%tl5654057372%_)
                                      (if (gx#stx-pair/null?
                                           _%$%tl5653157342%_)
                                          (let ((_%__splice100477100478%_
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl5653157342%_
                                                  '0)))
                                            (let ((_%$%tl5658057227%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100477100478%_
                                                      '1)))
                                                  (_%$%target5657857224%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100477100478%_
                                                      '0))))
                                              (if (gx#stx-null?
                                                   _%$%tl5658057227%_)
                                                  (_%__match100689100690%_
                                                   _%$%e5652657325%_
                                                   _%$%hd5652757329%_
                                                   _%$%tl5652857332%_
                                                   _%$%e5652957335%_
                                                   _%$%hd5653057339%_
                                                   _%$%tl5653157342%_
                                                   _%$%e5653257345%_
                                                   _%$%hd5653357349%_
                                                   _%$%tl5653457352%_
                                                   _%$%e5653557355%_
                                                   _%$%hd5653657359%_
                                                   _%$%tl5653757362%_
                                                   _%$%e5653857365%_
                                                   _%$%hd5653957369%_
                                                   _%$%tl5654057372%_
                                                   _%__splice100477100478%_
                                                   _%$%target5657857224%_
                                                   _%$%tl5658057227%_)
                                                  (if (gx#stx-pair?
                                                       _%$%hd5653357349%_)
                                                      (let ((_%$%e5666256814%_
                                                             (gx#syntax-e
                                                              _%$%hd5653357349%_)))
                                                        (let ((_%$%tl5666456821%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5666256814%_)))
                      (_%$%hd5666356818%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5666256814%_))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))
              (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair? _%$%hd5653357349%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5653357349%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                      (if (gx#stx-pair? _%$%hd5653357349%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5653357349%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (if (gx#stx-pair/null?
                                                   _%$%tl5653157342%_)
                                                  (let ((_%__splice100489100490%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl5653157342%_
                                                          '0)))
                                                    (let ((_%$%tl5666756827%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '1)))
                                                          (_%$%target5666556824%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5666756827%_)
                                                          (_%__match100821100822%_
                                                           _%$%e5652657325%_
                                                           _%$%hd5652757329%_
                                                           _%$%tl5652857332%_
                                                           _%$%e5652957335%_
                                                           _%$%hd5653057339%_
                                                           _%$%tl5653157342%_
                                                           _%$%e5653257345%_
                                                           _%$%hd5653357349%_
                                                           _%$%tl5653457352%_
                                                           _%$%e5666256814%_
                                                           _%$%hd5666356818%_
                                                           _%$%tl5666456821%_
                                                           _%__splice100489100490%_
                                                           _%$%target5666556824%_
                                                           _%$%tl5666756827%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g5645456695%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                              (if (gx#stx-null? _%$%tl5654057372%_)
                                  (if (gx#stx-pair/null? _%$%tl5653157342%_)
                                      (let ((_%__splice100477100478%_
                                             (gx#syntax-split-splice->vector
                                              _%$%tl5653157342%_
                                              '0)))
                                        (let ((_%$%tl5658057227%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice100477100478%_
                                                  '1)))
                                              (_%$%target5657857224%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice100477100478%_
                                                  '0))))
                                          (if (gx#stx-null? _%$%tl5658057227%_)
                                              (_%__match100689100690%_
                                               _%$%e5652657325%_
                                               _%$%hd5652757329%_
                                               _%$%tl5652857332%_
                                               _%$%e5652957335%_
                                               _%$%hd5653057339%_
                                               _%$%tl5653157342%_
                                               _%$%e5653257345%_
                                               _%$%hd5653357349%_
                                               _%$%tl5653457352%_
                                               _%$%e5653557355%_
                                               _%$%hd5653657359%_
                                               _%$%tl5653757362%_
                                               _%$%e5653857365%_
                                               _%$%hd5653957369%_
                                               _%$%tl5654057372%_
                                               _%__splice100477100478%_
                                               _%$%target5657857224%_
                                               _%$%tl5658057227%_)
                                              (if (gx#stx-pair?
                                                   _%$%hd5653357349%_)
                                                  (let ((_%$%e5666256814%_
                                                         (gx#syntax-e
                                                          _%$%hd5653357349%_)))
                                                    (let ((_%$%tl5666456821%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5666256814%_)))
                                                          (_%$%hd5666356818%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5666256814%_))))
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g5645456695%_))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_))))))
                                      (if (gx#stx-pair? _%$%hd5653357349%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5653357349%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                  (if (gx#identifier? _%$%hd5653657359%_)
                                      (if (gx#free-identifier=?
                                           |gerbil/core/contract~Using[1]#_g107430_|
                                           _%$%hd5653657359%_)
                                          (if (gx#stx-pair? _%$%tl5654057372%_)
                                              (let ((_%$%e5663456944%_
                                                     (gx#syntax-e
                                                      _%$%tl5654057372%_)))
                                                (let ((_%$%tl5663656951%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5663456944%_)))
                                                      (_%$%hd5663556948%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5663456944%_))))
                                                  (if (gx#stx-pair?
                                                       _%$%tl5663656951%_)
                                                      (let ((_%$%e5663756954%_
                                                             (gx#syntax-e
                                                              _%$%tl5663656951%_)))
                                                        (let ((_%$%tl5663956961%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5663756954%_)))
                      (_%$%hd5663856958%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5663756954%_))))
                  (if (gx#stx-null? _%$%tl5663956961%_)
                      (if (gx#stx-pair/null? _%$%tl5653157342%_)
                          (let ((_%__splice100485100486%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5653157342%_
                                  '0)))
                            (let ((_%$%tl5664256967%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100485100486%_
                                      '1)))
                                  (_%$%target5664056964%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100485100486%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5664256967%_)
                                  (_%__match100789100790%_
                                   _%$%e5652657325%_
                                   _%$%hd5652757329%_
                                   _%$%tl5652857332%_
                                   _%$%e5652957335%_
                                   _%$%hd5653057339%_
                                   _%$%tl5653157342%_
                                   _%$%e5653257345%_
                                   _%$%hd5653357349%_
                                   _%$%tl5653457352%_
                                   _%$%e5653557355%_
                                   _%$%hd5653657359%_
                                   _%$%tl5653757362%_
                                   _%$%e5653857365%_
                                   _%$%hd5653957369%_
                                   _%$%tl5654057372%_
                                   _%$%e5663456944%_
                                   _%$%hd5663556948%_
                                   _%$%tl5663656951%_
                                   _%$%e5663756954%_
                                   _%$%hd5663856958%_
                                   _%$%tl5663956961%_
                                   _%__splice100485100486%_
                                   _%$%target5664056964%_
                                   _%$%tl5664256967%_)
                                  (if (gx#stx-pair? _%$%hd5653357349%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5653357349%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))
                          (if (gx#stx-pair? _%$%hd5653357349%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5653357349%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                      (if (gx#stx-pair? _%$%hd5653357349%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5653357349%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (if (gx#stx-pair/null? _%$%tl5653157342%_)
                                  (let ((_%__splice100489100490%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5653157342%_
                                          '0)))
                                    (let ((_%$%tl5666756827%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '1)))
                                          (_%$%target5666556824%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5666756827%_)
                                          (_%__match100821100822%_
                                           _%$%e5652657325%_
                                           _%$%hd5652757329%_
                                           _%$%tl5652857332%_
                                           _%$%e5652957335%_
                                           _%$%hd5653057339%_
                                           _%$%tl5653157342%_
                                           _%$%e5653257345%_
                                           _%$%hd5653357349%_
                                           _%$%tl5653457352%_
                                           _%$%e5666256814%_
                                           _%$%hd5666356818%_
                                           _%$%tl5666456821%_
                                           _%__splice100489100490%_
                                           _%$%target5666556824%_
                                           _%$%tl5666756827%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))))
              (if (gx#stx-pair? _%$%hd5653357349%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5653357349%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (if (gx#stx-pair/null? _%$%tl5653157342%_)
                          (let ((_%__splice100489100490%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5653157342%_
                                  '0)))
                            (let ((_%$%tl5666756827%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '1)))
                                  (_%$%target5666556824%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5666756827%_)
                                  (_%__match100821100822%_
                                   _%$%e5652657325%_
                                   _%$%hd5652757329%_
                                   _%$%tl5652857332%_
                                   _%$%e5652957335%_
                                   _%$%hd5653057339%_
                                   _%$%tl5653157342%_
                                   _%$%e5653257345%_
                                   _%$%hd5653357349%_
                                   _%$%tl5653457352%_
                                   _%$%e5666256814%_
                                   _%$%hd5666356818%_
                                   _%$%tl5666456821%_
                                   _%__splice100489100490%_
                                   _%$%target5666556824%_
                                   _%$%tl5666756827%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#stx-pair?
                                                   _%$%hd5653357349%_)
                                                  (let ((_%$%e5666256814%_
                                                         (gx#syntax-e
                                                          _%$%hd5653357349%_)))
                                                    (let ((_%$%tl5666456821%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5666256814%_)))
                                                          (_%$%hd5666356818%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5666256814%_))))
                                                      (if (gx#stx-pair/null?
                                                           _%$%tl5653157342%_)
                                                          (let ((_%__splice100489100490%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice->vector
                          _%$%tl5653157342%_
                          '0)))
                    (let ((_%$%tl5666756827%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100489100490%_ '1)))
                          (_%$%target5666556824%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100489100490%_ '0))))
                      (if (gx#stx-null? _%$%tl5666756827%_)
                          (_%__match100821100822%_
                           _%$%e5652657325%_
                           _%$%hd5652757329%_
                           _%$%tl5652857332%_
                           _%$%e5652957335%_
                           _%$%hd5653057339%_
                           _%$%tl5653157342%_
                           _%$%e5653257345%_
                           _%$%hd5653357349%_
                           _%$%tl5653457352%_
                           _%$%e5666256814%_
                           _%$%hd5666356818%_
                           _%$%tl5666456821%_
                           _%__splice100489100490%_
                           _%$%target5666556824%_
                           _%$%tl5666756827%_)
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_))))
                                          (if (gx#stx-pair? _%$%hd5653357349%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5653357349%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5653157342%_)
                                                      (let ((_%__splice100489100490%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5653157342%_
                                                              '0)))
                                                        (let ((_%$%tl5666756827%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '1)))
                      (_%$%target5666556824%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '0))))
                  (if (gx#stx-null? _%$%tl5666756827%_)
                      (_%__match100821100822%_
                       _%$%e5652657325%_
                       _%$%hd5652757329%_
                       _%$%tl5652857332%_
                       _%$%e5652957335%_
                       _%$%hd5653057339%_
                       _%$%tl5653157342%_
                       _%$%e5653257345%_
                       _%$%hd5653357349%_
                       _%$%tl5653457352%_
                       _%$%e5666256814%_
                       _%$%hd5666356818%_
                       _%$%tl5666456821%_
                       _%__splice100489100490%_
                       _%$%target5666556824%_
                       _%$%tl5666756827%_)
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                      (if (gx#stx-pair? _%$%hd5653357349%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5653357349%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (if (gx#stx-pair/null?
                                                   _%$%tl5653157342%_)
                                                  (let ((_%__splice100489100490%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl5653157342%_
                                                          '0)))
                                                    (let ((_%$%tl5666756827%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '1)))
                                                          (_%$%target5666556824%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5666756827%_)
                                                          (_%__match100821100822%_
                                                           _%$%e5652657325%_
                                                           _%$%hd5652757329%_
                                                           _%$%tl5652857332%_
                                                           _%$%e5652957335%_
                                                           _%$%hd5653057339%_
                                                           _%$%tl5653157342%_
                                                           _%$%e5653257345%_
                                                           _%$%hd5653357349%_
                                                           _%$%tl5653457352%_
                                                           _%$%e5666256814%_
                                                           _%$%hd5666356818%_
                                                           _%$%tl5666456821%_
                                                           _%__splice100489100490%_
                                                           _%$%target5666556824%_
                                                           _%$%tl5666756827%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g5645456695%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))))
                          (if (gx#stx-null? _%$%tl5654057372%_)
                              (if (gx#stx-pair/null? _%$%tl5653157342%_)
                                  (let ((_%__splice100477100478%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5653157342%_
                                          '0)))
                                    (let ((_%$%tl5658057227%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100477100478%_
                                              '1)))
                                          (_%$%target5657857224%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100477100478%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5658057227%_)
                                          (_%__match100689100690%_
                                           _%$%e5652657325%_
                                           _%$%hd5652757329%_
                                           _%$%tl5652857332%_
                                           _%$%e5652957335%_
                                           _%$%hd5653057339%_
                                           _%$%tl5653157342%_
                                           _%$%e5653257345%_
                                           _%$%hd5653357349%_
                                           _%$%tl5653457352%_
                                           _%$%e5653557355%_
                                           _%$%hd5653657359%_
                                           _%$%tl5653757362%_
                                           _%$%e5653857365%_
                                           _%$%hd5653957369%_
                                           _%$%tl5654057372%_
                                           _%__splice100477100478%_
                                           _%$%target5657857224%_
                                           _%$%tl5658057227%_)
                                          (if (gx#stx-pair? _%$%hd5653357349%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5653357349%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))))
                                  (if (gx#stx-pair? _%$%hd5653357349%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5653357349%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))
                              (if (gx#identifier? _%$%hd5653657359%_)
                                  (if (gx#free-identifier=?
                                       |gerbil/core/contract~Using[1]#_g107430_|
                                       _%$%hd5653657359%_)
                                      (if (gx#stx-pair? _%$%tl5654057372%_)
                                          (let ((_%$%e5663456944%_
                                                 (gx#syntax-e
                                                  _%$%tl5654057372%_)))
                                            (let ((_%$%tl5663656951%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5663456944%_)))
                                                  (_%$%hd5663556948%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5663456944%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5663656951%_)
                                                  (let ((_%$%e5663756954%_
                                                         (gx#syntax-e
                                                          _%$%tl5663656951%_)))
                                                    (let ((_%$%tl5663956961%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5663756954%_)))
                                                          (_%$%hd5663856958%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5663756954%_))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5663956961%_)
                                                          (if (gx#stx-pair/null?
                                                               _%$%tl5653157342%_)
                                                              (let ((_%__splice100485100486%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#syntax-split-splice->vector
                              _%$%tl5653157342%_
                              '0)))
                        (let ((_%$%tl5664256967%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100485100486%_ '1)))
                              (_%$%target5664056964%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100485100486%_ '0))))
                          (if (gx#stx-null? _%$%tl5664256967%_)
                              (_%__match100789100790%_
                               _%$%e5652657325%_
                               _%$%hd5652757329%_
                               _%$%tl5652857332%_
                               _%$%e5652957335%_
                               _%$%hd5653057339%_
                               _%$%tl5653157342%_
                               _%$%e5653257345%_
                               _%$%hd5653357349%_
                               _%$%tl5653457352%_
                               _%$%e5653557355%_
                               _%$%hd5653657359%_
                               _%$%tl5653757362%_
                               _%$%e5653857365%_
                               _%$%hd5653957369%_
                               _%$%tl5654057372%_
                               _%$%e5663456944%_
                               _%$%hd5663556948%_
                               _%$%tl5663656951%_
                               _%$%e5663756954%_
                               _%$%hd5663856958%_
                               _%$%tl5663956961%_
                               _%__splice100485100486%_
                               _%$%target5664056964%_
                               _%$%tl5664256967%_)
                              (if (gx#stx-pair? _%$%hd5653357349%_)
                                  (let ((_%$%e5666256814%_
                                         (gx#syntax-e _%$%hd5653357349%_)))
                                    (let ((_%$%tl5666456821%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5666256814%_)))
                                          (_%$%hd5666356818%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5666256814%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))))
                      (if (gx#stx-pair? _%$%hd5653357349%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5653357349%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))
                  (if (gx#stx-pair? _%$%hd5653357349%_)
                      (let ((_%$%e5666256814%_
                             (gx#syntax-e _%$%hd5653357349%_)))
                        (let ((_%$%tl5666456821%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5666256814%_)))
                              (_%$%hd5666356818%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5666256814%_))))
                          (if (gx#stx-pair/null? _%$%tl5653157342%_)
                              (let ((_%__splice100489100490%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5653157342%_
                                      '0)))
                                (let ((_%$%tl5666756827%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '1)))
                                      (_%$%target5666556824%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5666756827%_)
                                      (_%__match100821100822%_
                                       _%$%e5652657325%_
                                       _%$%hd5652757329%_
                                       _%$%tl5652857332%_
                                       _%$%e5652957335%_
                                       _%$%hd5653057339%_
                                       _%$%tl5653157342%_
                                       _%$%e5653257345%_
                                       _%$%hd5653357349%_
                                       _%$%tl5653457352%_
                                       _%$%e5666256814%_
                                       _%$%hd5666356818%_
                                       _%$%tl5666456821%_
                                       _%__splice100489100490%_
                                       _%$%target5666556824%_
                                       _%$%tl5666756827%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair?
                                                       _%$%hd5653357349%_)
                                                      (let ((_%$%e5666256814%_
                                                             (gx#syntax-e
                                                              _%$%hd5653357349%_)))
                                                        (let ((_%$%tl5666456821%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5666256814%_)))
                      (_%$%hd5666356818%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5666256814%_))))
                  (if (gx#stx-pair/null? _%$%tl5653157342%_)
                      (let ((_%__splice100489100490%_
                             (gx#syntax-split-splice->vector
                              _%$%tl5653157342%_
                              '0)))
                        (let ((_%$%tl5666756827%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '1)))
                              (_%$%target5666556824%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '0))))
                          (if (gx#stx-null? _%$%tl5666756827%_)
                              (_%__match100821100822%_
                               _%$%e5652657325%_
                               _%$%hd5652757329%_
                               _%$%tl5652857332%_
                               _%$%e5652957335%_
                               _%$%hd5653057339%_
                               _%$%tl5653157342%_
                               _%$%e5653257345%_
                               _%$%hd5653357349%_
                               _%$%tl5653457352%_
                               _%$%e5666256814%_
                               _%$%hd5666356818%_
                               _%$%tl5666456821%_
                               _%__splice100489100490%_
                               _%$%target5666556824%_
                               _%$%tl5666756827%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair? _%$%hd5653357349%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5653357349%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5653157342%_)
                                                      (let ((_%__splice100489100490%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5653157342%_
                                                              '0)))
                                                        (let ((_%$%tl5666756827%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '1)))
                      (_%$%target5666556824%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '0))))
                  (if (gx#stx-null? _%$%tl5666756827%_)
                      (_%__match100821100822%_
                       _%$%e5652657325%_
                       _%$%hd5652757329%_
                       _%$%tl5652857332%_
                       _%$%e5652957335%_
                       _%$%hd5653057339%_
                       _%$%tl5653157342%_
                       _%$%e5653257345%_
                       _%$%hd5653357349%_
                       _%$%tl5653457352%_
                       _%$%e5666256814%_
                       _%$%hd5666356818%_
                       _%$%tl5666456821%_
                       _%__splice100489100490%_
                       _%$%target5666556824%_
                       _%$%tl5666756827%_)
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                      (if (gx#stx-pair? _%$%hd5653357349%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5653357349%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (if (gx#stx-pair/null?
                                                   _%$%tl5653157342%_)
                                                  (let ((_%__splice100489100490%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl5653157342%_
                                                          '0)))
                                                    (let ((_%$%tl5666756827%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '1)))
                                                          (_%$%target5666556824%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5666756827%_)
                                                          (_%__match100821100822%_
                                                           _%$%e5652657325%_
                                                           _%$%hd5652757329%_
                                                           _%$%tl5652857332%_
                                                           _%$%e5652957335%_
                                                           _%$%hd5653057339%_
                                                           _%$%tl5653157342%_
                                                           _%$%e5653257345%_
                                                           _%$%hd5653357349%_
                                                           _%$%tl5653457352%_
                                                           _%$%e5666256814%_
                                                           _%$%hd5666356818%_
                                                           _%$%tl5666456821%_
                                                           _%__splice100489100490%_
                                                           _%$%target5666556824%_
                                                           _%$%tl5666756827%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g5645456695%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                  (if (gx#stx-pair? _%$%hd5653357349%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5653357349%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (if (gx#stx-pair/null?
                                               _%$%tl5653157342%_)
                                              (let ((_%__splice100489100490%_
                                                     (gx#syntax-split-splice->vector
                                                      _%$%tl5653157342%_
                                                      '0)))
                                                (let ((_%$%tl5666756827%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100489100490%_
                                                          '1)))
                                                      (_%$%target5666556824%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100489100490%_
                                                          '0))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5666756827%_)
                                                      (_%__match100821100822%_
                                                       _%$%e5652657325%_
                                                       _%$%hd5652757329%_
                                                       _%$%tl5652857332%_
                                                       _%$%e5652957335%_
                                                       _%$%hd5653057339%_
                                                       _%$%tl5653157342%_
                                                       _%$%e5653257345%_
                                                       _%$%hd5653357349%_
                                                       _%$%tl5653457352%_
                                                       _%$%e5666256814%_
                                                       _%$%hd5666356818%_
                                                       _%$%tl5666456821%_
                                                       _%__splice100489100490%_
                                                       _%$%target5666556824%_
                                                       _%$%tl5666756827%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g5645456695%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))))
                   (_%__match100587100588%_
                    (lambda (_%$%e5649357499%_
                             _%$%hd5649457503%_
                             _%$%tl5649557506%_
                             _%$%e5649657509%_
                             _%$%hd5649757513%_
                             _%$%tl5649857516%_
                             _%$%e5649957519%_
                             _%$%hd5650057523%_
                             _%$%tl5650157526%_
                             _%$%e5650257529%_
                             _%$%hd5650357533%_
                             _%$%tl5650457536%_
                             _%$%e5650557539%_
                             _%$%hd5650657543%_
                             _%$%tl5650757546%_
                             _%$%e5650857549%_
                             _%$%hd5650957553%_
                             _%$%tl5651057556%_
                             _%__splice100469100470%_
                             _%$%target5651157559%_
                             _%$%tl5651357562%_)
                      (letrec ((_%$%loop5651457565%_
                                (lambda (_%$%hd5651257569%_
                                         _%$%body5651857572%_)
                                  (if (gx#stx-pair? _%$%hd5651257569%_)
                                      (let ((_%$%e5651557574%_
                                             (gx#syntax-e _%$%hd5651257569%_)))
                                        (let ((_%$%lp-tl5651757581%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5651557574%_)))
                                              (_%$%lp-hd5651657578%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5651557574%_))))
                                          (_%$%loop5651457565%_
                                           _%$%lp-tl5651757581%_
                                           (cons _%$%lp-hd5651657578%_
                                                 _%$%body5651857572%_))))
                                      (let ((_%$%body5651957584%_
                                             (reverse _%$%body5651857572%_)))
                                        (let ((_%$%g5648857587%_
                                               _%$%body5651957584%_)
                                              (_%$%g5648957589%_
                                               _%$%hd5650957553%_)
                                              (_%$%g5649057590%_
                                               _%$%hd5650657543%_)
                                              (_%$%g5649157591%_
                                               _%$%hd5650357533%_)
                                              (_%$%g5649257592%_
                                               _%$%hd5650057523%_))
                                          (if (and (gx#identifier?
                                                    _%$%g5649257592%_)
                                                   (gx#identifier?
                                                    _%$%g5649057590%_)
                                                   (or (gx#free-identifier=?
                                                        _%$%g5649057590%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':))
                                                       (gx#free-identifier=?
                                                        _%$%g5649057590%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':-))
                                                       (gx#free-identifier=?
                                                        _%$%g5649057590%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         '::-))
                                                       (gx#free-identifier=?
                                                        _%$%g5649057590%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':~))
                                                       (gx#free-identifier=?
                                                        _%$%g5649057590%_
                                                        (gx#datum->syntax
                                                         '#f
                                                         ':?))))
                                              (_%__kont100467100468%_
                                               _%$%g5648857587%_
                                               _%$%g5648957589%_
                                               _%$%g5649057590%_
                                               _%$%g5649157591%_
                                               _%$%g5649257592%_)
                                              (_%__match100617100618%_
                                               _%$%e5649357499%_
                                               _%$%hd5649457503%_
                                               _%$%tl5649557506%_
                                               _%$%e5649657509%_
                                               _%$%hd5649757513%_
                                               _%$%tl5649857516%_
                                               _%$%e5649957519%_
                                               _%$%hd5650057523%_
                                               _%$%tl5650157526%_
                                               _%$%e5650257529%_
                                               _%$%hd5650357533%_
                                               _%$%tl5650457536%_
                                               _%$%e5650557539%_
                                               _%$%hd5650657543%_
                                               _%$%tl5650757546%_))))))))
                        (_%$%loop5651457565%_ _%$%target5651157559%_ '()))))
                   (_%__match100541100542%_
                    (lambda (_%$%e5646157651%_
                             _%$%hd5646257655%_
                             _%$%tl5646357658%_
                             _%$%e5646457661%_
                             _%$%hd5646557665%_
                             _%$%tl5646657668%_
                             _%$%e5646757671%_
                             _%$%hd5646857675%_
                             _%$%tl5646957678%_
                             _%$%e5647057681%_
                             _%$%hd5647157685%_
                             _%$%tl5647257688%_
                             _%$%e5647357691%_
                             _%$%hd5647457695%_
                             _%$%tl5647557698%_
                             _%$%e5647657701%_
                             _%$%hd5647757705%_
                             _%$%tl5647857708%_
                             _%__splice100465100466%_
                             _%$%target5647957711%_
                             _%$%tl5648157714%_)
                      (letrec ((_%$%loop5648257717%_
                                (lambda (_%$%hd5648057721%_
                                         _%$%body5648657724%_)
                                  (if (gx#stx-pair? _%$%hd5648057721%_)
                                      (let ((_%$%e5648357726%_
                                             (gx#syntax-e _%$%hd5648057721%_)))
                                        (let ((_%$%lp-tl5648557733%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5648357726%_)))
                                              (_%$%lp-hd5648457730%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5648357726%_))))
                                          (_%$%loop5648257717%_
                                           _%$%lp-tl5648557733%_
                                           (cons _%$%lp-hd5648457730%_
                                                 _%$%body5648657724%_))))
                                      (let ((_%$%body5648757736%_
                                             (reverse _%$%body5648657724%_)))
                                        (let ((_%$%g5645657739%_
                                               _%$%body5648757736%_)
                                              (_%$%g5645757741%_
                                               _%$%hd5647757705%_)
                                              (_%$%g5645857742%_
                                               _%$%hd5647457695%_)
                                              (_%$%g5645957743%_
                                               _%$%hd5647157685%_)
                                              (_%$%g5646057744%_
                                               _%$%hd5646857675%_))
                                          (if (and (gx#identifier?
                                                    _%$%g5645957743%_)
                                                   (gx#free-identifier=?
                                                    _%$%g5645957743%_
                                                    (gx#datum->syntax '#f ':?))
                                                   (eq? (gx#stx-e
                                                         _%$%g5645757741%_)
                                                        'unchecked:))
                                              (_%__kont100463100464%_
                                               _%$%g5645657739%_
                                               _%$%g5645757741%_
                                               _%$%g5645857742%_
                                               _%$%g5645957743%_
                                               _%$%g5646057744%_)
                                              (_%__match100587100588%_
                                               _%$%e5646157651%_
                                               _%$%hd5646257655%_
                                               _%$%tl5646357658%_
                                               _%$%e5646457661%_
                                               _%$%hd5646557665%_
                                               _%$%tl5646657668%_
                                               _%$%e5646757671%_
                                               _%$%hd5646857675%_
                                               _%$%tl5646957678%_
                                               _%$%e5647057681%_
                                               _%$%hd5647157685%_
                                               _%$%tl5647257688%_
                                               _%$%e5647357691%_
                                               _%$%hd5647457695%_
                                               _%$%tl5647557698%_
                                               _%$%e5647657701%_
                                               _%$%hd5647757705%_
                                               _%$%tl5647857708%_
                                               _%__splice100465100466%_
                                               _%$%target5647957711%_
                                               _%$%tl5648157714%_))))))))
                        (_%$%loop5648257717%_ _%$%target5647957711%_ '())))))
              (if (gx#stx-pair? _%__stx100460100461%_)
                  (let ((_%$%e5646157651%_
                         (gx#syntax-e _%__stx100460100461%_)))
                    (let ((_%$%tl5646357658%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5646157651%_)))
                          (_%$%hd5646257655%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5646157651%_))))
                      (if (gx#stx-pair? _%$%tl5646357658%_)
                          (let ((_%$%e5646457661%_
                                 (gx#syntax-e _%$%tl5646357658%_)))
                            (let ((_%$%tl5646657668%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5646457661%_)))
                                  (_%$%hd5646557665%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5646457661%_))))
                              (if (gx#stx-pair? _%$%hd5646557665%_)
                                  (let ((_%$%e5646757671%_
                                         (gx#syntax-e _%$%hd5646557665%_)))
                                    (let ((_%$%tl5646957678%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5646757671%_)))
                                          (_%$%hd5646857675%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5646757671%_))))
                                      (if (gx#stx-pair? _%$%tl5646957678%_)
                                          (let ((_%$%e5647057681%_
                                                 (gx#syntax-e
                                                  _%$%tl5646957678%_)))
                                            (let ((_%$%tl5647257688%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5647057681%_)))
                                                  (_%$%hd5647157685%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5647057681%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5647257688%_)
                                                  (let ((_%$%e5647357691%_
                                                         (gx#syntax-e
                                                          _%$%tl5647257688%_)))
                                                    (let ((_%$%tl5647557698%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5647357691%_)))
                                                          (_%$%hd5647457695%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5647357691%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl5647557698%_)
                                                          (let ((_%$%e5647657701%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl5647557698%_)))
                    (let ((_%$%tl5647857708%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5647657701%_)))
                          (_%$%hd5647757705%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5647657701%_))))
                      (if (gx#stx-null? _%$%tl5647857708%_)
                          (if (gx#stx-pair/null? _%$%tl5646657668%_)
                              (let ((_%__splice100465100466%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5646657668%_
                                      '0)))
                                (let ((_%$%tl5648157714%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100465100466%_
                                          '1)))
                                      (_%$%target5647957711%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100465100466%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5648157714%_)
                                      (_%__match100541100542%_
                                       _%$%e5646157651%_
                                       _%$%hd5646257655%_
                                       _%$%tl5646357658%_
                                       _%$%e5646457661%_
                                       _%$%hd5646557665%_
                                       _%$%tl5646657668%_
                                       _%$%e5646757671%_
                                       _%$%hd5646857675%_
                                       _%$%tl5646957678%_
                                       _%$%e5647057681%_
                                       _%$%hd5647157685%_
                                       _%$%tl5647257688%_
                                       _%$%e5647357691%_
                                       _%$%hd5647457695%_
                                       _%$%tl5647557698%_
                                       _%$%e5647657701%_
                                       _%$%hd5647757705%_
                                       _%$%tl5647857708%_
                                       _%__splice100465100466%_
                                       _%$%target5647957711%_
                                       _%$%tl5648157714%_)
                                      (if (gx#stx-pair? _%$%hd5646857675%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5646857675%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))))
                              (if (gx#stx-pair? _%$%hd5646857675%_)
                                  (let ((_%$%e5666256814%_
                                         (gx#syntax-e _%$%hd5646857675%_)))
                                    (let ((_%$%tl5666456821%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5666256814%_)))
                                          (_%$%hd5666356818%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5666256814%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                          (if (gx#identifier? _%$%hd5647457695%_)
                              (if (gx#free-identifier=?
                                   |gerbil/core/contract~Using[1]#_g107431_|
                                   _%$%hd5647457695%_)
                                  (if (gx#stx-pair? _%$%tl5647857708%_)
                                      (let ((_%$%e5654457385%_
                                             (gx#syntax-e _%$%tl5647857708%_)))
                                        (let ((_%$%tl5654657392%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5654457385%_)))
                                              (_%$%hd5654557389%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5654457385%_))))
                                          (if (gx#stx-pair? _%$%tl5654657392%_)
                                              (let ((_%$%e5654757395%_
                                                     (gx#syntax-e
                                                      _%$%tl5654657392%_)))
                                                (let ((_%$%tl5654957402%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5654757395%_)))
                                                      (_%$%hd5654857399%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5654757395%_))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5654957402%_)
                                                      (if (gx#stx-pair/null?
                                                           _%$%tl5646657668%_)
                                                          (let ((_%__splice100473100474%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice->vector
                          _%$%tl5646657668%_
                          '0)))
                    (let ((_%$%tl5655257408%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100473100474%_ '1)))
                          (_%$%target5655057405%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100473100474%_ '0))))
                      (if (gx#stx-null? _%$%tl5655257408%_)
                          (_%__match100649100650%_
                           _%$%e5646157651%_
                           _%$%hd5646257655%_
                           _%$%tl5646357658%_
                           _%$%e5646457661%_
                           _%$%hd5646557665%_
                           _%$%tl5646657668%_
                           _%$%e5646757671%_
                           _%$%hd5646857675%_
                           _%$%tl5646957678%_
                           _%$%e5647057681%_
                           _%$%hd5647157685%_
                           _%$%tl5647257688%_
                           _%$%e5647357691%_
                           _%$%hd5647457695%_
                           _%$%tl5647557698%_
                           _%$%e5647657701%_
                           _%$%hd5647757705%_
                           _%$%tl5647857708%_
                           _%$%e5654457385%_
                           _%$%hd5654557389%_
                           _%$%tl5654657392%_
                           _%$%e5654757395%_
                           _%$%hd5654857399%_
                           _%$%tl5654957402%_
                           _%__splice100473100474%_
                           _%$%target5655057405%_
                           _%$%tl5655257408%_)
                          (if (gx#stx-pair? _%$%hd5646857675%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5646857675%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))))
                  (if (gx#stx-pair? _%$%hd5646857675%_)
                      (let ((_%$%e5666256814%_
                             (gx#syntax-e _%$%hd5646857675%_)))
                        (let ((_%$%tl5666456821%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5666256814%_)))
                              (_%$%hd5666356818%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5666256814%_))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))
              (if (gx#stx-pair? _%$%hd5646857675%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5646857675%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (if (gx#stx-pair/null? _%$%tl5646657668%_)
                          (let ((_%__splice100489100490%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5646657668%_
                                  '0)))
                            (let ((_%$%tl5666756827%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '1)))
                                  (_%$%target5666556824%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5666756827%_)
                                  (_%__match100821100822%_
                                   _%$%e5646157651%_
                                   _%$%hd5646257655%_
                                   _%$%tl5646357658%_
                                   _%$%e5646457661%_
                                   _%$%hd5646557665%_
                                   _%$%tl5646657668%_
                                   _%$%e5646757671%_
                                   _%$%hd5646857675%_
                                   _%$%tl5646957678%_
                                   _%$%e5666256814%_
                                   _%$%hd5666356818%_
                                   _%$%tl5666456821%_
                                   _%__splice100489100490%_
                                   _%$%target5666556824%_
                                   _%$%tl5666756827%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#identifier?
                                                   _%$%hd5647157685%_)
                                                  (if (gx#free-identifier=?
                                                       |gerbil/core/contract~Using[1]#_g107430_|
                                                       _%$%hd5647157685%_)
                                                      (if (gx#stx-null?
                                                           _%$%tl5654657392%_)
                                                          (if (gx#stx-pair/null?
                                                               _%$%tl5646657668%_)
                                                              (let ((_%__splice100485100486%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#syntax-split-splice->vector
                              _%$%tl5646657668%_
                              '0)))
                        (let ((_%$%tl5664256967%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100485100486%_ '1)))
                              (_%$%target5664056964%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100485100486%_ '0))))
                          (if (gx#stx-null? _%$%tl5664256967%_)
                              (_%__match100789100790%_
                               _%$%e5646157651%_
                               _%$%hd5646257655%_
                               _%$%tl5646357658%_
                               _%$%e5646457661%_
                               _%$%hd5646557665%_
                               _%$%tl5646657668%_
                               _%$%e5646757671%_
                               _%$%hd5646857675%_
                               _%$%tl5646957678%_
                               _%$%e5647057681%_
                               _%$%hd5647157685%_
                               _%$%tl5647257688%_
                               _%$%e5647357691%_
                               _%$%hd5647457695%_
                               _%$%tl5647557698%_
                               _%$%e5647657701%_
                               _%$%hd5647757705%_
                               _%$%tl5647857708%_
                               _%$%e5654457385%_
                               _%$%hd5654557389%_
                               _%$%tl5654657392%_
                               _%__splice100485100486%_
                               _%$%target5664056964%_
                               _%$%tl5664256967%_)
                              (if (gx#stx-pair? _%$%hd5646857675%_)
                                  (let ((_%$%e5666256814%_
                                         (gx#syntax-e _%$%hd5646857675%_)))
                                    (let ((_%$%tl5666456821%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5666256814%_)))
                                          (_%$%hd5666356818%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5666256814%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))))
                      (if (gx#stx-pair? _%$%hd5646857675%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5646857675%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))
                  (if (gx#stx-pair? _%$%hd5646857675%_)
                      (let ((_%$%e5666256814%_
                             (gx#syntax-e _%$%hd5646857675%_)))
                        (let ((_%$%tl5666456821%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5666256814%_)))
                              (_%$%hd5666356818%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5666256814%_))))
                          (if (gx#stx-pair/null? _%$%tl5646657668%_)
                              (let ((_%__splice100489100490%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5646657668%_
                                      '0)))
                                (let ((_%$%tl5666756827%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '1)))
                                      (_%$%target5666556824%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100489100490%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5666756827%_)
                                      (_%__match100821100822%_
                                       _%$%e5646157651%_
                                       _%$%hd5646257655%_
                                       _%$%tl5646357658%_
                                       _%$%e5646457661%_
                                       _%$%hd5646557665%_
                                       _%$%tl5646657668%_
                                       _%$%e5646757671%_
                                       _%$%hd5646857675%_
                                       _%$%tl5646957678%_
                                       _%$%e5666256814%_
                                       _%$%hd5666356818%_
                                       _%$%tl5666456821%_
                                       _%__splice100489100490%_
                                       _%$%target5666556824%_
                                       _%$%tl5666756827%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))
              (if (gx#stx-pair? _%$%hd5646857675%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5646857675%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (if (gx#stx-pair/null? _%$%tl5646657668%_)
                          (let ((_%__splice100489100490%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5646657668%_
                                  '0)))
                            (let ((_%$%tl5666756827%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '1)))
                                  (_%$%target5666556824%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5666756827%_)
                                  (_%__match100821100822%_
                                   _%$%e5646157651%_
                                   _%$%hd5646257655%_
                                   _%$%tl5646357658%_
                                   _%$%e5646457661%_
                                   _%$%hd5646557665%_
                                   _%$%tl5646657668%_
                                   _%$%e5646757671%_
                                   _%$%hd5646857675%_
                                   _%$%tl5646957678%_
                                   _%$%e5666256814%_
                                   _%$%hd5666356818%_
                                   _%$%tl5666456821%_
                                   _%__splice100489100490%_
                                   _%$%target5666556824%_
                                   _%$%tl5666756827%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair?
                                                       _%$%hd5646857675%_)
                                                      (let ((_%$%e5666256814%_
                                                             (gx#syntax-e
                                                              _%$%hd5646857675%_)))
                                                        (let ((_%$%tl5666456821%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5666256814%_)))
                      (_%$%hd5666356818%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5666256814%_))))
                  (if (gx#stx-pair/null? _%$%tl5646657668%_)
                      (let ((_%__splice100489100490%_
                             (gx#syntax-split-splice->vector
                              _%$%tl5646657668%_
                              '0)))
                        (let ((_%$%tl5666756827%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '1)))
                              (_%$%target5666556824%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '0))))
                          (if (gx#stx-null? _%$%tl5666756827%_)
                              (_%__match100821100822%_
                               _%$%e5646157651%_
                               _%$%hd5646257655%_
                               _%$%tl5646357658%_
                               _%$%e5646457661%_
                               _%$%hd5646557665%_
                               _%$%tl5646657668%_
                               _%$%e5646757671%_
                               _%$%hd5646857675%_
                               _%$%tl5646957678%_
                               _%$%e5666256814%_
                               _%$%hd5666356818%_
                               _%$%tl5666456821%_
                               _%__splice100489100490%_
                               _%$%target5666556824%_
                               _%$%tl5666756827%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (if (gx#stx-pair? _%$%hd5646857675%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5646857675%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (if (gx#stx-pair/null?
                                                   _%$%tl5646657668%_)
                                                  (let ((_%__splice100489100490%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl5646657668%_
                                                          '0)))
                                                    (let ((_%$%tl5666756827%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '1)))
                                                          (_%$%target5666556824%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5666756827%_)
                                                          (_%__match100821100822%_
                                                           _%$%e5646157651%_
                                                           _%$%hd5646257655%_
                                                           _%$%tl5646357658%_
                                                           _%$%e5646457661%_
                                                           _%$%hd5646557665%_
                                                           _%$%tl5646657668%_
                                                           _%$%e5646757671%_
                                                           _%$%hd5646857675%_
                                                           _%$%tl5646957678%_
                                                           _%$%e5666256814%_
                                                           _%$%hd5666356818%_
                                                           _%$%tl5666456821%_
                                                           _%__splice100489100490%_
                                                           _%$%target5666556824%_
                                                           _%$%tl5666756827%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g5645456695%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                  (if (gx#identifier? _%$%hd5647157685%_)
                                      (if (gx#free-identifier=?
                                           |gerbil/core/contract~Using[1]#_g107430_|
                                           _%$%hd5647157685%_)
                                          (if (gx#stx-pair? _%$%tl5647857708%_)
                                              (let ((_%$%e5663756954%_
                                                     (gx#syntax-e
                                                      _%$%tl5647857708%_)))
                                                (let ((_%$%tl5663956961%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5663756954%_)))
                                                      (_%$%hd5663856958%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5663756954%_))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5663956961%_)
                                                      (if (gx#stx-pair/null?
                                                           _%$%tl5646657668%_)
                                                          (let ((_%__splice100485100486%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice->vector
                          _%$%tl5646657668%_
                          '0)))
                    (let ((_%$%tl5664256967%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100485100486%_ '1)))
                          (_%$%target5664056964%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100485100486%_ '0))))
                      (if (gx#stx-null? _%$%tl5664256967%_)
                          (_%__match100789100790%_
                           _%$%e5646157651%_
                           _%$%hd5646257655%_
                           _%$%tl5646357658%_
                           _%$%e5646457661%_
                           _%$%hd5646557665%_
                           _%$%tl5646657668%_
                           _%$%e5646757671%_
                           _%$%hd5646857675%_
                           _%$%tl5646957678%_
                           _%$%e5647057681%_
                           _%$%hd5647157685%_
                           _%$%tl5647257688%_
                           _%$%e5647357691%_
                           _%$%hd5647457695%_
                           _%$%tl5647557698%_
                           _%$%e5647657701%_
                           _%$%hd5647757705%_
                           _%$%tl5647857708%_
                           _%$%e5663756954%_
                           _%$%hd5663856958%_
                           _%$%tl5663956961%_
                           _%__splice100485100486%_
                           _%$%target5664056964%_
                           _%$%tl5664256967%_)
                          (if (gx#stx-pair? _%$%hd5646857675%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5646857675%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))))
                  (if (gx#stx-pair? _%$%hd5646857675%_)
                      (let ((_%$%e5666256814%_
                             (gx#syntax-e _%$%hd5646857675%_)))
                        (let ((_%$%tl5666456821%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5666256814%_)))
                              (_%$%hd5666356818%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5666256814%_))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))
              (if (gx#stx-pair? _%$%hd5646857675%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5646857675%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (if (gx#stx-pair/null? _%$%tl5646657668%_)
                          (let ((_%__splice100489100490%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5646657668%_
                                  '0)))
                            (let ((_%$%tl5666756827%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '1)))
                                  (_%$%target5666556824%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100489100490%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5666756827%_)
                                  (_%__match100821100822%_
                                   _%$%e5646157651%_
                                   _%$%hd5646257655%_
                                   _%$%tl5646357658%_
                                   _%$%e5646457661%_
                                   _%$%hd5646557665%_
                                   _%$%tl5646657668%_
                                   _%$%e5646757671%_
                                   _%$%hd5646857675%_
                                   _%$%tl5646957678%_
                                   _%$%e5666256814%_
                                   _%$%hd5666356818%_
                                   _%$%tl5666456821%_
                                   _%__splice100489100490%_
                                   _%$%target5666556824%_
                                   _%$%tl5666756827%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#stx-pair?
                                                   _%$%hd5646857675%_)
                                                  (let ((_%$%e5666256814%_
                                                         (gx#syntax-e
                                                          _%$%hd5646857675%_)))
                                                    (let ((_%$%tl5666456821%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5666256814%_)))
                                                          (_%$%hd5666356818%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5666256814%_))))
                                                      (if (gx#stx-pair/null?
                                                           _%$%tl5646657668%_)
                                                          (let ((_%__splice100489100490%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice->vector
                          _%$%tl5646657668%_
                          '0)))
                    (let ((_%$%tl5666756827%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100489100490%_ '1)))
                          (_%$%target5666556824%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100489100490%_ '0))))
                      (if (gx#stx-null? _%$%tl5666756827%_)
                          (_%__match100821100822%_
                           _%$%e5646157651%_
                           _%$%hd5646257655%_
                           _%$%tl5646357658%_
                           _%$%e5646457661%_
                           _%$%hd5646557665%_
                           _%$%tl5646657668%_
                           _%$%e5646757671%_
                           _%$%hd5646857675%_
                           _%$%tl5646957678%_
                           _%$%e5666256814%_
                           _%$%hd5666356818%_
                           _%$%tl5666456821%_
                           _%__splice100489100490%_
                           _%$%target5666556824%_
                           _%$%tl5666756827%_)
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_))))
                                          (if (gx#stx-pair? _%$%hd5646857675%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5646857675%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5646657668%_)
                                                      (let ((_%__splice100489100490%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5646657668%_
                                                              '0)))
                                                        (let ((_%$%tl5666756827%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '1)))
                      (_%$%target5666556824%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '0))))
                  (if (gx#stx-null? _%$%tl5666756827%_)
                      (_%__match100821100822%_
                       _%$%e5646157651%_
                       _%$%hd5646257655%_
                       _%$%tl5646357658%_
                       _%$%e5646457661%_
                       _%$%hd5646557665%_
                       _%$%tl5646657668%_
                       _%$%e5646757671%_
                       _%$%hd5646857675%_
                       _%$%tl5646957678%_
                       _%$%e5666256814%_
                       _%$%hd5666356818%_
                       _%$%tl5666456821%_
                       _%__splice100489100490%_
                       _%$%target5666556824%_
                       _%$%tl5666756827%_)
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                      (if (gx#stx-pair? _%$%hd5646857675%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5646857675%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (if (gx#stx-pair/null?
                                                   _%$%tl5646657668%_)
                                                  (let ((_%__splice100489100490%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl5646657668%_
                                                          '0)))
                                                    (let ((_%$%tl5666756827%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '1)))
                                                          (_%$%target5666556824%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5666756827%_)
                                                          (_%__match100821100822%_
                                                           _%$%e5646157651%_
                                                           _%$%hd5646257655%_
                                                           _%$%tl5646357658%_
                                                           _%$%e5646457661%_
                                                           _%$%hd5646557665%_
                                                           _%$%tl5646657668%_
                                                           _%$%e5646757671%_
                                                           _%$%hd5646857675%_
                                                           _%$%tl5646957678%_
                                                           _%$%e5666256814%_
                                                           _%$%hd5666356818%_
                                                           _%$%tl5666456821%_
                                                           _%__splice100489100490%_
                                                           _%$%target5666556824%_
                                                           _%$%tl5666756827%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g5645456695%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                              (if (gx#identifier? _%$%hd5647157685%_)
                                  (if (gx#free-identifier=?
                                       |gerbil/core/contract~Using[1]#_g107430_|
                                       _%$%hd5647157685%_)
                                      (if (gx#stx-pair? _%$%tl5647857708%_)
                                          (let ((_%$%e5663756954%_
                                                 (gx#syntax-e
                                                  _%$%tl5647857708%_)))
                                            (let ((_%$%tl5663956961%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5663756954%_)))
                                                  (_%$%hd5663856958%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5663756954%_))))
                                              (if (gx#stx-null?
                                                   _%$%tl5663956961%_)
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5646657668%_)
                                                      (let ((_%__splice100485100486%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5646657668%_
                                                              '0)))
                                                        (let ((_%$%tl5664256967%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100485100486%_ '1)))
                      (_%$%target5664056964%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100485100486%_ '0))))
                  (if (gx#stx-null? _%$%tl5664256967%_)
                      (_%__match100789100790%_
                       _%$%e5646157651%_
                       _%$%hd5646257655%_
                       _%$%tl5646357658%_
                       _%$%e5646457661%_
                       _%$%hd5646557665%_
                       _%$%tl5646657668%_
                       _%$%e5646757671%_
                       _%$%hd5646857675%_
                       _%$%tl5646957678%_
                       _%$%e5647057681%_
                       _%$%hd5647157685%_
                       _%$%tl5647257688%_
                       _%$%e5647357691%_
                       _%$%hd5647457695%_
                       _%$%tl5647557698%_
                       _%$%e5647657701%_
                       _%$%hd5647757705%_
                       _%$%tl5647857708%_
                       _%$%e5663756954%_
                       _%$%hd5663856958%_
                       _%$%tl5663956961%_
                       _%__splice100485100486%_
                       _%$%target5664056964%_
                       _%$%tl5664256967%_)
                      (if (gx#stx-pair? _%$%hd5646857675%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5646857675%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                          (let () (declare (not safe)) (_%$%g5645456695%_))))))
              (if (gx#stx-pair? _%$%hd5646857675%_)
                  (let ((_%$%e5666256814%_ (gx#syntax-e _%$%hd5646857675%_)))
                    (let ((_%$%tl5666456821%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5666256814%_)))
                          (_%$%hd5666356818%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5666256814%_))))
                      (let () (declare (not safe)) (_%$%g5645456695%_))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair?
                                                       _%$%hd5646857675%_)
                                                      (let ((_%$%e5666256814%_
                                                             (gx#syntax-e
                                                              _%$%hd5646857675%_)))
                                                        (let ((_%$%tl5666456821%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5666256814%_)))
                      (_%$%hd5666356818%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5666256814%_))))
                  (if (gx#stx-pair/null? _%$%tl5646657668%_)
                      (let ((_%__splice100489100490%_
                             (gx#syntax-split-splice->vector
                              _%$%tl5646657668%_
                              '0)))
                        (let ((_%$%tl5666756827%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '1)))
                              (_%$%target5666556824%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '0))))
                          (if (gx#stx-null? _%$%tl5666756827%_)
                              (_%__match100821100822%_
                               _%$%e5646157651%_
                               _%$%hd5646257655%_
                               _%$%tl5646357658%_
                               _%$%e5646457661%_
                               _%$%hd5646557665%_
                               _%$%tl5646657668%_
                               _%$%e5646757671%_
                               _%$%hd5646857675%_
                               _%$%tl5646957678%_
                               _%$%e5666256814%_
                               _%$%hd5666356818%_
                               _%$%tl5666456821%_
                               _%__splice100489100490%_
                               _%$%target5666556824%_
                               _%$%tl5666756827%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair? _%$%hd5646857675%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5646857675%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5646657668%_)
                                                      (let ((_%__splice100489100490%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5646657668%_
                                                              '0)))
                                                        (let ((_%$%tl5666756827%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '1)))
                      (_%$%target5666556824%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '0))))
                  (if (gx#stx-null? _%$%tl5666756827%_)
                      (_%__match100821100822%_
                       _%$%e5646157651%_
                       _%$%hd5646257655%_
                       _%$%tl5646357658%_
                       _%$%e5646457661%_
                       _%$%hd5646557665%_
                       _%$%tl5646657668%_
                       _%$%e5646757671%_
                       _%$%hd5646857675%_
                       _%$%tl5646957678%_
                       _%$%e5666256814%_
                       _%$%hd5666356818%_
                       _%$%tl5666456821%_
                       _%__splice100489100490%_
                       _%$%target5666556824%_
                       _%$%tl5666756827%_)
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))
                                      (if (gx#stx-pair? _%$%hd5646857675%_)
                                          (let ((_%$%e5666256814%_
                                                 (gx#syntax-e
                                                  _%$%hd5646857675%_)))
                                            (let ((_%$%tl5666456821%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5666256814%_)))
                                                  (_%$%hd5666356818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5666256814%_))))
                                              (if (gx#stx-pair/null?
                                                   _%$%tl5646657668%_)
                                                  (let ((_%__splice100489100490%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl5646657668%_
                                                          '0)))
                                                    (let ((_%$%tl5666756827%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '1)))
                                                          (_%$%target5666556824%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice100489100490%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl5666756827%_)
                                                          (_%__match100821100822%_
                                                           _%$%e5646157651%_
                                                           _%$%hd5646257655%_
                                                           _%$%tl5646357658%_
                                                           _%$%e5646457661%_
                                                           _%$%hd5646557665%_
                                                           _%$%tl5646657668%_
                                                           _%$%e5646757671%_
                                                           _%$%hd5646857675%_
                                                           _%$%tl5646957678%_
                                                           _%$%e5666256814%_
                                                           _%$%hd5666356818%_
                                                           _%$%tl5666456821%_
                                                           _%__splice100489100490%_
                                                           _%$%target5666556824%_
                                                           _%$%tl5666756827%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g5645456695%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                  (if (gx#stx-pair? _%$%hd5646857675%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5646857675%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (if (gx#stx-pair/null?
                                               _%$%tl5646657668%_)
                                              (let ((_%__splice100489100490%_
                                                     (gx#syntax-split-splice->vector
                                                      _%$%tl5646657668%_
                                                      '0)))
                                                (let ((_%$%tl5666756827%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100489100490%_
                                                          '1)))
                                                      (_%$%target5666556824%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100489100490%_
                                                          '0))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5666756827%_)
                                                      (_%__match100821100822%_
                                                       _%$%e5646157651%_
                                                       _%$%hd5646257655%_
                                                       _%$%tl5646357658%_
                                                       _%$%e5646457661%_
                                                       _%$%hd5646557665%_
                                                       _%$%tl5646657668%_
                                                       _%$%e5646757671%_
                                                       _%$%hd5646857675%_
                                                       _%$%tl5646957678%_
                                                       _%$%e5666256814%_
                                                       _%$%hd5666356818%_
                                                       _%$%tl5666456821%_
                                                       _%__splice100489100490%_
                                                       _%$%target5666556824%_
                                                       _%$%tl5666756827%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g5645456695%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))))
                  (if (gx#stx-null? _%$%tl5647557698%_)
                      (if (gx#stx-pair/null? _%$%tl5646657668%_)
                          (let ((_%__splice100477100478%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5646657668%_
                                  '0)))
                            (let ((_%$%tl5658057227%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100477100478%_
                                      '1)))
                                  (_%$%target5657857224%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100477100478%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5658057227%_)
                                  (_%__match100689100690%_
                                   _%$%e5646157651%_
                                   _%$%hd5646257655%_
                                   _%$%tl5646357658%_
                                   _%$%e5646457661%_
                                   _%$%hd5646557665%_
                                   _%$%tl5646657668%_
                                   _%$%e5646757671%_
                                   _%$%hd5646857675%_
                                   _%$%tl5646957678%_
                                   _%$%e5647057681%_
                                   _%$%hd5647157685%_
                                   _%$%tl5647257688%_
                                   _%$%e5647357691%_
                                   _%$%hd5647457695%_
                                   _%$%tl5647557698%_
                                   _%__splice100477100478%_
                                   _%$%target5657857224%_
                                   _%$%tl5658057227%_)
                                  (if (gx#stx-pair? _%$%hd5646857675%_)
                                      (let ((_%$%e5666256814%_
                                             (gx#syntax-e _%$%hd5646857675%_)))
                                        (let ((_%$%tl5666456821%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5666256814%_)))
                                              (_%$%hd5666356818%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5666256814%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))
                          (if (gx#stx-pair? _%$%hd5646857675%_)
                              (let ((_%$%e5666256814%_
                                     (gx#syntax-e _%$%hd5646857675%_)))
                                (let ((_%$%tl5666456821%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5666256814%_)))
                                      (_%$%hd5666356818%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5666256814%_))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_))))
                      (if (gx#stx-pair? _%$%hd5646857675%_)
                          (let ((_%$%e5666256814%_
                                 (gx#syntax-e _%$%hd5646857675%_)))
                            (let ((_%$%tl5666456821%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5666256814%_)))
                                  (_%$%hd5666356818%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5666256814%_))))
                              (if (gx#stx-pair/null? _%$%tl5646657668%_)
                                  (let ((_%__splice100489100490%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5646657668%_
                                          '0)))
                                    (let ((_%$%tl5666756827%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '1)))
                                          (_%$%target5666556824%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100489100490%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5666756827%_)
                                          (_%__match100821100822%_
                                           _%$%e5646157651%_
                                           _%$%hd5646257655%_
                                           _%$%tl5646357658%_
                                           _%$%e5646457661%_
                                           _%$%hd5646557665%_
                                           _%$%tl5646657668%_
                                           _%$%e5646757671%_
                                           _%$%hd5646857675%_
                                           _%$%tl5646957678%_
                                           _%$%e5666256814%_
                                           _%$%hd5666356818%_
                                           _%$%tl5666456821%_
                                           _%__splice100489100490%_
                                           _%$%target5666556824%_
                                           _%$%tl5666756827%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5645456695%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g5645456695%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair?
                                                       _%$%hd5646857675%_)
                                                      (let ((_%$%e5666256814%_
                                                             (gx#syntax-e
                                                              _%$%hd5646857675%_)))
                                                        (let ((_%$%tl5666456821%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5666256814%_)))
                      (_%$%hd5666356818%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5666256814%_))))
                  (if (gx#stx-pair/null? _%$%tl5646657668%_)
                      (let ((_%__splice100489100490%_
                             (gx#syntax-split-splice->vector
                              _%$%tl5646657668%_
                              '0)))
                        (let ((_%$%tl5666756827%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '1)))
                              (_%$%target5666556824%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100489100490%_ '0))))
                          (if (gx#stx-null? _%$%tl5666756827%_)
                              (_%__match100821100822%_
                               _%$%e5646157651%_
                               _%$%hd5646257655%_
                               _%$%tl5646357658%_
                               _%$%e5646457661%_
                               _%$%hd5646557665%_
                               _%$%tl5646657668%_
                               _%$%e5646757671%_
                               _%$%hd5646857675%_
                               _%$%tl5646957678%_
                               _%$%e5666256814%_
                               _%$%hd5666356818%_
                               _%$%tl5666456821%_
                               _%__splice100489100490%_
                               _%$%target5666556824%_
                               _%$%tl5666756827%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g5645456695%_)))))
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair? _%$%hd5646857675%_)
                                              (let ((_%$%e5666256814%_
                                                     (gx#syntax-e
                                                      _%$%hd5646857675%_)))
                                                (let ((_%$%tl5666456821%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5666256814%_)))
                                                      (_%$%hd5666356818%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5666256814%_))))
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5646657668%_)
                                                      (let ((_%__splice100489100490%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5646657668%_
                                                              '0)))
                                                        (let ((_%$%tl5666756827%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '1)))
                      (_%$%target5666556824%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100489100490%_ '0))))
                  (if (gx#stx-null? _%$%tl5666756827%_)
                      (_%__match100821100822%_
                       _%$%e5646157651%_
                       _%$%hd5646257655%_
                       _%$%tl5646357658%_
                       _%$%e5646457661%_
                       _%$%hd5646557665%_
                       _%$%tl5646657668%_
                       _%$%e5646757671%_
                       _%$%hd5646857675%_
                       _%$%tl5646957678%_
                       _%$%e5666256814%_
                       _%$%hd5666356818%_
                       _%$%tl5666456821%_
                       _%__splice100489100490%_
                       _%$%target5666556824%_
                       _%$%tl5666756827%_)
                      (let () (declare (not safe)) (_%$%g5645456695%_)))))
              (let () (declare (not safe)) (_%$%g5645456695%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5645456695%_))))))
                                  (if (gx#stx-null? _%$%hd5646557665%_)
                                      (if (gx#stx-pair/null?
                                           _%$%tl5646657668%_)
                                          (let ((_%__splice100493100494%_
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl5646657668%_
                                                  '0)))
                                            (let ((_%$%tl5668356725%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100493100494%_
                                                      '1)))
                                                  (_%$%target5668156722%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100493100494%_
                                                      '0))))
                                              (if (gx#stx-null?
                                                   _%$%tl5668356725%_)
                                                  (_%__match100843100844%_
                                                   _%$%e5646157651%_
                                                   _%$%hd5646257655%_
                                                   _%$%tl5646357658%_
                                                   _%$%e5646457661%_
                                                   _%$%hd5646557665%_
                                                   _%$%tl5646657668%_
                                                   _%__splice100493100494%_
                                                   _%$%target5668156722%_
                                                   _%$%tl5668356725%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5645456695%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5645456695%_)))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5645456695%_))))))
                          (let () (declare (not safe)) (_%$%g5645456695%_)))))
                  (let () (declare (not safe)) (_%$%g5645456695%_))))))))
    (define |gerbil/core/contract~Using[:0:]#with-contract|
      (lambda (_%$stx57800%_)
        (let* ((_%$%g5780457838%_
                (lambda (_%$%g5780557834%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5780557834%_)))
               (_%$%g5780357959%_
                (lambda (_%$%g5780557842%_)
                  (if (gx#stx-pair? _%$%g5780557842%_)
                      (let ((_%$%e5780957845%_
                             (gx#syntax-e _%$%g5780557842%_)))
                        (let ((_%$%hd5781057849%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5780957845%_)))
                              (_%$%tl5781157852%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5780957845%_))))
                          (if (gx#stx-pair? _%$%tl5781157852%_)
                              (let ((_%$%e5781257855%_
                                     (gx#syntax-e _%$%tl5781157852%_)))
                                (let ((_%$%hd5781357859%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5781257855%_)))
                                      (_%$%tl5781457862%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5781257855%_))))
                                  (if (gx#stx-pair? _%$%hd5781357859%_)
                                      (let ((_%$%e5781557865%_
                                             (gx#syntax-e _%$%hd5781357859%_)))
                                        (let ((_%$%hd5781657869%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5781557865%_)))
                                              (_%$%tl5781757872%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5781557865%_))))
                                          (if (gx#stx-pair? _%$%tl5781757872%_)
                                              (let ((_%$%e5781857875%_
                                                     (gx#syntax-e
                                                      _%$%tl5781757872%_)))
                                                (let ((_%$%hd5781957879%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5781857875%_)))
                                                      (_%$%tl5782057882%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5781857875%_))))
                                                  (if (gx#identifier?
                                                       _%$%hd5781957879%_)
                                                      (if (gx#free-identifier=?
                                                           |gerbil/core/contract~Using[1]#_g107432_|
                                                           _%$%hd5781957879%_)
                                                          (if (gx#stx-pair?
                                                               _%$%tl5782057882%_)
                                                              (let ((_%$%e5782157885%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#syntax-e _%$%tl5782057882%_)))
                        (let ((_%$%hd5782257889%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5782157885%_)))
                              (_%$%tl5782357892%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5782157885%_))))
                          (if (gx#stx-null? _%$%tl5782357892%_)
                              (if (gx#stx-pair/null? _%$%tl5781457862%_)
                                  (let ((_g107433_
                                         (gx#syntax-split-splice
                                          _%$%tl5781457862%_
                                          '0)))
                                    (begin
                                      (let ((_g107434_
                                             (let ()
                                               (declare (not safe))
                                               (if (##values? _g107433_)
                                                   (##values-length _g107433_)
                                                   1))))
                                        (if (not (let ()
                                                   (declare (not safe))
                                                   (##fx= _g107434_ 2)))
                                            (error "Context expects 2 values"
                                                   _g107434_)))
                                      (let ((_%$%target5782457895%_
                                             (let ()
                                               (declare (not safe))
                                               (##values-ref _g107433_ 0)))
                                            (_%$%tl5782657898%_
                                             (let ()
                                               (declare (not safe))
                                               (##values-ref _g107433_ 1))))
                                        (if (gx#stx-null? _%$%tl5782657898%_)
                                            (letrec ((_%$%loop5782757901%_
                                                      (lambda (_%$%hd5782557905%_
                                                               _%$%body5783157908%_)
                                                        (if (gx#stx-pair?
                                                             _%$%hd5782557905%_)
                                                            (let ((_%$%e5782857910%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-e _%$%hd5782557905%_)))
                      (let ((_%$%lp-hd5782957914%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5782857910%_)))
                            (_%$%lp-tl5783057917%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5782857910%_))))
                        (_%$%loop5782757901%_
                         _%$%lp-tl5783057917%_
                         (cons _%$%lp-hd5782957914%_ _%$%body5783157908%_))))
                    (let ((_%$%body5783257920%_
                           (reverse _%$%body5783157908%_)))
                      (if (gx#identifier? _%$%hd5781657869%_)
                          (cons (gx#datum->syntax '#f 'if)
                                (cons (cons _%$%hd5782257889%_
                                            (cons _%$%hd5781657869%_ '()))
                                      (cons (cons (gx#datum->syntax '#f 'let)
                                                  (cons '()
                                                        (foldr (lambda (_%$%g5795057953%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                _%$%g5795157956%_)
                         (cons _%$%g5795057953%_ _%$%g5795157956%_))
                       '()
                       _%$%body5783257920%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'contract-violation!)
                                                        (cons _%$%hd5781657869%_
                                                              (cons _%$%hd5782257889%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%$%hd5781657869%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '()))))
                          (_%$%g5780457838%_ _%$%g5780557842%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%loop5782757901%_
                                               _%$%target5782457895%_
                                               '()))
                                            (_%$%g5780457838%_
                                             _%$%g5780557842%_)))))
                                  (_%$%g5780457838%_ _%$%g5780557842%_))
                              (_%$%g5780457838%_ _%$%g5780557842%_))))
                      (_%$%g5780457838%_ _%$%g5780557842%_))
                  (_%$%g5780457838%_ _%$%g5780557842%_))
              (_%$%g5780457838%_ _%$%g5780557842%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g5780457838%_
                                               _%$%g5780557842%_))))
                                      (_%$%g5780457838%_ _%$%g5780557842%_))))
                              (_%$%g5780457838%_ _%$%g5780557842%_))))
                      (_%$%g5780457838%_ _%$%g5780557842%_)))))
          (_%$%g5780357959%_ _%$stx57800%_))))
    (define |gerbil/core/contract~Using[1]#!class-slot-type|
      (lambda (_%klass58851%_ _%slot58853%_)
        (let ((_%$e58855%_
               (let ((__obj107212 _%klass58851%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-direct-instance-of?
                        __obj107212
                        'gerbil/core#class-type-info::t))
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref __obj107212 '20 '#f '#f))
                     (class-slot-ref
                      gerbil/core/mop~MOP-2#class-type-info::t
                      __obj107212
                      'slot-types)))))
          (if _%$e58855%_ (agetq _%slot58853%_ _%$e58855%_) '#f))))
    (define |gerbil/core/contract~Using[1]#!class-slot-default|
      (lambda (_%klass58832%_ _%slot58834%_)
        (let ((_%$e58836%_
               (let ((__obj107213 _%klass58832%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-direct-instance-of?
                        __obj107213
                        'gerbil/core#class-type-info::t))
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref __obj107213 '21 '#f '#f))
                     (class-slot-ref
                      gerbil/core/mop~MOP-2#class-type-info::t
                      __obj107213
                      'slot-defaults)))))
          (if _%$e58836%_
              (let ((_%$e58843%_ (agetq _%slot58834%_ _%$e58836%_)))
                (if _%$e58843%_ (gx#syntax-local-introduce _%$e58843%_) '#f))
              '#f))))
    (define |gerbil/core/contract~Using[1]#!class-slot-contract|
      (lambda (_%klass58813%_ _%slot58815%_)
        (let ((_%$e58817%_
               (let ((__obj107214 _%klass58813%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-direct-instance-of?
                        __obj107214
                        'gerbil/core#class-type-info::t))
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref __obj107214 '22 '#f '#f))
                     (class-slot-ref
                      gerbil/core/mop~MOP-2#class-type-info::t
                      __obj107214
                      'slot-contracts)))))
          (if _%$e58817%_
              (let ((_%$e58824%_ (agetq _%slot58815%_ _%$e58817%_)))
                (if _%$e58824%_ (gx#syntax-local-introduce _%$e58824%_) '#f))
              '#f))))
    (define |gerbil/core/contract~Using[1]#!class-slot-checked-method-contract?|
      (lambda (_%klass58582%_ _%slot58584%_)
        (let ((_%$%contract5858558587%_
               (|gerbil/core/contract~Using[1]#!class-slot-contract|
                _%klass58582%_
                _%slot58584%_)))
          (if _%$%contract5858558587%_
              (let* ((_%contract58590%_ _%$%contract5858558587%_)
                     (_%__stx100846100847%_ _%contract58590%_)
                     (_%$%g5859558632%_
                      (lambda ()
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; invalid match target"
                         _%__stx100846100847%_))))
                (let ((_%__kont100849100850%_
                       (lambda (_%$%g5859758782%_ _%$%g5859858784%_)
                         (not (gx#free-identifier=?
                               _%$%g5859858784%_
                               (gx#datum->syntax '#f ':-)))))
                      (_%__kont100851100852%_
                       (lambda (_%$%g5860558722%_
                                _%$%g5860658724%_
                                _%$%g5860758725%_)
                         (not (gx#free-identifier=?
                               _%$%g5860658724%_
                               (gx#datum->syntax '#f ':-)))))
                      (_%__kont100853100854%_
                       (lambda (_%$%g5862058659%_) '#f)))
                  (let* ((_%__match100899100900%_
                          (lambda (_%$%e5860858682%_
                                   _%$%hd5860958686%_
                                   _%$%tl5861058689%_
                                   _%$%e5861158692%_
                                   _%$%hd5861258696%_
                                   _%$%tl5861358699%_
                                   _%$%e5861458702%_
                                   _%$%hd5861558706%_
                                   _%$%tl5861658709%_
                                   _%$%e5861758712%_
                                   _%$%hd5861858716%_
                                   _%$%tl5861958719%_)
                            (let ((_%$%g5860558722%_ _%$%hd5861858716%_)
                                  (_%$%g5860658724%_ _%$%hd5861558706%_)
                                  (_%$%g5860758725%_ _%$%hd5861258696%_))
                              (if (and (gx#identifier? _%$%g5860658724%_)
                                       (or (gx#free-identifier=?
                                            _%$%g5860658724%_
                                            (gx#datum->syntax '#f ':))
                                           (gx#free-identifier=?
                                            _%$%g5860658724%_
                                            (gx#datum->syntax '#f ':-))
                                           (gx#free-identifier=?
                                            _%$%g5860658724%_
                                            (gx#datum->syntax '#f '::-))
                                           (gx#free-identifier=?
                                            _%$%g5860658724%_
                                            (gx#datum->syntax '#f ':?))))
                                  (_%__kont100851100852%_
                                   _%$%g5860558722%_
                                   _%$%g5860658724%_
                                   _%$%g5860758725%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5859558632%_))))))
                         (_%__match100869100870%_
                          (lambda (_%$%e5859958762%_
                                   _%$%hd5860058766%_
                                   _%$%tl5860158769%_
                                   _%$%e5860258772%_
                                   _%$%hd5860358776%_
                                   _%$%tl5860458779%_)
                            (let ((_%$%g5859758782%_ _%$%hd5860358776%_)
                                  (_%$%g5859858784%_ _%$%hd5860058766%_))
                              (if (and (gx#identifier? _%$%g5859858784%_)
                                       (or (gx#free-identifier=?
                                            _%$%g5859858784%_
                                            (gx#datum->syntax '#f ':))
                                           (gx#free-identifier=?
                                            _%$%g5859858784%_
                                            (gx#datum->syntax '#f ':-))
                                           (gx#free-identifier=?
                                            _%$%g5859858784%_
                                            (gx#datum->syntax '#f '::-))
                                           (gx#free-identifier=?
                                            _%$%g5859858784%_
                                            (gx#datum->syntax '#f ':?))))
                                  (_%__kont100849100850%_
                                   _%$%g5859758782%_
                                   _%$%g5859858784%_)
                                  (if (gx#identifier? _%$%hd5860058766%_)
                                      (if (gx#free-identifier=?
                                           |gerbil/core/contract~Using[1]#_g107435_|
                                           _%$%hd5860058766%_)
                                          (_%__kont100853100854%_
                                           _%$%hd5860358776%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5859558632%_)))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5859558632%_))))))))
                    (if (gx#stx-pair? _%__stx100846100847%_)
                        (let ((_%$%e5859958762%_
                               (gx#syntax-e _%__stx100846100847%_)))
                          (let ((_%$%tl5860158769%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e5859958762%_)))
                                (_%$%hd5860058766%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e5859958762%_))))
                            (if (gx#stx-pair? _%$%tl5860158769%_)
                                (let ((_%$%e5860258772%_
                                       (gx#syntax-e _%$%tl5860158769%_)))
                                  (let ((_%$%tl5860458779%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e5860258772%_)))
                                        (_%$%hd5860358776%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e5860258772%_))))
                                    (if (gx#stx-null? _%$%tl5860458779%_)
                                        (_%__match100869100870%_
                                         _%$%e5859958762%_
                                         _%$%hd5860058766%_
                                         _%$%tl5860158769%_
                                         _%$%e5860258772%_
                                         _%$%hd5860358776%_
                                         _%$%tl5860458779%_)
                                        (if (gx#identifier? _%$%hd5860058766%_)
                                            (if (gx#free-identifier=?
                                                 |gerbil/core/contract~Using[1]#_g107435_|
                                                 _%$%hd5860058766%_)
                                                (if (gx#stx-pair?
                                                     _%$%tl5860458779%_)
                                                    (let ((_%$%e5861458702%_
                                                           (gx#syntax-e
                                                            _%$%tl5860458779%_)))
                                                      (let ((_%$%tl5861658709%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e5861458702%_)))
                    (_%$%hd5861558706%_
                     (let () (declare (not safe)) (##car _%$%e5861458702%_))))
                (if (gx#stx-pair? _%$%tl5861658709%_)
                    (let ((_%$%e5861758712%_ (gx#syntax-e _%$%tl5861658709%_)))
                      (let ((_%$%tl5861958719%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5861758712%_)))
                            (_%$%hd5861858716%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5861758712%_))))
                        (if (gx#stx-null? _%$%tl5861958719%_)
                            (_%__match100899100900%_
                             _%$%e5859958762%_
                             _%$%hd5860058766%_
                             _%$%tl5860158769%_
                             _%$%e5860258772%_
                             _%$%hd5860358776%_
                             _%$%tl5860458779%_
                             _%$%e5861458702%_
                             _%$%hd5861558706%_
                             _%$%tl5861658709%_
                             _%$%e5861758712%_
                             _%$%hd5861858716%_
                             _%$%tl5861958719%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g5859558632%_)))))
                    (let () (declare (not safe)) (_%$%g5859558632%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g5859558632%_)))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5859558632%_)))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5859558632%_))))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5859558632%_)))))
                        (let () (declare (not safe)) (_%$%g5859558632%_))))))
              '#f))))
    (define |gerbil/core/contract~Using[1]#!class-slot-nullable?|
      (lambda (_%klass58568%_ _%slot58570%_)
        (let ((_%$%contract5857158573%_
               (|gerbil/core/contract~Using[1]#!class-slot-contract|
                _%klass58568%_
                _%slot58570%_)))
          (if _%$%contract5857158573%_
              (let ((_%contract58576%_ _%$%contract5857158573%_))
                (gx#stx-ormap
                 (lambda (_%x58579%_)
                   (if (gx#identifier? _%x58579%_)
                       (gx#free-identifier=?
                        _%x58579%_
                        (gx#datum->syntax '#f ':?))
                       '#f))
                 _%contract58576%_))
              '#f))))
    (define |gerbil/core/contract~Using[1]#!class-slot-checked-mutator-contract?|
      (lambda (_%klass58337%_ _%slot58339%_)
        (let ((_%$%contract5834058342%_
               (|gerbil/core/contract~Using[1]#!class-slot-contract|
                _%klass58337%_
                _%slot58339%_)))
          (if _%$%contract5834058342%_
              (let* ((_%contract58345%_ _%$%contract5834058342%_)
                     (_%__stx100920100921%_ _%contract58345%_)
                     (_%$%g5835058387%_
                      (lambda ()
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; invalid match target"
                         _%__stx100920100921%_))))
                (let ((_%__kont100923100924%_
                       (lambda (_%$%g5835258537%_ _%$%g5835358539%_)
                         (not (gx#free-identifier=?
                               _%$%g5835358539%_
                               (gx#datum->syntax '#f ':-)))))
                      (_%__kont100925100926%_
                       (lambda (_%$%g5836058477%_
                                _%$%g5836158479%_
                                _%$%g5836258480%_)
                         '#t))
                      (_%__kont100927100928%_
                       (lambda (_%$%g5837558414%_) '#t)))
                  (let* ((_%__match100973100974%_
                          (lambda (_%$%e5836358437%_
                                   _%$%hd5836458441%_
                                   _%$%tl5836558444%_
                                   _%$%e5836658447%_
                                   _%$%hd5836758451%_
                                   _%$%tl5836858454%_
                                   _%$%e5836958457%_
                                   _%$%hd5837058461%_
                                   _%$%tl5837158464%_
                                   _%$%e5837258467%_
                                   _%$%hd5837358471%_
                                   _%$%tl5837458474%_)
                            (let ((_%$%g5836058477%_ _%$%hd5837358471%_)
                                  (_%$%g5836158479%_ _%$%hd5837058461%_)
                                  (_%$%g5836258480%_ _%$%hd5836758451%_))
                              (if (and (gx#identifier? _%$%g5836158479%_)
                                       (or (gx#free-identifier=?
                                            _%$%g5836158479%_
                                            (gx#datum->syntax '#f ':))
                                           (gx#free-identifier=?
                                            _%$%g5836158479%_
                                            (gx#datum->syntax '#f ':-))
                                           (gx#free-identifier=?
                                            _%$%g5836158479%_
                                            (gx#datum->syntax '#f '::-))
                                           (gx#free-identifier=?
                                            _%$%g5836158479%_
                                            (gx#datum->syntax '#f ':?))))
                                  (_%__kont100925100926%_
                                   _%$%g5836058477%_
                                   _%$%g5836158479%_
                                   _%$%g5836258480%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5835058387%_))))))
                         (_%__match100943100944%_
                          (lambda (_%$%e5835458517%_
                                   _%$%hd5835558521%_
                                   _%$%tl5835658524%_
                                   _%$%e5835758527%_
                                   _%$%hd5835858531%_
                                   _%$%tl5835958534%_)
                            (let ((_%$%g5835258537%_ _%$%hd5835858531%_)
                                  (_%$%g5835358539%_ _%$%hd5835558521%_))
                              (if (and (gx#identifier? _%$%g5835358539%_)
                                       (or (gx#free-identifier=?
                                            _%$%g5835358539%_
                                            (gx#datum->syntax '#f ':))
                                           (gx#free-identifier=?
                                            _%$%g5835358539%_
                                            (gx#datum->syntax '#f ':-))
                                           (gx#free-identifier=?
                                            _%$%g5835358539%_
                                            (gx#datum->syntax '#f '::-))
                                           (gx#free-identifier=?
                                            _%$%g5835358539%_
                                            (gx#datum->syntax '#f ':?))))
                                  (_%__kont100923100924%_
                                   _%$%g5835258537%_
                                   _%$%g5835358539%_)
                                  (if (gx#identifier? _%$%hd5835558521%_)
                                      (if (gx#free-identifier=?
                                           |gerbil/core/contract~Using[1]#_g107436_|
                                           _%$%hd5835558521%_)
                                          (_%__kont100927100928%_
                                           _%$%hd5835858531%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5835058387%_)))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5835058387%_))))))))
                    (if (gx#stx-pair? _%__stx100920100921%_)
                        (let ((_%$%e5835458517%_
                               (gx#syntax-e _%__stx100920100921%_)))
                          (let ((_%$%tl5835658524%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e5835458517%_)))
                                (_%$%hd5835558521%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e5835458517%_))))
                            (if (gx#stx-pair? _%$%tl5835658524%_)
                                (let ((_%$%e5835758527%_
                                       (gx#syntax-e _%$%tl5835658524%_)))
                                  (let ((_%$%tl5835958534%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e5835758527%_)))
                                        (_%$%hd5835858531%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e5835758527%_))))
                                    (if (gx#stx-null? _%$%tl5835958534%_)
                                        (_%__match100943100944%_
                                         _%$%e5835458517%_
                                         _%$%hd5835558521%_
                                         _%$%tl5835658524%_
                                         _%$%e5835758527%_
                                         _%$%hd5835858531%_
                                         _%$%tl5835958534%_)
                                        (if (gx#identifier? _%$%hd5835558521%_)
                                            (if (gx#free-identifier=?
                                                 |gerbil/core/contract~Using[1]#_g107436_|
                                                 _%$%hd5835558521%_)
                                                (if (gx#stx-pair?
                                                     _%$%tl5835958534%_)
                                                    (let ((_%$%e5836958457%_
                                                           (gx#syntax-e
                                                            _%$%tl5835958534%_)))
                                                      (let ((_%$%tl5837158464%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e5836958457%_)))
                    (_%$%hd5837058461%_
                     (let () (declare (not safe)) (##car _%$%e5836958457%_))))
                (if (gx#stx-pair? _%$%tl5837158464%_)
                    (let ((_%$%e5837258467%_ (gx#syntax-e _%$%tl5837158464%_)))
                      (let ((_%$%tl5837458474%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5837258467%_)))
                            (_%$%hd5837358471%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5837258467%_))))
                        (if (gx#stx-null? _%$%tl5837458474%_)
                            (_%__match100973100974%_
                             _%$%e5835458517%_
                             _%$%hd5835558521%_
                             _%$%tl5835658524%_
                             _%$%e5835758527%_
                             _%$%hd5835858531%_
                             _%$%tl5835958534%_
                             _%$%e5836958457%_
                             _%$%hd5837058461%_
                             _%$%tl5837158464%_
                             _%$%e5837258467%_
                             _%$%hd5837358471%_
                             _%$%tl5837458474%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g5835058387%_)))))
                    (let () (declare (not safe)) (_%$%g5835058387%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g5835058387%_)))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5835058387%_)))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5835058387%_))))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5835058387%_)))))
                        (let () (declare (not safe)) (_%$%g5835058387%_))))))
              '#f))))
    (define |gerbil/core/contract~Using[1]#dotted-identifier?|
      (lambda (_%id58324%_)
        (if (gx#identifier? _%id58324%_)
            (let* ((_%str58327%_ (symbol->string (gx#stx-e _%id58324%_)))
                   (_%$%index5832958331%_ (string-index _%str58327%_ '#\.)))
              (if _%$%index5832958331%_
                  (let ((_%index58334%_ _%$%index5832958331%_))
                    (if (let () (declare (not safe)) (##fx> _%index58334%_ '0))
                        (not (ormap string-empty?
                                    (string-split _%str58327%_ '#\.)))
                        '#f))
                  '#f))
            '#f)))
    (define |gerbil/core/contract~Using[1]#split-dotted-identifier|
      (lambda (_%stx58317%_ _%id58319%_)
        (let ((_%parts58321%_
               (string-split (symbol->string (gx#stx-e _%id58319%_)) '#\.)))
          (if (find string-empty? _%parts58321%_)
              (gx#raise-syntax-error
               '#f
               '"bad dotted identifier"
               _%stx58317%_
               _%id58319%_)
              (cons (gx#stx-identifier _%id58319%_ (car _%parts58321%_))
                    (map string->symbol (cdr _%parts58321%_)))))))
    (define |gerbil/core/contract~Using[1]#get-slot-accessor__%|
      (lambda (_%stx58134%_
               _%klass-or-id58136%_
               _%slot58137%_
               _%checked?58138%_)
        (let* ((_%klass58140%_
                (if (gx#identifier? _%klass-or-id58136%_)
                    (let ()
                      (declare (not safe))
                      (|gerbil/core/contract~TypeReference[1]#resolve-type|
                       _%stx58134%_
                       _%klass-or-id58136%_))
                    _%klass-or-id58136%_))
               (_%$e58145%_
                (agetq _%slot58137%_
                       (if _%checked?58138%_
                           (let ((__obj107216 _%klass58140%_))
                             (if (let ()
                                   (declare (not safe))
                                   (##structure-direct-instance-of?
                                    __obj107216
                                    'gerbil/core#class-type-info::t))
                                 (let ()
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    __obj107216
                                    '16
                                    '#f
                                    '#f))
                                 (class-slot-ref
                                  gerbil/core/mop~MOP-2#class-type-info::t
                                  __obj107216
                                  'accessors)))
                           (let ((__obj107215 _%klass58140%_))
                             (if (let ()
                                   (declare (not safe))
                                   (##structure-direct-instance-of?
                                    __obj107215
                                    'gerbil/core#class-type-info::t))
                                 (let ()
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    __obj107215
                                    '18
                                    '#f
                                    '#f))
                                 (class-slot-ref
                                  gerbil/core/mop~MOP-2#class-type-info::t
                                  __obj107215
                                  'unchecked-accessors)))))))
          (if _%$e58145%_
              _%$e58145%_
              (let ((_%$e58153%_
                     (agetq _%slot58137%_
                            (let ((_%$e58149%_
                                   (let ((__obj107217 _%klass58140%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (##structure-direct-instance-of?
                                            __obj107217
                                            'gerbil/core#class-type-info::t))
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            __obj107217
                                            '23
                                            '#f
                                            '#f))
                                         (class-slot-ref
                                          gerbil/core/mop~MOP-2#class-type-info::t
                                          __obj107217
                                          'slot-offsets)))))
                              (if _%$e58149%_ _%$e58149%_ '())))))
                (if _%$e58153%_
                    (let* ((_%$%g5816058183%_
                            (lambda (_%$%g5816158179%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%$%g5816158179%_)))
                           (_%$%g5815958293%_
                            (lambda (_%$%g5816158187%_)
                              (if (gx#stx-pair? _%$%g5816158187%_)
                                  (let ((_%$%e5816658190%_
                                         (gx#syntax-e _%$%g5816158187%_)))
                                    (let ((_%$%hd5816758194%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5816658190%_)))
                                          (_%$%tl5816858197%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5816658190%_))))
                                      (if (gx#stx-pair? _%$%tl5816858197%_)
                                          (let ((_%$%e5816958200%_
                                                 (gx#syntax-e
                                                  _%$%tl5816858197%_)))
                                            (let ((_%$%hd5817058204%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5816958200%_)))
                                                  (_%$%tl5817158207%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5816958200%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5817158207%_)
                                                  (let ((_%$%e5817258210%_
                                                         (gx#syntax-e
                                                          _%$%tl5817158207%_)))
                                                    (let ((_%$%hd5817358214%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5817258210%_)))
                                                          (_%$%tl5817458217%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5817258210%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl5817458217%_)
                                                          (let ((_%$%e5817558220%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl5817458217%_)))
                    (let ((_%$%hd5817658224%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5817558220%_)))
                          (_%$%tl5817758227%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5817558220%_))))
                      (if (gx#stx-null? _%$%tl5817758227%_)
                          (let* ((_%$%g5826158269%_
                                  (lambda (_%$%g5826258265%_)
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Bad syntax; invalid match target"
                                     _%$%g5826258265%_)))
                                 (_%$%g5826058289%_
                                  (lambda (_%$%g5826258273%_)
                                    (gx#stx-wrap-source
                                     (cons (gx#datum->syntax '#f 'lambda)
                                           (cons (cons (gx#datum->syntax
                                                        '#f
                                                        '$obj)
                                                       '())
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '##unchecked-structure-ref)
                                                             (cons _%$%g5826258273%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%$%hd5817358214%_
                                 (cons _%$%hd5816758194%_
                                       (cons (cons (gx#datum->syntax
                                                    '#f
                                                    'quote)
                                                   (cons _%$%hd5817058204%_
                                                         '()))
                                             '())))))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (gx#stx-source _%stx58134%_)))))
                            (_%$%g5826058289%_
                             (if _%checked?58138%_
                                 (cons (gx#datum->syntax '#f ':~)
                                       (cons (gx#datum->syntax '#f '$obj)
                                             (cons _%$%hd5817658224%_ '())))
                                 (gx#datum->syntax '#f '$obj))))
                          (_%$%g5816058183%_ _%$%g5816158187%_))))
                  (_%$%g5816058183%_ _%$%g5816158187%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5816058183%_
                                                   _%$%g5816158187%_))))
                                          (_%$%g5816058183%_
                                           _%$%g5816158187%_))))
                                  (_%$%g5816058183%_ _%$%g5816158187%_)))))
                      (_%$%g5815958293%_
                       (list (let ((__obj107218 _%klass58140%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-direct-instance-of?
                                      __obj107218
                                      'gerbil/core#runtime-type-info::t))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      __obj107218
                                      '3
                                      '#f
                                      '#f))
                                   (class-slot-ref
                                    gerbil/core/mop~MOP-2#runtime-type-info::t
                                    __obj107218
                                    'type-descriptor)))
                             _%slot58137%_
                             _%$e58153%_
                             (let ((__obj107219 _%klass58140%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-direct-instance-of?
                                      __obj107219
                                      'gerbil/core#class-type-info::t))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      __obj107219
                                      '15
                                      '#f
                                      '#f))
                                   (class-slot-ref
                                    gerbil/core/mop~MOP-2#class-type-info::t
                                    __obj107219
                                    'predicate))))))
                    (gx#raise-syntax-error
                     '#f
                     '"no accessor for slot"
                     _%stx58134%_
                     _%klass58140%_
                     _%slot58137%_)))))))
    (define |gerbil/core/contract~Using[1]#get-slot-accessor__0|
      (lambda (_%stx58303%_ _%klass-or-id58305%_ _%slot58306%_)
        (let ((_%checked?58308%_ '#f))
          (|gerbil/core/contract~Using[1]#get-slot-accessor__%|
           _%stx58303%_
           _%klass-or-id58305%_
           _%slot58306%_
           _%checked?58308%_))))
    (define |gerbil/core/contract~Using[1]#get-slot-accessor|
      (lambda _g107437_
        (let ((_g107438_ (let () (declare (not safe)) (##length _g107437_))))
          (cond ((let () (declare (not safe)) (##fx= _g107438_ 3))
                 (apply |gerbil/core/contract~Using[1]#get-slot-accessor__0|
                        _g107437_))
                ((let () (declare (not safe)) (##fx= _g107438_ 4))
                 (apply |gerbil/core/contract~Using[1]#get-slot-accessor__%|
                        _g107437_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  |gerbil/core/contract~Using[1]#get-slot-accessor|
                  _g107437_))))))
    (define |gerbil/core/contract~Using[1]#get-slot-mutator|
      (lambda (_%stx57964%_
               _%klass-or-id57966%_
               _%slot57967%_
               _%checked?57968%_)
        (let* ((_%klass57970%_
                (if (gx#identifier? _%klass-or-id57966%_)
                    (let ()
                      (declare (not safe))
                      (|gerbil/core/contract~TypeReference[1]#resolve-type|
                       _%stx57964%_
                       _%klass-or-id57966%_))
                    _%klass-or-id57966%_))
               (_%mutators57973%_
                (if _%checked?57968%_
                    (let ((__obj107221 _%klass57970%_))
                      (if (let ()
                            (declare (not safe))
                            (##structure-direct-instance-of?
                             __obj107221
                             'gerbil/core#class-type-info::t))
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             __obj107221
                             '17
                             '#f
                             '#f))
                          (class-slot-ref
                           gerbil/core/mop~MOP-2#class-type-info::t
                           __obj107221
                           'mutators)))
                    (let ((__obj107220 _%klass57970%_))
                      (if (let ()
                            (declare (not safe))
                            (##structure-direct-instance-of?
                             __obj107220
                             'gerbil/core#class-type-info::t))
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             __obj107220
                             '19
                             '#f
                             '#f))
                          (class-slot-ref
                           gerbil/core/mop~MOP-2#class-type-info::t
                           __obj107220
                           'unchecked-mutators)))))
               (_%$e57978%_ (agetq _%slot57967%_ _%mutators57973%_)))
          (if _%$e57978%_
              _%$e57978%_
              (let ((_%$e57986%_
                     (agetq _%slot57967%_
                            (let ((_%$e57982%_
                                   (let ((__obj107222 _%klass57970%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (##structure-direct-instance-of?
                                            __obj107222
                                            'gerbil/core#class-type-info::t))
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            __obj107222
                                            '23
                                            '#f
                                            '#f))
                                         (class-slot-ref
                                          gerbil/core/mop~MOP-2#class-type-info::t
                                          __obj107222
                                          'slot-offsets)))))
                              (if _%$e57982%_ _%$e57982%_ '())))))
                (if _%$e57986%_
                    (let* ((_%$%g5799358016%_
                            (lambda (_%$%g5799458012%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%$%g5799458012%_)))
                           (_%$%g5799258127%_
                            (lambda (_%$%g5799458020%_)
                              (if (gx#stx-pair? _%$%g5799458020%_)
                                  (let ((_%$%e5799958023%_
                                         (gx#syntax-e _%$%g5799458020%_)))
                                    (let ((_%$%hd5800058027%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5799958023%_)))
                                          (_%$%tl5800158030%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5799958023%_))))
                                      (if (gx#stx-pair? _%$%tl5800158030%_)
                                          (let ((_%$%e5800258033%_
                                                 (gx#syntax-e
                                                  _%$%tl5800158030%_)))
                                            (let ((_%$%hd5800358037%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5800258033%_)))
                                                  (_%$%tl5800458040%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5800258033%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5800458040%_)
                                                  (let ((_%$%e5800558043%_
                                                         (gx#syntax-e
                                                          _%$%tl5800458040%_)))
                                                    (let ((_%$%hd5800658047%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5800558043%_)))
                                                          (_%$%tl5800758050%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5800558043%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl5800758050%_)
                                                          (let ((_%$%e5800858053%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl5800758050%_)))
                    (let ((_%$%hd5800958057%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5800858053%_)))
                          (_%$%tl5801058060%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5800858053%_))))
                      (if (gx#stx-null? _%$%tl5801058060%_)
                          (let* ((_%$%g5809558103%_
                                  (lambda (_%$%g5809658099%_)
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Bad syntax; invalid match target"
                                     _%$%g5809658099%_)))
                                 (_%$%g5809458123%_
                                  (lambda (_%$%g5809658107%_)
                                    (gx#stx-wrap-source
                                     (cons (gx#datum->syntax '#f 'lambda)
                                           (cons (cons (gx#datum->syntax
                                                        '#f
                                                        '$obj)
                                                       (cons (gx#datum->syntax
                                                              '#f
                                                              '$val)
                                                             '()))
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '##unchecked-structure-set!)
                                                             (cons _%$%g5809658107%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons (gx#datum->syntax '#f '$val)
                                 (cons _%$%hd5800658047%_
                                       (cons _%$%hd5800058027%_
                                             (cons (cons (gx#datum->syntax
                                                          '#f
                                                          'quote)
                                                         (cons _%$%hd5800358037%_
                                                               '()))
                                                   '()))))))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (gx#stx-source _%stx57964%_)))))
                            (_%$%g5809458123%_
                             (if _%checked?57968%_
                                 (cons (gx#datum->syntax '#f ':~)
                                       (cons (gx#datum->syntax '#f '$obj)
                                             (cons _%$%hd5800958057%_ '())))
                                 (gx#datum->syntax '#f '$obj))))
                          (_%$%g5799358016%_ _%$%g5799458020%_))))
                  (_%$%g5799358016%_ _%$%g5799458020%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5799358016%_
                                                   _%$%g5799458020%_))))
                                          (_%$%g5799358016%_
                                           _%$%g5799458020%_))))
                                  (_%$%g5799358016%_ _%$%g5799458020%_)))))
                      (_%$%g5799258127%_
                       (list (let ((__obj107223 _%klass57970%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-direct-instance-of?
                                      __obj107223
                                      'gerbil/core#runtime-type-info::t))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      __obj107223
                                      '3
                                      '#f
                                      '#f))
                                   (class-slot-ref
                                    gerbil/core/mop~MOP-2#runtime-type-info::t
                                    __obj107223
                                    'type-descriptor)))
                             _%slot57967%_
                             _%$e57986%_
                             (let ((__obj107224 _%klass57970%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-direct-instance-of?
                                      __obj107224
                                      'gerbil/core#class-type-info::t))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      __obj107224
                                      '15
                                      '#f
                                      '#f))
                                   (class-slot-ref
                                    gerbil/core/mop~MOP-2#class-type-info::t
                                    __obj107224
                                    'predicate))))))
                    (gx#raise-syntax-error
                     '#f
                     '"no mutator for slot"
                     _%stx57964%_
                     _%klass57970%_
                     _%slot57967%_)))))))
    (define |gerbil/core/contract~Using[:0:]#with-class|
      (lambda (_%stx58866%_)
        (letrec ((_%expand-body58869%_
                  (lambda (_%klass59938%_
                           _%var59940%_
                           _%Type59941%_
                           _%body59942%_
                           _%checked?59943%_
                           _%maybe?59944%_)
                    (let* ((_%$%g5994659994%_
                            (lambda (_%$%g5994759990%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%$%g5994759990%_)))
                           (_%$%g5994560163%_
                            (lambda (_%$%g5994759998%_)
                              (if (gx#stx-pair? _%$%g5994759998%_)
                                  (let ((_%$%e5995660001%_
                                         (gx#syntax-e _%$%g5994759998%_)))
                                    (let ((_%$%hd5995760005%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5995660001%_)))
                                          (_%$%tl5995860008%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5995660001%_))))
                                      (if (gx#stx-pair? _%$%tl5995860008%_)
                                          (let ((_%$%e5995960011%_
                                                 (gx#syntax-e
                                                  _%$%tl5995860008%_)))
                                            (let ((_%$%hd5996060015%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5995960011%_)))
                                                  (_%$%tl5996160018%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5995960011%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5996160018%_)
                                                  (let ((_%$%e5996260021%_
                                                         (gx#syntax-e
                                                          _%$%tl5996160018%_)))
                                                    (let ((_%$%hd5996360025%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5996260021%_)))
                                                          (_%$%tl5996460028%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5996260021%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl5996460028%_)
                                                          (let ((_%$%e5996560031%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl5996460028%_)))
                    (let ((_%$%hd5996660035%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5996560031%_)))
                          (_%$%tl5996760038%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5996560031%_))))
                      (if (gx#stx-pair? _%$%tl5996760038%_)
                          (let ((_%$%e5996860041%_
                                 (gx#syntax-e _%$%tl5996760038%_)))
                            (let ((_%$%hd5996960045%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5996860041%_)))
                                  (_%$%tl5997060048%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5996860041%_))))
                              (if (gx#stx-pair? _%$%tl5997060048%_)
                                  (let ((_%$%e5997160051%_
                                         (gx#syntax-e _%$%tl5997060048%_)))
                                    (let ((_%$%hd5997260055%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5997160051%_)))
                                          (_%$%tl5997360058%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5997160051%_))))
                                      (if (gx#stx-pair? _%$%tl5997360058%_)
                                          (let ((_%$%e5997460061%_
                                                 (gx#syntax-e
                                                  _%$%tl5997360058%_)))
                                            (let ((_%$%hd5997560065%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5997460061%_)))
                                                  (_%$%tl5997660068%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5997460061%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl5997660068%_)
                                                  (let ((_%$%e5997760071%_
                                                         (gx#syntax-e
                                                          _%$%tl5997660068%_)))
                                                    (let ((_%$%hd5997860075%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5997760071%_)))
                                                          (_%$%tl5997960078%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5997760071%_))))
                                                      (if (gx#stx-pair/null?
                                                           _%$%hd5997860075%_)
                                                          (let ((_g107439_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice _%$%hd5997860075%_ '0)))
                    (begin
                      (let ((_g107440_
                             (let ()
                               (declare (not safe))
                               (if (##values? _g107439_)
                                   (##values-length _g107439_)
                                   1))))
                        (if (not (let ()
                                   (declare (not safe))
                                   (##fx= _g107440_ 2)))
                            (error "Context expects 2 values" _g107440_)))
                      (let ((_%$%target5998060081%_
                             (let ()
                               (declare (not safe))
                               (##values-ref _g107439_ 0)))
                            (_%$%tl5998260084%_
                             (let ()
                               (declare (not safe))
                               (##values-ref _g107439_ 1))))
                        (if (gx#stx-null? _%$%tl5998260084%_)
                            (letrec ((_%$%loop5998360087%_
                                      (lambda (_%$%hd5998160091%_
                                               _%$%body5998760094%_)
                                        (if (gx#stx-pair? _%$%hd5998160091%_)
                                            (let ((_%$%e5998460096%_
                                                   (gx#syntax-e
                                                    _%$%hd5998160091%_)))
                                              (let ((_%$%lp-hd5998560100%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e5998460096%_)))
                                                    (_%$%lp-tl5998660103%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e5998460096%_))))
                                                (_%$%loop5998360087%_
                                                 _%$%lp-tl5998660103%_
                                                 (cons _%$%lp-hd5998560100%_
                                                       _%$%body5998760094%_))))
                                            (let ((_%$%body5998860106%_
                                                   (reverse _%$%body5998760094%_)))
                                              (if (gx#stx-null?
                                                   _%$%tl5997960078%_)
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'let)
                                                        (cons (cons _%$%hd5996360025%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons (cons (gx#datum->syntax
                                         '#f
                                         'begin-annotation)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     '@type)
                                                    (cons _%$%hd5996060015%_
                                                          '()))
                                              (cons _%$%hd5996360025%_ '())))
                                  '()))
                      (cons (cons (gx#datum->syntax '#f 'let-syntax)
                                  (cons (cons (cons _%$%hd5995760005%_
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'make-type-env)
                        (cons (cons (gx#datum->syntax '#f 'quote-syntax)
                                    (cons _%$%hd5996360025%_ '()))
                              (cons (cons (gx#datum->syntax '#f 'quote)
                                          (cons _%$%hd5996660035%_ '()))
                                    (cons _%$%hd5996960045%_
                                          (cons _%$%hd5997260055%_
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'quote)
                                                            (cons _%$%hd5997560065%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())
                                        (cons (cons (gx#datum->syntax '#f 'let)
                                                    (cons '()
                                                          (foldr (lambda (_%$%g6015460157%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  _%$%g6015560160%_)
                           (cons _%$%g6015460157%_ _%$%g6015560160%_))
                         '()
                         _%$%body5998860106%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5994659994%_
                                                   _%$%g5994759998%_)))))))
                              (_%$%loop5998360087%_
                               _%$%target5998060081%_
                               '()))
                            (_%$%g5994659994%_ _%$%g5994759998%_)))))
                  (_%$%g5994659994%_ _%$%g5994759998%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5994659994%_
                                                   _%$%g5994759998%_))))
                                          (_%$%g5994659994%_
                                           _%$%g5994759998%_))))
                                  (_%$%g5994659994%_ _%$%g5994759998%_))))
                          (_%$%g5994659994%_ _%$%g5994759998%_))))
                  (_%$%g5994659994%_ _%$%g5994759998%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5994659994%_
                                                   _%$%g5994759998%_))))
                                          (_%$%g5994659994%_
                                           _%$%g5994759998%_))))
                                  (_%$%g5994659994%_ _%$%g5994759998%_)))))
                      (_%$%g5994560163%_
                       (list (gx#syntax-local-introduce '@@type)
                             (if _%maybe?59944%_
                                 (cons 'nullable
                                       (cons (let ((__obj107226
                                                    _%klass59938%_))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (##structure-direct-instance-of?
                                                      __obj107226
                                                      'gerbil/core#class-type-info::t))
                                                   (let ()
                                                     (declare (not safe))
                                                     (##unchecked-structure-ref
                                                      __obj107226
                                                      '4
                                                      '#f
                                                      '#f))
                                                   (class-slot-ref
                                                    gerbil/core/mop~MOP-2#class-type-info::t
                                                    __obj107226
                                                    'type-descriptor)))
                                             '()))
                                 (let ((__obj107225 _%klass59938%_))
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-direct-instance-of?
                                          __obj107225
                                          'gerbil/core#class-type-info::t))
                                       (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          __obj107225
                                          '4
                                          '#f
                                          '#f))
                                       (class-slot-ref
                                        gerbil/core/mop~MOP-2#class-type-info::t
                                        __obj107225
                                        'type-descriptor))))
                             _%var59940%_
                             _%klass59938%_
                             _%checked?59943%_
                             _%maybe?59944%_
                             (let ()
                               (declare (not safe))
                               (gerbil/core/contract~TypeEnv#current-type-env))
                             _%body59942%_)))))
                 (_%expand58871%_
                  (lambda (_%var59825%_
                           _%Type59827%_
                           _%body59828%_
                           _%checked?59829%_
                           _%checked-mutators?59830%_
                           _%maybe?59831%_)
                    (let* ((_%klass59833%_
                            (gx#syntax-local-value _%Type59827%_ false))
                           (_%expr-body59840%_
                            (_%expand-body58869%_
                             _%klass59833%_
                             _%var59825%_
                             _%Type59827%_
                             _%body59828%_
                             (let ((_%$e59836%_ _%checked?59829%_))
                               (if _%$e59836%_
                                   _%$e59836%_
                                   _%checked-mutators?59830%_))
                             _%maybe?59831%_)))
                      (if _%checked?59829%_
                          (let* ((_%$%g5984559864%_
                                  (lambda (_%$%g5984659860%_)
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Bad syntax; invalid match target"
                                     _%$%g5984659860%_)))
                                 (_%$%g5984459926%_
                                  (lambda (_%$%g5984659868%_)
                                    (if (gx#stx-pair? _%$%g5984659868%_)
                                        (let ((_%$%e5985059871%_
                                               (gx#syntax-e
                                                _%$%g5984659868%_)))
                                          (let ((_%$%hd5985159875%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5985059871%_)))
                                                (_%$%tl5985259878%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5985059871%_))))
                                            (if (gx#stx-pair?
                                                 _%$%tl5985259878%_)
                                                (let ((_%$%e5985359881%_
                                                       (gx#syntax-e
                                                        _%$%tl5985259878%_)))
                                                  (let ((_%$%hd5985459885%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e5985359881%_)))
                                                        (_%$%tl5985559888%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e5985359881%_))))
                                                    (if (gx#stx-pair?
                                                         _%$%tl5985559888%_)
                                                        (let ((_%$%e5985659891%_
                                                               (gx#syntax-e
                                                                _%$%tl5985559888%_)))
                                                          (let ((_%$%hd5985759895%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##car _%$%e5985659891%_)))
                        (_%$%tl5985859898%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e5985659891%_))))
                    (if (gx#stx-null? _%$%tl5985859898%_)
                        (cons (gx#datum->syntax '#f 'with-contract)
                              (cons (cons _%$%hd5985459885%_
                                          (cons (gx#datum->syntax '#f ':~)
                                                (cons _%$%hd5985159875%_ '())))
                                    (cons _%$%hd5985759895%_ '())))
                        (_%$%g5984559864%_ _%$%g5984659868%_))))
                (_%$%g5984559864%_ _%$%g5984659868%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g5984559864%_
                                                 _%$%g5984659868%_))))
                                        (_%$%g5984559864%_
                                         _%$%g5984659868%_)))))
                            (_%$%g5984459926%_
                             (list (let ((_%instance?59930%_
                                          (let ((__obj107227 _%klass59833%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##structure-direct-instance-of?
                                                   __obj107227
                                                   'gerbil/core#class-type-info::t))
                                                (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   __obj107227
                                                   '15
                                                   '#f
                                                   '#f))
                                                (class-slot-ref
                                                 gerbil/core/mop~MOP-2#class-type-info::t
                                                 __obj107227
                                                 'predicate)))))
                                     (if _%maybe?59831%_
                                         (list '?
                                               (list 'or
                                                     'not
                                                     _%instance?59930%_))
                                         _%instance?59930%_))
                                   _%var59825%_
                                   _%expr-body59840%_)))
                          _%expr-body59840%_)))))
          (let* ((_%__stx100994100995%_ _%stx58866%_)
                 (_%$%g5887859052%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx100994100995%_))))
            (let ((_%__kont100997100998%_
                   (lambda (_%$%g5888059782%_
                            _%$%g5888159784%_
                            _%$%g5888259785%_
                            _%$%g5888359786%_)
                     (_%expand58871%_
                      _%$%g5888359786%_
                      (let ()
                        (declare (not safe))
                        (|gerbil/core/contract~TypeReference[1]#resolve-type->identifier|
                         _%stx58866%_
                         _%$%g5888259785%_))
                      (foldr (lambda (_%$%g5981259815%_ _%$%g5981359818%_)
                               (cons _%$%g5981259815%_ _%$%g5981359818%_))
                             '()
                             _%$%g5888059782%_)
                      '#f
                      '#t
                      '#t)))
                  (_%__kont101001101002%_
                   (lambda (_%$%g5891159619%_
                            _%$%g5891259621%_
                            _%$%g5891359622%_
                            _%$%g5891459623%_)
                     (let* ((_%$%g5964859656%_
                             (lambda (_%$%g5964959652%_)
                               (gx#raise-syntax-error
                                '#f
                                '"Bad syntax; invalid match target"
                                _%$%g5964959652%_)))
                            (_%$%g5964759683%_
                             (lambda (_%$%g5964959660%_)
                               (cons (gx#datum->syntax '#f 'with-class)
                                     (cons (cons _%$%g5891459623%_
                                                 (cons _%$%g5891359622%_
                                                       (cons _%$%g5964959660%_
                                                             '())))
                                           (foldr (lambda (_%$%g5967459677%_
                                                           _%$%g5967559680%_)
                                                    (cons _%$%g5967459677%_
                                                          _%$%g5967559680%_))
                                                  '()
                                                  _%$%g5891159619%_))))))
                       (_%$%g5964759683%_
                        (let ((__obj107228
                               (gx#syntax-local-value _%$%g5891259621%_)))
                          (if (let ()
                                (declare (not safe))
                                (##structure-direct-instance-of?
                                 __obj107228
                                 'gerbil/core/contract~TypeReference#type-reference::t))
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 __obj107228
                                 '1
                                 '#f
                                 '#f))
                              (class-slot-ref
                               |gerbil/core/contract~TypeReference[1]#type-reference::t|
                               __obj107228
                               'identifier)))))))
                  (_%__kont101005101006%_
                   (lambda (_%$%g5893959499%_
                            _%$%g5894059501%_
                            _%$%g5894159502%_)
                     (_%expand58871%_
                      _%$%g5894159502%_
                      _%$%g5894059501%_
                      (foldr (lambda (_%$%g5952559528%_ _%$%g5952659531%_)
                               (cons _%$%g5952559528%_ _%$%g5952659531%_))
                             '()
                             _%$%g5893959499%_)
                      '#t
                      '#t
                      '#f)))
                  (_%__kont101009101010%_
                   (lambda (_%$%g5896659379%_
                            _%$%g5896759381%_
                            _%$%g5896859382%_)
                     (_%expand58871%_
                      _%$%g5896859382%_
                      _%$%g5896759381%_
                      (foldr (lambda (_%$%g5940559408%_ _%$%g5940659411%_)
                               (cons _%$%g5940559408%_ _%$%g5940659411%_))
                             '()
                             _%$%g5896659379%_)
                      '#t
                      '#t
                      '#t)))
                  (_%__kont101013101014%_
                   (lambda (_%$%g5899359259%_
                            _%$%g5899459261%_
                            _%$%g5899559262%_)
                     (_%expand58871%_
                      _%$%g5899559262%_
                      _%$%g5899459261%_
                      (foldr (lambda (_%$%g5928559288%_ _%$%g5928659291%_)
                               (cons _%$%g5928559288%_ _%$%g5928659291%_))
                             '()
                             _%$%g5899359259%_)
                      '#f
                      '#f
                      '#f)))
                  (_%__kont101017101018%_
                   (lambda (_%$%g5902059137%_
                            _%$%g5902159139%_
                            _%$%g5902259140%_)
                     (_%expand58871%_
                      _%$%g5902259140%_
                      _%$%g5902159139%_
                      (foldr (lambda (_%$%g5916559168%_ _%$%g5916659171%_)
                               (cons _%$%g5916559168%_ _%$%g5916659171%_))
                             '()
                             _%$%g5902059137%_)
                      '#f
                      '#t
                      '#f))))
              (let* ((_%__match101287101288%_
                      (lambda (_%$%e5902359059%_
                               _%$%hd5902459063%_
                               _%$%tl5902559066%_
                               _%$%e5902659069%_
                               _%$%hd5902759073%_
                               _%$%tl5902859076%_
                               _%$%e5902959079%_
                               _%$%hd5903059083%_
                               _%$%tl5903159086%_
                               _%$%e5903259089%_
                               _%$%hd5903359093%_
                               _%$%tl5903459096%_
                               _%$%e5903559099%_
                               _%$%hd5903659103%_
                               _%$%tl5903759106%_
                               _%__splice101019101020%_
                               _%$%target5903859109%_
                               _%$%tl5904059112%_)
                        (letrec ((_%$%loop5904159115%_
                                  (lambda (_%$%hd5903959119%_
                                           _%$%body5904559122%_)
                                    (if (gx#stx-pair? _%$%hd5903959119%_)
                                        (let ((_%$%e5904259124%_
                                               (gx#syntax-e
                                                _%$%hd5903959119%_)))
                                          (let ((_%$%lp-tl5904459131%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5904259124%_)))
                                                (_%$%lp-hd5904359128%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5904259124%_))))
                                            (_%$%loop5904159115%_
                                             _%$%lp-tl5904459131%_
                                             (cons _%$%lp-hd5904359128%_
                                                   _%$%body5904559122%_))))
                                        (let ((_%$%body5904659134%_
                                               (reverse _%$%body5904559122%_)))
                                          (let ((_%$%g5902059137%_
                                                 _%$%body5904659134%_)
                                                (_%$%g5902159139%_
                                                 _%$%hd5903659103%_)
                                                (_%$%g5902259140%_
                                                 _%$%hd5903059083%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gerbil/core/mop~MOP-2#syntax-local-class-type-info?__0
                                                   _%$%g5902159139%_))
                                                (_%__kont101017101018%_
                                                 _%$%g5902059137%_
                                                 _%$%g5902159139%_
                                                 _%$%g5902259140%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))))))
                          (_%$%loop5904159115%_ _%$%target5903859109%_ '()))))
                     (_%__match101243101244%_
                      (lambda (_%$%e5899659181%_
                               _%$%hd5899759185%_
                               _%$%tl5899859188%_
                               _%$%e5899959191%_
                               _%$%hd5900059195%_
                               _%$%tl5900159198%_
                               _%$%e5900259201%_
                               _%$%hd5900359205%_
                               _%$%tl5900459208%_
                               _%$%e5900559211%_
                               _%$%hd5900659215%_
                               _%$%tl5900759218%_
                               _%$%e5900859221%_
                               _%$%hd5900959225%_
                               _%$%tl5901059228%_
                               _%__splice101015101016%_
                               _%$%target5901159231%_
                               _%$%tl5901359234%_)
                        (letrec ((_%$%loop5901459237%_
                                  (lambda (_%$%hd5901259241%_
                                           _%$%body5901859244%_)
                                    (if (gx#stx-pair? _%$%hd5901259241%_)
                                        (let ((_%$%e5901559246%_
                                               (gx#syntax-e
                                                _%$%hd5901259241%_)))
                                          (let ((_%$%lp-tl5901759253%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5901559246%_)))
                                                (_%$%lp-hd5901659250%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5901559246%_))))
                                            (_%$%loop5901459237%_
                                             _%$%lp-tl5901759253%_
                                             (cons _%$%lp-hd5901659250%_
                                                   _%$%body5901859244%_))))
                                        (let ((_%$%body5901959256%_
                                               (reverse _%$%body5901859244%_)))
                                          (let ((_%$%g5899359259%_
                                                 _%$%body5901959256%_)
                                                (_%$%g5899459261%_
                                                 _%$%hd5900959225%_)
                                                (_%$%g5899559262%_
                                                 _%$%hd5900359205%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gerbil/core/mop~MOP-2#syntax-local-class-type-info?__0
                                                   _%$%g5899459261%_))
                                                (_%__kont101013101014%_
                                                 _%$%g5899359259%_
                                                 _%$%g5899459261%_
                                                 _%$%g5899559262%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))))))
                          (_%$%loop5901459237%_ _%$%target5901159231%_ '()))))
                     (_%__match101199101200%_
                      (lambda (_%$%e5896959301%_
                               _%$%hd5897059305%_
                               _%$%tl5897159308%_
                               _%$%e5897259311%_
                               _%$%hd5897359315%_
                               _%$%tl5897459318%_
                               _%$%e5897559321%_
                               _%$%hd5897659325%_
                               _%$%tl5897759328%_
                               _%$%e5897859331%_
                               _%$%hd5897959335%_
                               _%$%tl5898059338%_
                               _%$%e5898159341%_
                               _%$%hd5898259345%_
                               _%$%tl5898359348%_
                               _%__splice101011101012%_
                               _%$%target5898459351%_
                               _%$%tl5898659354%_)
                        (letrec ((_%$%loop5898759357%_
                                  (lambda (_%$%hd5898559361%_
                                           _%$%body5899159364%_)
                                    (if (gx#stx-pair? _%$%hd5898559361%_)
                                        (let ((_%$%e5898859366%_
                                               (gx#syntax-e
                                                _%$%hd5898559361%_)))
                                          (let ((_%$%lp-tl5899059373%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5898859366%_)))
                                                (_%$%lp-hd5898959370%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5898859366%_))))
                                            (_%$%loop5898759357%_
                                             _%$%lp-tl5899059373%_
                                             (cons _%$%lp-hd5898959370%_
                                                   _%$%body5899159364%_))))
                                        (let ((_%$%body5899259376%_
                                               (reverse _%$%body5899159364%_)))
                                          (let ((_%$%g5896659379%_
                                                 _%$%body5899259376%_)
                                                (_%$%g5896759381%_
                                                 _%$%hd5898259345%_)
                                                (_%$%g5896859382%_
                                                 _%$%hd5897659325%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gerbil/core/mop~MOP-2#syntax-local-class-type-info?__0
                                                   _%$%g5896759381%_))
                                                (_%__kont101009101010%_
                                                 _%$%g5896659379%_
                                                 _%$%g5896759381%_
                                                 _%$%g5896859382%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))))))
                          (_%$%loop5898759357%_ _%$%target5898459351%_ '()))))
                     (_%__match101155101156%_
                      (lambda (_%$%e5894259421%_
                               _%$%hd5894359425%_
                               _%$%tl5894459428%_
                               _%$%e5894559431%_
                               _%$%hd5894659435%_
                               _%$%tl5894759438%_
                               _%$%e5894859441%_
                               _%$%hd5894959445%_
                               _%$%tl5895059448%_
                               _%$%e5895159451%_
                               _%$%hd5895259455%_
                               _%$%tl5895359458%_
                               _%$%e5895459461%_
                               _%$%hd5895559465%_
                               _%$%tl5895659468%_
                               _%__splice101007101008%_
                               _%$%target5895759471%_
                               _%$%tl5895959474%_)
                        (letrec ((_%$%loop5896059477%_
                                  (lambda (_%$%hd5895859481%_
                                           _%$%body5896459484%_)
                                    (if (gx#stx-pair? _%$%hd5895859481%_)
                                        (let ((_%$%e5896159486%_
                                               (gx#syntax-e
                                                _%$%hd5895859481%_)))
                                          (let ((_%$%lp-tl5896359493%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5896159486%_)))
                                                (_%$%lp-hd5896259490%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5896159486%_))))
                                            (_%$%loop5896059477%_
                                             _%$%lp-tl5896359493%_
                                             (cons _%$%lp-hd5896259490%_
                                                   _%$%body5896459484%_))))
                                        (let ((_%$%body5896559496%_
                                               (reverse _%$%body5896459484%_)))
                                          (let ((_%$%g5893959499%_
                                                 _%$%body5896559496%_)
                                                (_%$%g5894059501%_
                                                 _%$%hd5895559465%_)
                                                (_%$%g5894159502%_
                                                 _%$%hd5894959445%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gerbil/core/mop~MOP-2#syntax-local-class-type-info?__0
                                                   _%$%g5894059501%_))
                                                (_%__kont101005101006%_
                                                 _%$%g5893959499%_
                                                 _%$%g5894059501%_
                                                 _%$%g5894159502%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))))))
                          (_%$%loop5896059477%_ _%$%target5895759471%_ '()))))
                     (_%__match101135101136%_
                      (lambda (_%$%e5894259421%_
                               _%$%hd5894359425%_
                               _%$%tl5894459428%_
                               _%$%e5894559431%_
                               _%$%hd5894659435%_
                               _%$%tl5894759438%_
                               _%$%e5894859441%_
                               _%$%hd5894959445%_
                               _%$%tl5895059448%_
                               _%$%e5895159451%_
                               _%$%hd5895259455%_
                               _%$%tl5895359458%_)
                        (if (gx#identifier? _%$%hd5895259455%_)
                            (if (gx#free-identifier=?
                                 |gerbil/core/contract~Using[1]#_g107441_|
                                 _%$%hd5895259455%_)
                                (if (gx#stx-pair? _%$%tl5895359458%_)
                                    (let ((_%$%e5895459461%_
                                           (gx#syntax-e _%$%tl5895359458%_)))
                                      (let ((_%$%tl5895659468%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e5895459461%_)))
                                            (_%$%hd5895559465%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e5895459461%_))))
                                        (if (gx#stx-null? _%$%tl5895659468%_)
                                            (if (gx#stx-pair/null?
                                                 _%$%tl5894759438%_)
                                                (let ((_%__splice101007101008%_
                                                       (gx#syntax-split-splice->vector
                                                        _%$%tl5894759438%_
                                                        '0)))
                                                  (let ((_%$%tl5895959474%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##vector-ref
                                                            _%__splice101007101008%_
                                                            '1)))
                                                        (_%$%target5895759471%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##vector-ref
                                                            _%__splice101007101008%_
                                                            '0))))
                                                    (if (gx#stx-null?
                                                         _%$%tl5895959474%_)
                                                        (_%__match101155101156%_
                                                         _%$%e5894259421%_
                                                         _%$%hd5894359425%_
                                                         _%$%tl5894459428%_
                                                         _%$%e5894559431%_
                                                         _%$%hd5894659435%_
                                                         _%$%tl5894759438%_
                                                         _%$%e5894859441%_
                                                         _%$%hd5894959445%_
                                                         _%$%tl5895059448%_
                                                         _%$%e5895159451%_
                                                         _%$%hd5895259455%_
                                                         _%$%tl5895359458%_
                                                         _%$%e5895459461%_
                                                         _%$%hd5895559465%_
                                                         _%$%tl5895659468%_
                                                         _%__splice101007101008%_
                                                         _%$%target5895759471%_
                                                         _%$%tl5895959474%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g5887859052%_)))))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5887859052%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g5887859052%_)))
                                (if (gx#free-identifier=?
                                     |gerbil/core/contract~Using[1]#_g107442_|
                                     _%$%hd5895259455%_)
                                    (if (gx#stx-pair? _%$%tl5895359458%_)
                                        (let ((_%$%e5898159341%_
                                               (gx#syntax-e
                                                _%$%tl5895359458%_)))
                                          (let ((_%$%tl5898359348%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5898159341%_)))
                                                (_%$%hd5898259345%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5898159341%_))))
                                            (if (gx#stx-null?
                                                 _%$%tl5898359348%_)
                                                (if (gx#stx-pair/null?
                                                     _%$%tl5894759438%_)
                                                    (let ((_%__splice101011101012%_
                                                           (gx#syntax-split-splice->vector
                                                            _%$%tl5894759438%_
                                                            '0)))
                                                      (let ((_%$%tl5898659354%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##vector-ref _%__splice101011101012%_ '1)))
                    (_%$%target5898459351%_
                     (let ()
                       (declare (not safe))
                       (##vector-ref _%__splice101011101012%_ '0))))
                (if (gx#stx-null? _%$%tl5898659354%_)
                    (_%__match101199101200%_
                     _%$%e5894259421%_
                     _%$%hd5894359425%_
                     _%$%tl5894459428%_
                     _%$%e5894559431%_
                     _%$%hd5894659435%_
                     _%$%tl5894759438%_
                     _%$%e5894859441%_
                     _%$%hd5894959445%_
                     _%$%tl5895059448%_
                     _%$%e5895159451%_
                     _%$%hd5895259455%_
                     _%$%tl5895359458%_
                     _%$%e5898159341%_
                     _%$%hd5898259345%_
                     _%$%tl5898359348%_
                     _%__splice101011101012%_
                     _%$%target5898459351%_
                     _%$%tl5898659354%_)
                    (let () (declare (not safe)) (_%$%g5887859052%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g5887859052%_)))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g5887859052%_)))
                                    (if (gx#free-identifier=?
                                         |gerbil/core/contract~Using[1]#_g107443_|
                                         _%$%hd5895259455%_)
                                        (if (gx#stx-pair? _%$%tl5895359458%_)
                                            (let ((_%$%e5900859221%_
                                                   (gx#syntax-e
                                                    _%$%tl5895359458%_)))
                                              (let ((_%$%tl5901059228%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e5900859221%_)))
                                                    (_%$%hd5900959225%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e5900859221%_))))
                                                (if (gx#stx-null?
                                                     _%$%tl5901059228%_)
                                                    (if (gx#stx-pair/null?
                                                         _%$%tl5894759438%_)
                                                        (let ((_%__splice101015101016%_
                                                               (gx#syntax-split-splice->vector
                                                                _%$%tl5894759438%_
                                                                '0)))
                                                          (let ((_%$%tl5901359234%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice101015101016%_ '1)))
                        (_%$%target5901159231%_
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice101015101016%_ '0))))
                    (if (gx#stx-null? _%$%tl5901359234%_)
                        (_%__match101243101244%_
                         _%$%e5894259421%_
                         _%$%hd5894359425%_
                         _%$%tl5894459428%_
                         _%$%e5894559431%_
                         _%$%hd5894659435%_
                         _%$%tl5894759438%_
                         _%$%e5894859441%_
                         _%$%hd5894959445%_
                         _%$%tl5895059448%_
                         _%$%e5895159451%_
                         _%$%hd5895259455%_
                         _%$%tl5895359458%_
                         _%$%e5900859221%_
                         _%$%hd5900959225%_
                         _%$%tl5901059228%_
                         _%__splice101015101016%_
                         _%$%target5901159231%_
                         _%$%tl5901359234%_)
                        (let () (declare (not safe)) (_%$%g5887859052%_)))))
                (let () (declare (not safe)) (_%$%g5887859052%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g5887859052%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5887859052%_)))
                                        (if (gx#free-identifier=?
                                             |gerbil/core/contract~Using[1]#_g107444_|
                                             _%$%hd5895259455%_)
                                            (if (gx#stx-pair?
                                                 _%$%tl5895359458%_)
                                                (let ((_%$%e5903559099%_
                                                       (gx#syntax-e
                                                        _%$%tl5895359458%_)))
                                                  (let ((_%$%tl5903759106%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e5903559099%_)))
                                                        (_%$%hd5903659103%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e5903559099%_))))
                                                    (if (gx#stx-null?
                                                         _%$%tl5903759106%_)
                                                        (if (gx#stx-pair/null?
                                                             _%$%tl5894759438%_)
                                                            (let ((_%__splice101019101020%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-split-splice->vector
                            _%$%tl5894759438%_
                            '0)))
                      (let ((_%$%tl5904059112%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%__splice101019101020%_ '1)))
                            (_%$%target5903859109%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%__splice101019101020%_ '0))))
                        (if (gx#stx-null? _%$%tl5904059112%_)
                            (_%__match101287101288%_
                             _%$%e5894259421%_
                             _%$%hd5894359425%_
                             _%$%tl5894459428%_
                             _%$%e5894559431%_
                             _%$%hd5894659435%_
                             _%$%tl5894759438%_
                             _%$%e5894859441%_
                             _%$%hd5894959445%_
                             _%$%tl5895059448%_
                             _%$%e5895159451%_
                             _%$%hd5895259455%_
                             _%$%tl5895359458%_
                             _%$%e5903559099%_
                             _%$%hd5903659103%_
                             _%$%tl5903759106%_
                             _%__splice101019101020%_
                             _%$%target5903859109%_
                             _%$%tl5904059112%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g5887859052%_)))))
                    (let () (declare (not safe)) (_%$%g5887859052%_)))
                (let () (declare (not safe)) (_%$%g5887859052%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5887859052%_))))))
                            (let ()
                              (declare (not safe))
                              (_%$%g5887859052%_)))))
                     (_%__match101111101112%_
                      (lambda (_%$%e5891559541%_
                               _%$%hd5891659545%_
                               _%$%tl5891759548%_
                               _%$%e5891859551%_
                               _%$%hd5891959555%_
                               _%$%tl5892059558%_
                               _%$%e5892159561%_
                               _%$%hd5892259565%_
                               _%$%tl5892359568%_
                               _%$%e5892459571%_
                               _%$%hd5892559575%_
                               _%$%tl5892659578%_
                               _%$%e5892759581%_
                               _%$%hd5892859585%_
                               _%$%tl5892959588%_
                               _%__splice101003101004%_
                               _%$%target5893059591%_
                               _%$%tl5893259594%_)
                        (letrec ((_%$%loop5893359597%_
                                  (lambda (_%$%hd5893159601%_
                                           _%$%body5893759604%_)
                                    (if (gx#stx-pair? _%$%hd5893159601%_)
                                        (let ((_%$%e5893459606%_
                                               (gx#syntax-e
                                                _%$%hd5893159601%_)))
                                          (let ((_%$%lp-tl5893659613%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5893459606%_)))
                                                (_%$%lp-hd5893559610%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5893459606%_))))
                                            (_%$%loop5893359597%_
                                             _%$%lp-tl5893659613%_
                                             (cons _%$%lp-hd5893559610%_
                                                   _%$%body5893759604%_))))
                                        (let ((_%$%body5893859616%_
                                               (reverse _%$%body5893759604%_)))
                                          (let ((_%$%g5891159619%_
                                                 _%$%body5893859616%_)
                                                (_%$%g5891259621%_
                                                 _%$%hd5892859585%_)
                                                (_%$%g5891359622%_
                                                 _%$%hd5892559575%_)
                                                (_%$%g5891459623%_
                                                 _%$%hd5892259565%_))
                                            (if (let ((__tmp107445
                                                       (gx#syntax-local-value
                                                        _%$%g5891259621%_
                                                        false)))
                                                  (declare (not safe))
                                                  (class-instance?
                                                   |gerbil/core/contract~TypeReference[1]#type-reference::t|
                                                   __tmp107445))
                                                (_%__kont101001101002%_
                                                 _%$%g5891159619%_
                                                 _%$%g5891259621%_
                                                 _%$%g5891359622%_
                                                 _%$%g5891459623%_)
                                                (_%__match101135101136%_
                                                 _%$%e5891559541%_
                                                 _%$%hd5891659545%_
                                                 _%$%tl5891759548%_
                                                 _%$%e5891859551%_
                                                 _%$%hd5891959555%_
                                                 _%$%tl5892059558%_
                                                 _%$%e5892159561%_
                                                 _%$%hd5892259565%_
                                                 _%$%tl5892359568%_
                                                 _%$%e5892459571%_
                                                 _%$%hd5892559575%_
                                                 _%$%tl5892659578%_))))))))
                          (_%$%loop5893359597%_ _%$%target5893059591%_ '()))))
                     (_%__match101071101072%_
                      (lambda (_%$%e5888459694%_
                               _%$%hd5888559698%_
                               _%$%tl5888659701%_
                               _%$%e5888759704%_
                               _%$%hd5888859708%_
                               _%$%tl5888959711%_
                               _%$%e5889059714%_
                               _%$%hd5889159718%_
                               _%$%tl5889259721%_
                               _%$%e5889359724%_
                               _%$%hd5889459728%_
                               _%$%tl5889559731%_
                               _%$%e5889659734%_
                               _%$%hd5889759738%_
                               _%$%tl5889859741%_
                               _%$%e5889959744%_
                               _%$%hd5890059748%_
                               _%$%tl5890159751%_
                               _%__splice100999101000%_
                               _%$%target5890259754%_
                               _%$%tl5890459757%_)
                        (letrec ((_%$%loop5890559760%_
                                  (lambda (_%$%hd5890359764%_
                                           _%$%body5890959767%_)
                                    (if (gx#stx-pair? _%$%hd5890359764%_)
                                        (let ((_%$%e5890659769%_
                                               (gx#syntax-e
                                                _%$%hd5890359764%_)))
                                          (let ((_%$%lp-tl5890859776%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5890659769%_)))
                                                (_%$%lp-hd5890759773%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5890659769%_))))
                                            (_%$%loop5890559760%_
                                             _%$%lp-tl5890859776%_
                                             (cons _%$%lp-hd5890759773%_
                                                   _%$%body5890959767%_))))
                                        (let ((_%$%body5891059779%_
                                               (reverse _%$%body5890959767%_)))
                                          (let ((_%$%g5888059782%_
                                                 _%$%body5891059779%_)
                                                (_%$%g5888159784%_
                                                 _%$%hd5890059748%_)
                                                (_%$%g5888259785%_
                                                 _%$%hd5889759738%_)
                                                (_%$%g5888359786%_
                                                 _%$%hd5889159718%_))
                                            (if (eq? (gx#stx-e
                                                      _%$%g5888159784%_)
                                                     'unchecked:)
                                                (_%__kont100997100998%_
                                                 _%$%g5888059782%_
                                                 _%$%g5888159784%_
                                                 _%$%g5888259785%_
                                                 _%$%g5888359786%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))))))
                          (_%$%loop5890559760%_ _%$%target5890259754%_ '())))))
                (if (gx#stx-pair? _%__stx100994100995%_)
                    (let ((_%$%e5888459694%_
                           (gx#syntax-e _%__stx100994100995%_)))
                      (let ((_%$%tl5888659701%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5888459694%_)))
                            (_%$%hd5888559698%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5888459694%_))))
                        (if (gx#stx-pair? _%$%tl5888659701%_)
                            (let ((_%$%e5888759704%_
                                   (gx#syntax-e _%$%tl5888659701%_)))
                              (let ((_%$%tl5888959711%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e5888759704%_)))
                                    (_%$%hd5888859708%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e5888759704%_))))
                                (if (gx#stx-pair? _%$%hd5888859708%_)
                                    (let ((_%$%e5889059714%_
                                           (gx#syntax-e _%$%hd5888859708%_)))
                                      (let ((_%$%tl5889259721%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e5889059714%_)))
                                            (_%$%hd5889159718%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e5889059714%_))))
                                        (if (gx#stx-pair? _%$%tl5889259721%_)
                                            (let ((_%$%e5889359724%_
                                                   (gx#syntax-e
                                                    _%$%tl5889259721%_)))
                                              (let ((_%$%tl5889559731%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e5889359724%_)))
                                                    (_%$%hd5889459728%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e5889359724%_))))
                                                (if (gx#identifier?
                                                     _%$%hd5889459728%_)
                                                    (if (gx#free-identifier=?
                                                         |gerbil/core/contract~Using[1]#_g107446_|
                                                         _%$%hd5889459728%_)
                                                        (if (gx#stx-pair?
                                                             _%$%tl5889559731%_)
                                                            (let ((_%$%e5889659734%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-e _%$%tl5889559731%_)))
                      (let ((_%$%tl5889859741%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5889659734%_)))
                            (_%$%hd5889759738%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5889659734%_))))
                        (if (gx#stx-pair? _%$%tl5889859741%_)
                            (let ((_%$%e5889959744%_
                                   (gx#syntax-e _%$%tl5889859741%_)))
                              (let ((_%$%tl5890159751%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e5889959744%_)))
                                    (_%$%hd5890059748%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e5889959744%_))))
                                (if (gx#stx-null? _%$%tl5890159751%_)
                                    (if (gx#stx-pair/null? _%$%tl5888959711%_)
                                        (let ((_%__splice100999101000%_
                                               (gx#syntax-split-splice->vector
                                                _%$%tl5888959711%_
                                                '0)))
                                          (let ((_%$%tl5890459757%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice100999101000%_
                                                    '1)))
                                                (_%$%target5890259754%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice100999101000%_
                                                    '0))))
                                            (if (gx#stx-null?
                                                 _%$%tl5890459757%_)
                                                (_%__match101071101072%_
                                                 _%$%e5888459694%_
                                                 _%$%hd5888559698%_
                                                 _%$%tl5888659701%_
                                                 _%$%e5888759704%_
                                                 _%$%hd5888859708%_
                                                 _%$%tl5888959711%_
                                                 _%$%e5889059714%_
                                                 _%$%hd5889159718%_
                                                 _%$%tl5889259721%_
                                                 _%$%e5889359724%_
                                                 _%$%hd5889459728%_
                                                 _%$%tl5889559731%_
                                                 _%$%e5889659734%_
                                                 _%$%hd5889759738%_
                                                 _%$%tl5889859741%_
                                                 _%$%e5889959744%_
                                                 _%$%hd5890059748%_
                                                 _%$%tl5890159751%_
                                                 _%__splice100999101000%_
                                                 _%$%target5890259754%_
                                                 _%$%tl5890459757%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5887859052%_)))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g5887859052%_)))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g5887859052%_)))))
                            (if (gx#stx-null? _%$%tl5889859741%_)
                                (if (gx#stx-pair/null? _%$%tl5888959711%_)
                                    (let ((_%__splice101003101004%_
                                           (gx#syntax-split-splice->vector
                                            _%$%tl5888959711%_
                                            '0)))
                                      (let ((_%$%tl5893259594%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice101003101004%_
                                                '1)))
                                            (_%$%target5893059591%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice101003101004%_
                                                '0))))
                                        (if (gx#stx-null? _%$%tl5893259594%_)
                                            (_%__match101111101112%_
                                             _%$%e5888459694%_
                                             _%$%hd5888559698%_
                                             _%$%tl5888659701%_
                                             _%$%e5888759704%_
                                             _%$%hd5888859708%_
                                             _%$%tl5888959711%_
                                             _%$%e5889059714%_
                                             _%$%hd5889159718%_
                                             _%$%tl5889259721%_
                                             _%$%e5889359724%_
                                             _%$%hd5889459728%_
                                             _%$%tl5889559731%_
                                             _%$%e5889659734%_
                                             _%$%hd5889759738%_
                                             _%$%tl5889859741%_
                                             _%__splice101003101004%_
                                             _%$%target5893059591%_
                                             _%$%tl5893259594%_)
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5887859052%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g5887859052%_)))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5887859052%_))))))
                    (let () (declare (not safe)) (_%$%g5887859052%_)))
                (if (gx#stx-pair? _%$%tl5889559731%_)
                    (let ((_%$%e5892759581%_ (gx#syntax-e _%$%tl5889559731%_)))
                      (let ((_%$%tl5892959588%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5892759581%_)))
                            (_%$%hd5892859585%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5892759581%_))))
                        (if (gx#stx-null? _%$%tl5892959588%_)
                            (if (gx#stx-pair/null? _%$%tl5888959711%_)
                                (let ((_%__splice101003101004%_
                                       (gx#syntax-split-splice->vector
                                        _%$%tl5888959711%_
                                        '0)))
                                  (let ((_%$%tl5893259594%_
                                         (let ()
                                           (declare (not safe))
                                           (##vector-ref
                                            _%__splice101003101004%_
                                            '1)))
                                        (_%$%target5893059591%_
                                         (let ()
                                           (declare (not safe))
                                           (##vector-ref
                                            _%__splice101003101004%_
                                            '0))))
                                    (if (gx#stx-null? _%$%tl5893259594%_)
                                        (_%__match101111101112%_
                                         _%$%e5888459694%_
                                         _%$%hd5888559698%_
                                         _%$%tl5888659701%_
                                         _%$%e5888759704%_
                                         _%$%hd5888859708%_
                                         _%$%tl5888959711%_
                                         _%$%e5889059714%_
                                         _%$%hd5889159718%_
                                         _%$%tl5889259721%_
                                         _%$%e5889359724%_
                                         _%$%hd5889459728%_
                                         _%$%tl5889559731%_
                                         _%$%e5892759581%_
                                         _%$%hd5892859585%_
                                         _%$%tl5892959588%_
                                         _%__splice101003101004%_
                                         _%$%target5893059591%_
                                         _%$%tl5893259594%_)
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g5887859052%_)))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5887859052%_)))
                            (let ()
                              (declare (not safe))
                              (_%$%g5887859052%_)))))
                    (let () (declare (not safe)) (_%$%g5887859052%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (gx#stx-pair?
                                                         _%$%tl5889559731%_)
                                                        (let ((_%$%e5892759581%_
                                                               (gx#syntax-e
                                                                _%$%tl5889559731%_)))
                                                          (let ((_%$%tl5892959588%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e5892759581%_)))
                        (_%$%hd5892859585%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e5892759581%_))))
                    (if (gx#stx-null? _%$%tl5892959588%_)
                        (if (gx#stx-pair/null? _%$%tl5888959711%_)
                            (let ((_%__splice101003101004%_
                                   (gx#syntax-split-splice->vector
                                    _%$%tl5888959711%_
                                    '0)))
                              (let ((_%$%tl5893259594%_
                                     (let ()
                                       (declare (not safe))
                                       (##vector-ref
                                        _%__splice101003101004%_
                                        '1)))
                                    (_%$%target5893059591%_
                                     (let ()
                                       (declare (not safe))
                                       (##vector-ref
                                        _%__splice101003101004%_
                                        '0))))
                                (if (gx#stx-null? _%$%tl5893259594%_)
                                    (_%__match101111101112%_
                                     _%$%e5888459694%_
                                     _%$%hd5888559698%_
                                     _%$%tl5888659701%_
                                     _%$%e5888759704%_
                                     _%$%hd5888859708%_
                                     _%$%tl5888959711%_
                                     _%$%e5889059714%_
                                     _%$%hd5889159718%_
                                     _%$%tl5889259721%_
                                     _%$%e5889359724%_
                                     _%$%hd5889459728%_
                                     _%$%tl5889559731%_
                                     _%$%e5892759581%_
                                     _%$%hd5892859585%_
                                     _%$%tl5892959588%_
                                     _%__splice101003101004%_
                                     _%$%target5893059591%_
                                     _%$%tl5893259594%_)
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g5887859052%_)))))
                            (let () (declare (not safe)) (_%$%g5887859052%_)))
                        (let () (declare (not safe)) (_%$%g5887859052%_)))))
                (let () (declare (not safe)) (_%$%g5887859052%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5887859052%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g5887859052%_)))))
                            (let ()
                              (declare (not safe))
                              (_%$%g5887859052%_)))))
                    (let () (declare (not safe)) (_%$%g5887859052%_)))))))))
    (define |gerbil/core/contract~Using[:0:]#with-interface|
      (lambda (_%stx60174%_)
        (letrec ((_%expand-body60177%_
                  (lambda (_%var61304%_
                           _%Interface61306%_
                           _%body61307%_
                           _%checked?61308%_
                           _%maybe?61309%_)
                    (let* ((_%type61311%_
                            (let ()
                              (declare (not safe))
                              (|gerbil/core/contract~TypeReference[1]#resolve-type|
                               _%stx60174%_
                               _%Interface61306%_)))
                           (_%$%g6131461362%_
                            (lambda (_%$%g6131561358%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%$%g6131561358%_)))
                           (_%$%g6131361532%_
                            (lambda (_%$%g6131561366%_)
                              (if (gx#stx-pair? _%$%g6131561366%_)
                                  (let ((_%$%e6132461369%_
                                         (gx#syntax-e _%$%g6131561366%_)))
                                    (let ((_%$%hd6132561373%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e6132461369%_)))
                                          (_%$%tl6132661376%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e6132461369%_))))
                                      (if (gx#stx-pair? _%$%tl6132661376%_)
                                          (let ((_%$%e6132761379%_
                                                 (gx#syntax-e
                                                  _%$%tl6132661376%_)))
                                            (let ((_%$%hd6132861383%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e6132761379%_)))
                                                  (_%$%tl6132961386%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e6132761379%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl6132961386%_)
                                                  (let ((_%$%e6133061389%_
                                                         (gx#syntax-e
                                                          _%$%tl6132961386%_)))
                                                    (let ((_%$%hd6133161393%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e6133061389%_)))
                                                          (_%$%tl6133261396%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e6133061389%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl6133261396%_)
                                                          (let ((_%$%e6133361399%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl6133261396%_)))
                    (let ((_%$%hd6133461403%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e6133361399%_)))
                          (_%$%tl6133561406%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e6133361399%_))))
                      (if (gx#stx-pair? _%$%tl6133561406%_)
                          (let ((_%$%e6133661409%_
                                 (gx#syntax-e _%$%tl6133561406%_)))
                            (let ((_%$%hd6133761413%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e6133661409%_)))
                                  (_%$%tl6133861416%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e6133661409%_))))
                              (if (gx#stx-pair? _%$%tl6133861416%_)
                                  (let ((_%$%e6133961419%_
                                         (gx#syntax-e _%$%tl6133861416%_)))
                                    (let ((_%$%hd6134061423%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e6133961419%_)))
                                          (_%$%tl6134161426%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e6133961419%_))))
                                      (if (gx#stx-pair? _%$%tl6134161426%_)
                                          (let ((_%$%e6134261429%_
                                                 (gx#syntax-e
                                                  _%$%tl6134161426%_)))
                                            (let ((_%$%hd6134361433%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e6134261429%_)))
                                                  (_%$%tl6134461436%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e6134261429%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl6134461436%_)
                                                  (let ((_%$%e6134561439%_
                                                         (gx#syntax-e
                                                          _%$%tl6134461436%_)))
                                                    (let ((_%$%hd6134661443%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e6134561439%_)))
                                                          (_%$%tl6134761446%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e6134561439%_))))
                                                      (if (gx#stx-pair/null?
                                                           _%$%hd6134661443%_)
                                                          (let ((_g107447_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-split-splice _%$%hd6134661443%_ '0)))
                    (begin
                      (let ((_g107448_
                             (let ()
                               (declare (not safe))
                               (if (##values? _g107447_)
                                   (##values-length _g107447_)
                                   1))))
                        (if (not (let ()
                                   (declare (not safe))
                                   (##fx= _g107448_ 2)))
                            (error "Context expects 2 values" _g107448_)))
                      (let ((_%$%target6134861449%_
                             (let ()
                               (declare (not safe))
                               (##values-ref _g107447_ 0)))
                            (_%$%tl6135061452%_
                             (let ()
                               (declare (not safe))
                               (##values-ref _g107447_ 1))))
                        (if (gx#stx-null? _%$%tl6135061452%_)
                            (letrec ((_%$%loop6135161455%_
                                      (lambda (_%$%hd6134961459%_
                                               _%$%body6135561462%_)
                                        (if (gx#stx-pair? _%$%hd6134961459%_)
                                            (let ((_%$%e6135261464%_
                                                   (gx#syntax-e
                                                    _%$%hd6134961459%_)))
                                              (let ((_%$%lp-hd6135361468%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e6135261464%_)))
                                                    (_%$%lp-tl6135461471%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e6135261464%_))))
                                                (_%$%loop6135161455%_
                                                 _%$%lp-tl6135461471%_
                                                 (cons _%$%lp-hd6135361468%_
                                                       _%$%body6135561462%_))))
                                            (let ((_%$%body6135661474%_
                                                   (reverse _%$%body6135561462%_)))
                                              (if (gx#stx-null?
                                                   _%$%tl6134761446%_)
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'let)
                                                        (cons (cons _%$%hd6133461403%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons (cons (gx#datum->syntax
                                         '#f
                                         'begin-annotation)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     '@type)
                                                    (cons _%$%hd6133161393%_
                                                          '()))
                                              (cons _%$%hd6133461403%_ '())))
                                  '()))
                      (cons (cons (gx#datum->syntax '#f 'let-syntax)
                                  (cons (cons (cons _%$%hd6132561373%_
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'make-type-env)
                        (cons (cons (gx#datum->syntax '#f 'quote-syntax)
                                    (cons _%$%hd6133461403%_ '()))
                              (cons (cons (gx#datum->syntax '#f 'quote)
                                          (cons _%$%hd6132861383%_ '()))
                                    (cons _%$%hd6133761413%_
                                          (cons _%$%hd6134061423%_
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'quote)
                                                            (cons _%$%hd6134361433%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())
                                        (cons (cons (gx#datum->syntax '#f 'let)
                                                    (cons '()
                                                          (foldr (lambda (_%$%g6152361526%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  _%$%g6152461529%_)
                           (cons _%$%g6152361526%_ _%$%g6152461529%_))
                         '()
                         _%$%body6135661474%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g6131461362%_
                                                   _%$%g6131561366%_)))))))
                              (_%$%loop6135161455%_
                               _%$%target6134861449%_
                               '()))
                            (_%$%g6131461362%_ _%$%g6131561366%_)))))
                  (_%$%g6131461362%_ _%$%g6131561366%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g6131461362%_
                                                   _%$%g6131561366%_))))
                                          (_%$%g6131461362%_
                                           _%$%g6131561366%_))))
                                  (_%$%g6131461362%_ _%$%g6131561366%_))))
                          (_%$%g6131461362%_ _%$%g6131561366%_))))
                  (_%$%g6131461362%_ _%$%g6131561366%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g6131461362%_
                                                   _%$%g6131561366%_))))
                                          (_%$%g6131461362%_
                                           _%$%g6131561366%_))))
                                  (_%$%g6131461362%_ _%$%g6131561366%_)))))
                      (_%$%g6131361532%_
                       (list (gx#syntax-local-introduce '@@type)
                             _%type61311%_
                             (if _%maybe?61309%_
                                 (cons 'nullable
                                       (cons (let ((__obj107230 _%type61311%_))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (##structure-direct-instance-of?
                                                      __obj107230
                                                      'gerbil/core#runtime-type-info::t))
                                                   (let ()
                                                     (declare (not safe))
                                                     (##unchecked-structure-ref
                                                      __obj107230
                                                      '3
                                                      '#f
                                                      '#f))
                                                   (class-slot-ref
                                                    gerbil/core/mop~MOP-2#runtime-type-info::t
                                                    __obj107230
                                                    'type-descriptor)))
                                             '()))
                                 (let ((__obj107229 _%type61311%_))
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-direct-instance-of?
                                          __obj107229
                                          'gerbil/core#runtime-type-info::t))
                                       (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          __obj107229
                                          '3
                                          '#f
                                          '#f))
                                       (class-slot-ref
                                        gerbil/core/mop~MOP-2#runtime-type-info::t
                                        __obj107229
                                        'type-descriptor))))
                             _%var61304%_
                             _%checked?61308%_
                             _%maybe?61309%_
                             (let ()
                               (declare (not safe))
                               (gerbil/core/contract~TypeEnv#current-type-env))
                             _%body61307%_)))))
                 (_%expand60179%_
                  (lambda (_%var61133%_
                           _%Interface61135%_
                           _%body61136%_
                           _%checked?61137%_
                           _%checked-methods?61138%_
                           _%maybe?61139%_)
                    (let* ((_%$%g6114161149%_
                            (lambda (_%$%g6114261145%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%$%g6114261145%_)))
                           (_%$%g6114061296%_
                            (lambda (_%$%g6114261153%_)
                              (if _%checked?61137%_
                                  (if _%maybe?61139%_
                                      (let* ((_%$%g6116861183%_
                                              (lambda (_%$%g6116961179%_)
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Bad syntax; invalid match target"
                                                 _%$%g6116961179%_)))
                                             (_%$%g6116761229%_
                                              (lambda (_%$%g6116961187%_)
                                                (if (gx#stx-pair?
                                                     _%$%g6116961187%_)
                                                    (let ((_%$%e6117261190%_
                                                           (gx#syntax-e
                                                            _%$%g6116961187%_)))
                                                      (let ((_%$%hd6117361194%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e6117261190%_)))
                    (_%$%tl6117461197%_
                     (let () (declare (not safe)) (##cdr _%$%e6117261190%_))))
                (if (gx#stx-pair? _%$%tl6117461197%_)
                    (let ((_%$%e6117561200%_ (gx#syntax-e _%$%tl6117461197%_)))
                      (let ((_%$%hd6117661204%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6117561200%_)))
                            (_%$%tl6117761207%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6117561200%_))))
                        (if (gx#stx-null? _%$%tl6117761207%_)
                            (cons (gx#datum->syntax '#f 'let)
                                  (cons (cons _%$%hd6117361194%_
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'and)
                                                          (cons _%$%hd6117361194%_
                                                                (cons (cons _%$%hd6117661204%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    (cons _%$%hd6117361194%_ '()))
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '()))
                                        (cons _%$%g6114261153%_ '())))
                            (_%$%g6116861183%_ _%$%g6116961187%_))))
                    (_%$%g6116861183%_ _%$%g6116961187%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g6116861183%_
                                                     _%$%g6116961187%_)))))
                                        (_%$%g6116761229%_
                                         (list _%var61133%_
                                               _%Interface61135%_)))
                                      (let* ((_%$%g6123361248%_
                                              (lambda (_%$%g6123461244%_)
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Bad syntax; invalid match target"
                                                 _%$%g6123461244%_)))
                                             (_%$%g6123261292%_
                                              (lambda (_%$%g6123461252%_)
                                                (if (gx#stx-pair?
                                                     _%$%g6123461252%_)
                                                    (let ((_%$%e6123761255%_
                                                           (gx#syntax-e
                                                            _%$%g6123461252%_)))
                                                      (let ((_%$%hd6123861259%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e6123761255%_)))
                    (_%$%tl6123961262%_
                     (let () (declare (not safe)) (##cdr _%$%e6123761255%_))))
                (if (gx#stx-pair? _%$%tl6123961262%_)
                    (let ((_%$%e6124061265%_ (gx#syntax-e _%$%tl6123961262%_)))
                      (let ((_%$%hd6124161269%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6124061265%_)))
                            (_%$%tl6124261272%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6124061265%_))))
                        (if (gx#stx-null? _%$%tl6124261272%_)
                            (cons (gx#datum->syntax '#f 'let)
                                  (cons (cons _%$%hd6123861259%_
                                              (cons (cons _%$%hd6124161269%_
                                                          (cons _%$%hd6123861259%_
                                                                '()))
                                                    '()))
                                        (cons _%$%g6114261153%_ '())))
                            (_%$%g6123361248%_ _%$%g6123461252%_))))
                    (_%$%g6123361248%_ _%$%g6123461252%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g6123361248%_
                                                     _%$%g6123461252%_)))))
                                        (_%$%g6123261292%_
                                         (list _%var61133%_
                                               _%Interface61135%_))))
                                  _%$%g6114261153%_))))
                      (_%$%g6114061296%_
                       (_%expand-body60177%_
                        _%var61133%_
                        _%Interface61135%_
                        _%body61136%_
                        (let ((_%$e61300%_ _%checked?61137%_))
                          (if _%$e61300%_
                              _%$e61300%_
                              _%checked-methods?61138%_))
                        _%maybe?61139%_))))))
          (let* ((_%__stx101290101291%_ _%stx60174%_)
                 (_%$%g6018660360%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx101290101291%_))))
            (let ((_%__kont101293101294%_
                   (lambda (_%$%g6018861090%_
                            _%$%g6018961092%_
                            _%$%g6019061093%_
                            _%$%g6019161094%_)
                     (_%expand60179%_
                      _%$%g6019161094%_
                      (let ()
                        (declare (not safe))
                        (|gerbil/core/contract~TypeReference[1]#resolve-type->identifier|
                         _%stx60174%_
                         _%$%g6019061093%_))
                      (foldr (lambda (_%$%g6112061123%_ _%$%g6112161126%_)
                               (cons _%$%g6112061123%_ _%$%g6112161126%_))
                             '()
                             _%$%g6018861090%_)
                      '#f
                      '#t
                      '#t)))
                  (_%__kont101297101298%_
                   (lambda (_%$%g6021960927%_
                            _%$%g6022060929%_
                            _%$%g6022160930%_
                            _%$%g6022260931%_)
                     (let* ((_%$%g6095660964%_
                             (lambda (_%$%g6095760960%_)
                               (gx#raise-syntax-error
                                '#f
                                '"Bad syntax; invalid match target"
                                _%$%g6095760960%_)))
                            (_%$%g6095560991%_
                             (lambda (_%$%g6095760968%_)
                               (cons (gx#datum->syntax '#f 'with-interface)
                                     (cons (cons _%$%g6022260931%_
                                                 (cons _%$%g6022160930%_
                                                       (cons _%$%g6095760968%_
                                                             '())))
                                           (foldr (lambda (_%$%g6098260985%_
                                                           _%$%g6098360988%_)
                                                    (cons _%$%g6098260985%_
                                                          _%$%g6098360988%_))
                                                  '()
                                                  _%$%g6021960927%_))))))
                       (_%$%g6095560991%_
                        (let ((__obj107231
                               (gx#syntax-local-value _%$%g6022060929%_)))
                          (if (let ()
                                (declare (not safe))
                                (##structure-direct-instance-of?
                                 __obj107231
                                 'gerbil/core/contract~TypeReference#type-reference::t))
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 __obj107231
                                 '1
                                 '#f
                                 '#f))
                              (class-slot-ref
                               |gerbil/core/contract~TypeReference[1]#type-reference::t|
                               __obj107231
                               'identifier)))))))
                  (_%__kont101301101302%_
                   (lambda (_%$%g6024760807%_
                            _%$%g6024860809%_
                            _%$%g6024960810%_)
                     (_%expand60179%_
                      _%$%g6024960810%_
                      _%$%g6024860809%_
                      (foldr (lambda (_%$%g6083360836%_ _%$%g6083460839%_)
                               (cons _%$%g6083360836%_ _%$%g6083460839%_))
                             '()
                             _%$%g6024760807%_)
                      '#t
                      '#t
                      '#f)))
                  (_%__kont101305101306%_
                   (lambda (_%$%g6027460687%_
                            _%$%g6027560689%_
                            _%$%g6027660690%_)
                     (_%expand60179%_
                      _%$%g6027660690%_
                      _%$%g6027560689%_
                      (foldr (lambda (_%$%g6071360716%_ _%$%g6071460719%_)
                               (cons _%$%g6071360716%_ _%$%g6071460719%_))
                             '()
                             _%$%g6027460687%_)
                      '#t
                      '#t
                      '#t)))
                  (_%__kont101309101310%_
                   (lambda (_%$%g6030160567%_
                            _%$%g6030260569%_
                            _%$%g6030360570%_)
                     (_%expand60179%_
                      _%$%g6030360570%_
                      _%$%g6030260569%_
                      (foldr (lambda (_%$%g6059360596%_ _%$%g6059460599%_)
                               (cons _%$%g6059360596%_ _%$%g6059460599%_))
                             '()
                             _%$%g6030160567%_)
                      '#f
                      '#f
                      '#f)))
                  (_%__kont101313101314%_
                   (lambda (_%$%g6032860445%_
                            _%$%g6032960447%_
                            _%$%g6033060448%_)
                     (_%expand60179%_
                      _%$%g6033060448%_
                      _%$%g6032960447%_
                      (foldr (lambda (_%$%g6047360476%_ _%$%g6047460479%_)
                               (cons _%$%g6047360476%_ _%$%g6047460479%_))
                             '()
                             _%$%g6032860445%_)
                      '#f
                      '#t
                      '#f))))
              (let* ((_%__match101583101584%_
                      (lambda (_%$%e6033160367%_
                               _%$%hd6033260371%_
                               _%$%tl6033360374%_
                               _%$%e6033460377%_
                               _%$%hd6033560381%_
                               _%$%tl6033660384%_
                               _%$%e6033760387%_
                               _%$%hd6033860391%_
                               _%$%tl6033960394%_
                               _%$%e6034060397%_
                               _%$%hd6034160401%_
                               _%$%tl6034260404%_
                               _%$%e6034360407%_
                               _%$%hd6034460411%_
                               _%$%tl6034560414%_
                               _%__splice101315101316%_
                               _%$%target6034660417%_
                               _%$%tl6034860420%_)
                        (letrec ((_%$%loop6034960423%_
                                  (lambda (_%$%hd6034760427%_
                                           _%$%body6035360430%_)
                                    (if (gx#stx-pair? _%$%hd6034760427%_)
                                        (let ((_%$%e6035060432%_
                                               (gx#syntax-e
                                                _%$%hd6034760427%_)))
                                          (let ((_%$%lp-tl6035260439%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6035060432%_)))
                                                (_%$%lp-hd6035160436%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6035060432%_))))
                                            (_%$%loop6034960423%_
                                             _%$%lp-tl6035260439%_
                                             (cons _%$%lp-hd6035160436%_
                                                   _%$%body6035360430%_))))
                                        (let ((_%$%body6035460442%_
                                               (reverse _%$%body6035360430%_)))
                                          (let ((_%$%g6032860445%_
                                                 _%$%body6035460442%_)
                                                (_%$%g6032960447%_
                                                 _%$%hd6034460411%_)
                                                (_%$%g6033060448%_
                                                 _%$%hd6033860391%_))
                                            (if (and (gx#identifier?
                                                      _%$%g6033060448%_)
                                                     (let ()
                                                       (declare (not safe))
                                                       (gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__0
                                                        _%$%g6032960447%_)))
                                                (_%__kont101313101314%_
                                                 _%$%g6032860445%_
                                                 _%$%g6032960447%_
                                                 _%$%g6033060448%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))))))
                          (_%$%loop6034960423%_ _%$%target6034660417%_ '()))))
                     (_%__match101539101540%_
                      (lambda (_%$%e6030460489%_
                               _%$%hd6030560493%_
                               _%$%tl6030660496%_
                               _%$%e6030760499%_
                               _%$%hd6030860503%_
                               _%$%tl6030960506%_
                               _%$%e6031060509%_
                               _%$%hd6031160513%_
                               _%$%tl6031260516%_
                               _%$%e6031360519%_
                               _%$%hd6031460523%_
                               _%$%tl6031560526%_
                               _%$%e6031660529%_
                               _%$%hd6031760533%_
                               _%$%tl6031860536%_
                               _%__splice101311101312%_
                               _%$%target6031960539%_
                               _%$%tl6032160542%_)
                        (letrec ((_%$%loop6032260545%_
                                  (lambda (_%$%hd6032060549%_
                                           _%$%body6032660552%_)
                                    (if (gx#stx-pair? _%$%hd6032060549%_)
                                        (let ((_%$%e6032360554%_
                                               (gx#syntax-e
                                                _%$%hd6032060549%_)))
                                          (let ((_%$%lp-tl6032560561%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6032360554%_)))
                                                (_%$%lp-hd6032460558%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6032360554%_))))
                                            (_%$%loop6032260545%_
                                             _%$%lp-tl6032560561%_
                                             (cons _%$%lp-hd6032460558%_
                                                   _%$%body6032660552%_))))
                                        (let ((_%$%body6032760564%_
                                               (reverse _%$%body6032660552%_)))
                                          (let ((_%$%g6030160567%_
                                                 _%$%body6032760564%_)
                                                (_%$%g6030260569%_
                                                 _%$%hd6031760533%_)
                                                (_%$%g6030360570%_
                                                 _%$%hd6031160513%_))
                                            (if (and (gx#identifier?
                                                      _%$%g6030360570%_)
                                                     (let ()
                                                       (declare (not safe))
                                                       (gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__0
                                                        _%$%g6030260569%_)))
                                                (_%__kont101309101310%_
                                                 _%$%g6030160567%_
                                                 _%$%g6030260569%_
                                                 _%$%g6030360570%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))))))
                          (_%$%loop6032260545%_ _%$%target6031960539%_ '()))))
                     (_%__match101495101496%_
                      (lambda (_%$%e6027760609%_
                               _%$%hd6027860613%_
                               _%$%tl6027960616%_
                               _%$%e6028060619%_
                               _%$%hd6028160623%_
                               _%$%tl6028260626%_
                               _%$%e6028360629%_
                               _%$%hd6028460633%_
                               _%$%tl6028560636%_
                               _%$%e6028660639%_
                               _%$%hd6028760643%_
                               _%$%tl6028860646%_
                               _%$%e6028960649%_
                               _%$%hd6029060653%_
                               _%$%tl6029160656%_
                               _%__splice101307101308%_
                               _%$%target6029260659%_
                               _%$%tl6029460662%_)
                        (letrec ((_%$%loop6029560665%_
                                  (lambda (_%$%hd6029360669%_
                                           _%$%body6029960672%_)
                                    (if (gx#stx-pair? _%$%hd6029360669%_)
                                        (let ((_%$%e6029660674%_
                                               (gx#syntax-e
                                                _%$%hd6029360669%_)))
                                          (let ((_%$%lp-tl6029860681%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6029660674%_)))
                                                (_%$%lp-hd6029760678%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6029660674%_))))
                                            (_%$%loop6029560665%_
                                             _%$%lp-tl6029860681%_
                                             (cons _%$%lp-hd6029760678%_
                                                   _%$%body6029960672%_))))
                                        (let ((_%$%body6030060684%_
                                               (reverse _%$%body6029960672%_)))
                                          (let ((_%$%g6027460687%_
                                                 _%$%body6030060684%_)
                                                (_%$%g6027560689%_
                                                 _%$%hd6029060653%_)
                                                (_%$%g6027660690%_
                                                 _%$%hd6028460633%_))
                                            (if (and (gx#identifier?
                                                      _%$%g6027660690%_)
                                                     (let ()
                                                       (declare (not safe))
                                                       (gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__0
                                                        _%$%g6027560689%_)))
                                                (_%__kont101305101306%_
                                                 _%$%g6027460687%_
                                                 _%$%g6027560689%_
                                                 _%$%g6027660690%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))))))
                          (_%$%loop6029560665%_ _%$%target6029260659%_ '()))))
                     (_%__match101451101452%_
                      (lambda (_%$%e6025060729%_
                               _%$%hd6025160733%_
                               _%$%tl6025260736%_
                               _%$%e6025360739%_
                               _%$%hd6025460743%_
                               _%$%tl6025560746%_
                               _%$%e6025660749%_
                               _%$%hd6025760753%_
                               _%$%tl6025860756%_
                               _%$%e6025960759%_
                               _%$%hd6026060763%_
                               _%$%tl6026160766%_
                               _%$%e6026260769%_
                               _%$%hd6026360773%_
                               _%$%tl6026460776%_
                               _%__splice101303101304%_
                               _%$%target6026560779%_
                               _%$%tl6026760782%_)
                        (letrec ((_%$%loop6026860785%_
                                  (lambda (_%$%hd6026660789%_
                                           _%$%body6027260792%_)
                                    (if (gx#stx-pair? _%$%hd6026660789%_)
                                        (let ((_%$%e6026960794%_
                                               (gx#syntax-e
                                                _%$%hd6026660789%_)))
                                          (let ((_%$%lp-tl6027160801%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6026960794%_)))
                                                (_%$%lp-hd6027060798%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6026960794%_))))
                                            (_%$%loop6026860785%_
                                             _%$%lp-tl6027160801%_
                                             (cons _%$%lp-hd6027060798%_
                                                   _%$%body6027260792%_))))
                                        (let ((_%$%body6027360804%_
                                               (reverse _%$%body6027260792%_)))
                                          (let ((_%$%g6024760807%_
                                                 _%$%body6027360804%_)
                                                (_%$%g6024860809%_
                                                 _%$%hd6026360773%_)
                                                (_%$%g6024960810%_
                                                 _%$%hd6025760753%_))
                                            (if (and (gx#identifier?
                                                      _%$%g6024960810%_)
                                                     (let ()
                                                       (declare (not safe))
                                                       (gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__0
                                                        _%$%g6024860809%_)))
                                                (_%__kont101301101302%_
                                                 _%$%g6024760807%_
                                                 _%$%g6024860809%_
                                                 _%$%g6024960810%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))))))
                          (_%$%loop6026860785%_ _%$%target6026560779%_ '()))))
                     (_%__match101431101432%_
                      (lambda (_%$%e6025060729%_
                               _%$%hd6025160733%_
                               _%$%tl6025260736%_
                               _%$%e6025360739%_
                               _%$%hd6025460743%_
                               _%$%tl6025560746%_
                               _%$%e6025660749%_
                               _%$%hd6025760753%_
                               _%$%tl6025860756%_
                               _%$%e6025960759%_
                               _%$%hd6026060763%_
                               _%$%tl6026160766%_)
                        (if (gx#identifier? _%$%hd6026060763%_)
                            (if (gx#free-identifier=?
                                 |gerbil/core/contract~Using[1]#_g107449_|
                                 _%$%hd6026060763%_)
                                (if (gx#stx-pair? _%$%tl6026160766%_)
                                    (let ((_%$%e6026260769%_
                                           (gx#syntax-e _%$%tl6026160766%_)))
                                      (let ((_%$%tl6026460776%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e6026260769%_)))
                                            (_%$%hd6026360773%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e6026260769%_))))
                                        (if (gx#stx-null? _%$%tl6026460776%_)
                                            (if (gx#stx-pair/null?
                                                 _%$%tl6025560746%_)
                                                (let ((_%__splice101303101304%_
                                                       (gx#syntax-split-splice->vector
                                                        _%$%tl6025560746%_
                                                        '0)))
                                                  (let ((_%$%tl6026760782%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##vector-ref
                                                            _%__splice101303101304%_
                                                            '1)))
                                                        (_%$%target6026560779%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##vector-ref
                                                            _%__splice101303101304%_
                                                            '0))))
                                                    (if (gx#stx-null?
                                                         _%$%tl6026760782%_)
                                                        (_%__match101451101452%_
                                                         _%$%e6025060729%_
                                                         _%$%hd6025160733%_
                                                         _%$%tl6025260736%_
                                                         _%$%e6025360739%_
                                                         _%$%hd6025460743%_
                                                         _%$%tl6025560746%_
                                                         _%$%e6025660749%_
                                                         _%$%hd6025760753%_
                                                         _%$%tl6025860756%_
                                                         _%$%e6025960759%_
                                                         _%$%hd6026060763%_
                                                         _%$%tl6026160766%_
                                                         _%$%e6026260769%_
                                                         _%$%hd6026360773%_
                                                         _%$%tl6026460776%_
                                                         _%__splice101303101304%_
                                                         _%$%target6026560779%_
                                                         _%$%tl6026760782%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g6018660360%_)))))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g6018660360%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g6018660360%_)))
                                (if (gx#free-identifier=?
                                     |gerbil/core/contract~Using[1]#_g107450_|
                                     _%$%hd6026060763%_)
                                    (if (gx#stx-pair? _%$%tl6026160766%_)
                                        (let ((_%$%e6028960649%_
                                               (gx#syntax-e
                                                _%$%tl6026160766%_)))
                                          (let ((_%$%tl6029160656%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6028960649%_)))
                                                (_%$%hd6029060653%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6028960649%_))))
                                            (if (gx#stx-null?
                                                 _%$%tl6029160656%_)
                                                (if (gx#stx-pair/null?
                                                     _%$%tl6025560746%_)
                                                    (let ((_%__splice101307101308%_
                                                           (gx#syntax-split-splice->vector
                                                            _%$%tl6025560746%_
                                                            '0)))
                                                      (let ((_%$%tl6029460662%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##vector-ref _%__splice101307101308%_ '1)))
                    (_%$%target6029260659%_
                     (let ()
                       (declare (not safe))
                       (##vector-ref _%__splice101307101308%_ '0))))
                (if (gx#stx-null? _%$%tl6029460662%_)
                    (_%__match101495101496%_
                     _%$%e6025060729%_
                     _%$%hd6025160733%_
                     _%$%tl6025260736%_
                     _%$%e6025360739%_
                     _%$%hd6025460743%_
                     _%$%tl6025560746%_
                     _%$%e6025660749%_
                     _%$%hd6025760753%_
                     _%$%tl6025860756%_
                     _%$%e6025960759%_
                     _%$%hd6026060763%_
                     _%$%tl6026160766%_
                     _%$%e6028960649%_
                     _%$%hd6029060653%_
                     _%$%tl6029160656%_
                     _%__splice101307101308%_
                     _%$%target6029260659%_
                     _%$%tl6029460662%_)
                    (let () (declare (not safe)) (_%$%g6018660360%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g6018660360%_)))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g6018660360%_)))
                                    (if (gx#free-identifier=?
                                         |gerbil/core/contract~Using[1]#_g107451_|
                                         _%$%hd6026060763%_)
                                        (if (gx#stx-pair? _%$%tl6026160766%_)
                                            (let ((_%$%e6031660529%_
                                                   (gx#syntax-e
                                                    _%$%tl6026160766%_)))
                                              (let ((_%$%tl6031860536%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e6031660529%_)))
                                                    (_%$%hd6031760533%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e6031660529%_))))
                                                (if (gx#stx-null?
                                                     _%$%tl6031860536%_)
                                                    (if (gx#stx-pair/null?
                                                         _%$%tl6025560746%_)
                                                        (let ((_%__splice101311101312%_
                                                               (gx#syntax-split-splice->vector
                                                                _%$%tl6025560746%_
                                                                '0)))
                                                          (let ((_%$%tl6032160542%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice101311101312%_ '1)))
                        (_%$%target6031960539%_
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice101311101312%_ '0))))
                    (if (gx#stx-null? _%$%tl6032160542%_)
                        (_%__match101539101540%_
                         _%$%e6025060729%_
                         _%$%hd6025160733%_
                         _%$%tl6025260736%_
                         _%$%e6025360739%_
                         _%$%hd6025460743%_
                         _%$%tl6025560746%_
                         _%$%e6025660749%_
                         _%$%hd6025760753%_
                         _%$%tl6025860756%_
                         _%$%e6025960759%_
                         _%$%hd6026060763%_
                         _%$%tl6026160766%_
                         _%$%e6031660529%_
                         _%$%hd6031760533%_
                         _%$%tl6031860536%_
                         _%__splice101311101312%_
                         _%$%target6031960539%_
                         _%$%tl6032160542%_)
                        (let () (declare (not safe)) (_%$%g6018660360%_)))))
                (let () (declare (not safe)) (_%$%g6018660360%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g6018660360%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g6018660360%_)))
                                        (if (gx#free-identifier=?
                                             |gerbil/core/contract~Using[1]#_g107452_|
                                             _%$%hd6026060763%_)
                                            (if (gx#stx-pair?
                                                 _%$%tl6026160766%_)
                                                (let ((_%$%e6034360407%_
                                                       (gx#syntax-e
                                                        _%$%tl6026160766%_)))
                                                  (let ((_%$%tl6034560414%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e6034360407%_)))
                                                        (_%$%hd6034460411%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e6034360407%_))))
                                                    (if (gx#stx-null?
                                                         _%$%tl6034560414%_)
                                                        (if (gx#stx-pair/null?
                                                             _%$%tl6025560746%_)
                                                            (let ((_%__splice101315101316%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-split-splice->vector
                            _%$%tl6025560746%_
                            '0)))
                      (let ((_%$%tl6034860420%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%__splice101315101316%_ '1)))
                            (_%$%target6034660417%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%__splice101315101316%_ '0))))
                        (if (gx#stx-null? _%$%tl6034860420%_)
                            (_%__match101583101584%_
                             _%$%e6025060729%_
                             _%$%hd6025160733%_
                             _%$%tl6025260736%_
                             _%$%e6025360739%_
                             _%$%hd6025460743%_
                             _%$%tl6025560746%_
                             _%$%e6025660749%_
                             _%$%hd6025760753%_
                             _%$%tl6025860756%_
                             _%$%e6025960759%_
                             _%$%hd6026060763%_
                             _%$%tl6026160766%_
                             _%$%e6034360407%_
                             _%$%hd6034460411%_
                             _%$%tl6034560414%_
                             _%__splice101315101316%_
                             _%$%target6034660417%_
                             _%$%tl6034860420%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g6018660360%_)))))
                    (let () (declare (not safe)) (_%$%g6018660360%_)))
                (let () (declare (not safe)) (_%$%g6018660360%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g6018660360%_))))))
                            (let ()
                              (declare (not safe))
                              (_%$%g6018660360%_)))))
                     (_%__match101407101408%_
                      (lambda (_%$%e6022360849%_
                               _%$%hd6022460853%_
                               _%$%tl6022560856%_
                               _%$%e6022660859%_
                               _%$%hd6022760863%_
                               _%$%tl6022860866%_
                               _%$%e6022960869%_
                               _%$%hd6023060873%_
                               _%$%tl6023160876%_
                               _%$%e6023260879%_
                               _%$%hd6023360883%_
                               _%$%tl6023460886%_
                               _%$%e6023560889%_
                               _%$%hd6023660893%_
                               _%$%tl6023760896%_
                               _%__splice101299101300%_
                               _%$%target6023860899%_
                               _%$%tl6024060902%_)
                        (letrec ((_%$%loop6024160905%_
                                  (lambda (_%$%hd6023960909%_
                                           _%$%body6024560912%_)
                                    (if (gx#stx-pair? _%$%hd6023960909%_)
                                        (let ((_%$%e6024260914%_
                                               (gx#syntax-e
                                                _%$%hd6023960909%_)))
                                          (let ((_%$%lp-tl6024460921%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6024260914%_)))
                                                (_%$%lp-hd6024360918%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6024260914%_))))
                                            (_%$%loop6024160905%_
                                             _%$%lp-tl6024460921%_
                                             (cons _%$%lp-hd6024360918%_
                                                   _%$%body6024560912%_))))
                                        (let ((_%$%body6024660924%_
                                               (reverse _%$%body6024560912%_)))
                                          (let ((_%$%g6021960927%_
                                                 _%$%body6024660924%_)
                                                (_%$%g6022060929%_
                                                 _%$%hd6023660893%_)
                                                (_%$%g6022160930%_
                                                 _%$%hd6023360883%_)
                                                (_%$%g6022260931%_
                                                 _%$%hd6023060873%_))
                                            (if (let ((__tmp107453
                                                       (gx#syntax-local-value
                                                        _%$%g6022060929%_
                                                        false)))
                                                  (declare (not safe))
                                                  (class-instance?
                                                   |gerbil/core/contract~TypeReference[1]#type-reference::t|
                                                   __tmp107453))
                                                (_%__kont101297101298%_
                                                 _%$%g6021960927%_
                                                 _%$%g6022060929%_
                                                 _%$%g6022160930%_
                                                 _%$%g6022260931%_)
                                                (_%__match101431101432%_
                                                 _%$%e6022360849%_
                                                 _%$%hd6022460853%_
                                                 _%$%tl6022560856%_
                                                 _%$%e6022660859%_
                                                 _%$%hd6022760863%_
                                                 _%$%tl6022860866%_
                                                 _%$%e6022960869%_
                                                 _%$%hd6023060873%_
                                                 _%$%tl6023160876%_
                                                 _%$%e6023260879%_
                                                 _%$%hd6023360883%_
                                                 _%$%tl6023460886%_))))))))
                          (_%$%loop6024160905%_ _%$%target6023860899%_ '()))))
                     (_%__match101367101368%_
                      (lambda (_%$%e6019261002%_
                               _%$%hd6019361006%_
                               _%$%tl6019461009%_
                               _%$%e6019561012%_
                               _%$%hd6019661016%_
                               _%$%tl6019761019%_
                               _%$%e6019861022%_
                               _%$%hd6019961026%_
                               _%$%tl6020061029%_
                               _%$%e6020161032%_
                               _%$%hd6020261036%_
                               _%$%tl6020361039%_
                               _%$%e6020461042%_
                               _%$%hd6020561046%_
                               _%$%tl6020661049%_
                               _%$%e6020761052%_
                               _%$%hd6020861056%_
                               _%$%tl6020961059%_
                               _%__splice101295101296%_
                               _%$%target6021061062%_
                               _%$%tl6021261065%_)
                        (letrec ((_%$%loop6021361068%_
                                  (lambda (_%$%hd6021161072%_
                                           _%$%body6021761075%_)
                                    (if (gx#stx-pair? _%$%hd6021161072%_)
                                        (let ((_%$%e6021461077%_
                                               (gx#syntax-e
                                                _%$%hd6021161072%_)))
                                          (let ((_%$%lp-tl6021661084%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e6021461077%_)))
                                                (_%$%lp-hd6021561081%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e6021461077%_))))
                                            (_%$%loop6021361068%_
                                             _%$%lp-tl6021661084%_
                                             (cons _%$%lp-hd6021561081%_
                                                   _%$%body6021761075%_))))
                                        (let ((_%$%body6021861087%_
                                               (reverse _%$%body6021761075%_)))
                                          (let ((_%$%g6018861090%_
                                                 _%$%body6021861087%_)
                                                (_%$%g6018961092%_
                                                 _%$%hd6020861056%_)
                                                (_%$%g6019061093%_
                                                 _%$%hd6020561046%_)
                                                (_%$%g6019161094%_
                                                 _%$%hd6019961026%_))
                                            (if (eq? (gx#stx-e
                                                      _%$%g6018961092%_)
                                                     'unchecked:)
                                                (_%__kont101293101294%_
                                                 _%$%g6018861090%_
                                                 _%$%g6018961092%_
                                                 _%$%g6019061093%_
                                                 _%$%g6019161094%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))))))
                          (_%$%loop6021361068%_ _%$%target6021061062%_ '())))))
                (if (gx#stx-pair? _%__stx101290101291%_)
                    (let ((_%$%e6019261002%_
                           (gx#syntax-e _%__stx101290101291%_)))
                      (let ((_%$%tl6019461009%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6019261002%_)))
                            (_%$%hd6019361006%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6019261002%_))))
                        (if (gx#stx-pair? _%$%tl6019461009%_)
                            (let ((_%$%e6019561012%_
                                   (gx#syntax-e _%$%tl6019461009%_)))
                              (let ((_%$%tl6019761019%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6019561012%_)))
                                    (_%$%hd6019661016%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6019561012%_))))
                                (if (gx#stx-pair? _%$%hd6019661016%_)
                                    (let ((_%$%e6019861022%_
                                           (gx#syntax-e _%$%hd6019661016%_)))
                                      (let ((_%$%tl6020061029%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e6019861022%_)))
                                            (_%$%hd6019961026%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e6019861022%_))))
                                        (if (gx#stx-pair? _%$%tl6020061029%_)
                                            (let ((_%$%e6020161032%_
                                                   (gx#syntax-e
                                                    _%$%tl6020061029%_)))
                                              (let ((_%$%tl6020361039%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e6020161032%_)))
                                                    (_%$%hd6020261036%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e6020161032%_))))
                                                (if (gx#identifier?
                                                     _%$%hd6020261036%_)
                                                    (if (gx#free-identifier=?
                                                         |gerbil/core/contract~Using[1]#_g107454_|
                                                         _%$%hd6020261036%_)
                                                        (if (gx#stx-pair?
                                                             _%$%tl6020361039%_)
                                                            (let ((_%$%e6020461042%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-e _%$%tl6020361039%_)))
                      (let ((_%$%tl6020661049%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6020461042%_)))
                            (_%$%hd6020561046%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6020461042%_))))
                        (if (gx#stx-pair? _%$%tl6020661049%_)
                            (let ((_%$%e6020761052%_
                                   (gx#syntax-e _%$%tl6020661049%_)))
                              (let ((_%$%tl6020961059%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6020761052%_)))
                                    (_%$%hd6020861056%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6020761052%_))))
                                (if (gx#stx-null? _%$%tl6020961059%_)
                                    (if (gx#stx-pair/null? _%$%tl6019761019%_)
                                        (let ((_%__splice101295101296%_
                                               (gx#syntax-split-splice->vector
                                                _%$%tl6019761019%_
                                                '0)))
                                          (let ((_%$%tl6021261065%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice101295101296%_
                                                    '1)))
                                                (_%$%target6021061062%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice101295101296%_
                                                    '0))))
                                            (if (gx#stx-null?
                                                 _%$%tl6021261065%_)
                                                (_%__match101367101368%_
                                                 _%$%e6019261002%_
                                                 _%$%hd6019361006%_
                                                 _%$%tl6019461009%_
                                                 _%$%e6019561012%_
                                                 _%$%hd6019661016%_
                                                 _%$%tl6019761019%_
                                                 _%$%e6019861022%_
                                                 _%$%hd6019961026%_
                                                 _%$%tl6020061029%_
                                                 _%$%e6020161032%_
                                                 _%$%hd6020261036%_
                                                 _%$%tl6020361039%_
                                                 _%$%e6020461042%_
                                                 _%$%hd6020561046%_
                                                 _%$%tl6020661049%_
                                                 _%$%e6020761052%_
                                                 _%$%hd6020861056%_
                                                 _%$%tl6020961059%_
                                                 _%__splice101295101296%_
                                                 _%$%target6021061062%_
                                                 _%$%tl6021261065%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g6018660360%_)))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g6018660360%_)))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g6018660360%_)))))
                            (if (gx#stx-null? _%$%tl6020661049%_)
                                (if (gx#stx-pair/null? _%$%tl6019761019%_)
                                    (let ((_%__splice101299101300%_
                                           (gx#syntax-split-splice->vector
                                            _%$%tl6019761019%_
                                            '0)))
                                      (let ((_%$%tl6024060902%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice101299101300%_
                                                '1)))
                                            (_%$%target6023860899%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice101299101300%_
                                                '0))))
                                        (if (gx#stx-null? _%$%tl6024060902%_)
                                            (_%__match101407101408%_
                                             _%$%e6019261002%_
                                             _%$%hd6019361006%_
                                             _%$%tl6019461009%_
                                             _%$%e6019561012%_
                                             _%$%hd6019661016%_
                                             _%$%tl6019761019%_
                                             _%$%e6019861022%_
                                             _%$%hd6019961026%_
                                             _%$%tl6020061029%_
                                             _%$%e6020161032%_
                                             _%$%hd6020261036%_
                                             _%$%tl6020361039%_
                                             _%$%e6020461042%_
                                             _%$%hd6020561046%_
                                             _%$%tl6020661049%_
                                             _%__splice101299101300%_
                                             _%$%target6023860899%_
                                             _%$%tl6024060902%_)
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g6018660360%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g6018660360%_)))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g6018660360%_))))))
                    (let () (declare (not safe)) (_%$%g6018660360%_)))
                (if (gx#stx-pair? _%$%tl6020361039%_)
                    (let ((_%$%e6023560889%_ (gx#syntax-e _%$%tl6020361039%_)))
                      (let ((_%$%tl6023760896%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6023560889%_)))
                            (_%$%hd6023660893%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6023560889%_))))
                        (if (gx#stx-null? _%$%tl6023760896%_)
                            (if (gx#stx-pair/null? _%$%tl6019761019%_)
                                (let ((_%__splice101299101300%_
                                       (gx#syntax-split-splice->vector
                                        _%$%tl6019761019%_
                                        '0)))
                                  (let ((_%$%tl6024060902%_
                                         (let ()
                                           (declare (not safe))
                                           (##vector-ref
                                            _%__splice101299101300%_
                                            '1)))
                                        (_%$%target6023860899%_
                                         (let ()
                                           (declare (not safe))
                                           (##vector-ref
                                            _%__splice101299101300%_
                                            '0))))
                                    (if (gx#stx-null? _%$%tl6024060902%_)
                                        (_%__match101407101408%_
                                         _%$%e6019261002%_
                                         _%$%hd6019361006%_
                                         _%$%tl6019461009%_
                                         _%$%e6019561012%_
                                         _%$%hd6019661016%_
                                         _%$%tl6019761019%_
                                         _%$%e6019861022%_
                                         _%$%hd6019961026%_
                                         _%$%tl6020061029%_
                                         _%$%e6020161032%_
                                         _%$%hd6020261036%_
                                         _%$%tl6020361039%_
                                         _%$%e6023560889%_
                                         _%$%hd6023660893%_
                                         _%$%tl6023760896%_
                                         _%__splice101299101300%_
                                         _%$%target6023860899%_
                                         _%$%tl6024060902%_)
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g6018660360%_)))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g6018660360%_)))
                            (let ()
                              (declare (not safe))
                              (_%$%g6018660360%_)))))
                    (let () (declare (not safe)) (_%$%g6018660360%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (gx#stx-pair?
                                                         _%$%tl6020361039%_)
                                                        (let ((_%$%e6023560889%_
                                                               (gx#syntax-e
                                                                _%$%tl6020361039%_)))
                                                          (let ((_%$%tl6023760896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e6023560889%_)))
                        (_%$%hd6023660893%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e6023560889%_))))
                    (if (gx#stx-null? _%$%tl6023760896%_)
                        (if (gx#stx-pair/null? _%$%tl6019761019%_)
                            (let ((_%__splice101299101300%_
                                   (gx#syntax-split-splice->vector
                                    _%$%tl6019761019%_
                                    '0)))
                              (let ((_%$%tl6024060902%_
                                     (let ()
                                       (declare (not safe))
                                       (##vector-ref
                                        _%__splice101299101300%_
                                        '1)))
                                    (_%$%target6023860899%_
                                     (let ()
                                       (declare (not safe))
                                       (##vector-ref
                                        _%__splice101299101300%_
                                        '0))))
                                (if (gx#stx-null? _%$%tl6024060902%_)
                                    (_%__match101407101408%_
                                     _%$%e6019261002%_
                                     _%$%hd6019361006%_
                                     _%$%tl6019461009%_
                                     _%$%e6019561012%_
                                     _%$%hd6019661016%_
                                     _%$%tl6019761019%_
                                     _%$%e6019861022%_
                                     _%$%hd6019961026%_
                                     _%$%tl6020061029%_
                                     _%$%e6020161032%_
                                     _%$%hd6020261036%_
                                     _%$%tl6020361039%_
                                     _%$%e6023560889%_
                                     _%$%hd6023660893%_
                                     _%$%tl6023760896%_
                                     _%__splice101299101300%_
                                     _%$%target6023860899%_
                                     _%$%tl6024060902%_)
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g6018660360%_)))))
                            (let () (declare (not safe)) (_%$%g6018660360%_)))
                        (let () (declare (not safe)) (_%$%g6018660360%_)))))
                (let () (declare (not safe)) (_%$%g6018660360%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g6018660360%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g6018660360%_)))))
                            (let ()
                              (declare (not safe))
                              (_%$%g6018660360%_)))))
                    (let () (declare (not safe)) (_%$%g6018660360%_)))))))))
    (define |gerbil/core/contract~Using[:0:]#%%app-dotted|
      (lambda (_%stx61543%_)
        (let* ((_%__stx101586101587%_ _%stx61543%_)
               (_%$%g6154861608%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx101586101587%_))))
          (let ((_%__kont101589101590%_
                 (lambda (_%$%g6155062165%_ _%$%g6155162167%_)
                   (cons (gx#datum->syntax '#f '%%app-dotted)
                         (cons (cons (gx#datum->syntax '#f '%%ref-dotted)
                                     (cons _%$%g6155162167%_ '()))
                               (foldr (lambda (_%$%g6218362186%_
                                               _%$%g6218462189%_)
                                        (cons _%$%g6218362186%_
                                              _%$%g6218462189%_))
                                      '()
                                      _%$%g6155062165%_)))))
                (_%__kont101593101594%_
                 (lambda (_%$%g6156761752%_ _%$%g6156861754%_)
                   (if (|gerbil/core/contract~Using[1]#dotted-identifier?|
                        _%$%g6156861754%_)
                       (let* ((_%$%g6177461781%_
                               (|gerbil/core/contract~Using[1]#split-dotted-identifier|
                                _%stx61543%_
                                _%$%g6156861754%_))
                              (_%$%E6177661787%_
                               (lambda ()
                                 (error '"No clause matching"
                                        _%$%g6177461781%_
                                        '([var . parts]))
                                 (void)))
                              (_%$%K6177762086%_
                               (lambda (_%parts61791%_ _%var61793%_)
                                 (let ((_%$e61795%_
                                        (let ()
                                          (declare (not safe))
                                          (gerbil/core/contract~TypeEnv#type-env-lookup
                                           _%var61793%_))))
                                   (if _%$e61795%_
                                       (let _%loop61802%_ ((_%parts61805%_
                                                            _%parts61791%_)
                                                           (_%type61807%_
                                                            (##direct-structure-ref
                                                             _%$e61795%_
                                                             '2
                                                             gerbil/core/contract~TypeEnv#type-env::t
                                                             '#f))
                                                           (_%object61808%_
                                                            _%var61793%_)
                                                           (_%checked-method?61809%_
                                                            (##direct-structure-ref
                                                             _%$e61795%_
                                                             '3
                                                             gerbil/core/contract~TypeEnv#type-env::t
                                                             '#f))
                                                           (_%checked-receiver?61810%_
                                                            (##direct-structure-ref
                                                             _%$e61795%_
                                                             '4
                                                             gerbil/core/contract~TypeEnv#type-env::t
                                                             '#f))
                                                           (_%nil-check?61811%_
                                                            '#f))
                                         (let* ((_%$%parts6181261820%_
                                                 _%parts61805%_)
                                                (_%$%else6181461881%_
                                                 (lambda ()
                                                   (let* ((_%$%g6183261840%_
                                                           (lambda (_%$%g6183361836%_)
                                                             (gx#raise-syntax-error
                                                              '#f
                                                              '"Bad syntax; invalid match target"
                                                              _%$%g6183361836%_)))
                                                          (_%$%g6183161877%_
                                                           (lambda (_%$%g6183361844%_)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            '%%app)
                           (cons _%$%g6183361844%_
                                 (foldr (lambda (_%$%g6186861871%_
                                                 _%$%g6186961874%_)
                                          (cons _%$%g6186861871%_
                                                _%$%g6186961874%_))
                                        '()
                                        _%$%g6156761752%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g6183161877%_
                                                      _%object61808%_))))
                                                (_%$%K6181662060%_
                                                 (lambda (_%rest61885%_
                                                          _%part61887%_)
                                                   (if (if _%nil-check?61811%_
                                                           '#f
                                                           (let ((__tmp107455
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (symbol->string _%part61887%_)))
                     (declare (not safe))
                     (##string-prefix? '"?" __tmp107455)))
               (let ((_%str61891%_ (symbol->string _%part61887%_)))
                 (_%loop61802%_
                  (cons (let ((__tmp107456
                               (substring
                                _%str61891%_
                                '1
                                (let ()
                                  (declare (not safe))
                                  (##string-length _%str61891%_)))))
                          (declare (not safe))
                          (##string->symbol __tmp107456))
                        _%rest61885%_)
                  _%type61807%_
                  _%object61808%_
                  _%checked-method?61809%_
                  _%checked-receiver?61810%_
                  '#t))
               (if (let ()
                     (declare (not safe))
                     (class-instance?
                      gerbil/core/mop~MOP-2#class-type-info::t
                      _%type61807%_))
                   (let* ((_%$%g6189661911%_
                           (lambda (_%$%g6189761907%_)
                             (gx#raise-syntax-error
                              '#f
                              '"Bad syntax; invalid match target"
                              _%$%g6189761907%_)))
                          (_%$%g6189561980%_
                           (lambda (_%$%g6189761915%_)
                             (if (gx#stx-pair? _%$%g6189761915%_)
                                 (let ((_%$%e6190061918%_
                                        (gx#syntax-e _%$%g6189761915%_)))
                                   (let ((_%$%hd6190161922%_
                                          (let ()
                                            (declare (not safe))
                                            (##car _%$%e6190061918%_)))
                                         (_%$%tl6190261925%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%e6190061918%_))))
                                     (if (gx#stx-pair? _%$%tl6190261925%_)
                                         (let ((_%$%e6190361928%_
                                                (gx#syntax-e
                                                 _%$%tl6190261925%_)))
                                           (let ((_%$%hd6190461932%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e6190361928%_)))
                                                 (_%$%tl6190561935%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e6190361928%_))))
                                             (if (gx#stx-null?
                                                  _%$%tl6190561935%_)
                                                 (if (null? _%rest61885%_)
                                                     (cons (gx#datum->syntax
                                                            '#f
                                                            '%%app)
                                                           (cons (cons _%$%hd6190461932%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (cons _%$%hd6190161922%_ '()))
                         (foldr (lambda (_%$%g6195961962%_ _%$%g6196061965%_)
                                  (cons _%$%g6195961962%_ _%$%g6196061965%_))
                                '()
                                _%$%g6156761752%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ((_%$e61968%_
                                                            (|gerbil/core/contract~Using[1]#!class-slot-type|
                                                             _%type61807%_
                                                             _%part61887%_)))
                                                       (if _%$e61968%_
                                                           (let ((_%slot-type61975%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (|gerbil/core/contract~TypeReference[1]#resolve-type|
                             _%stx61543%_
                             _%$e61968%_))))
                     (_%loop61802%_
                      _%rest61885%_
                      _%slot-type61975%_
                      (cons _%$%hd6190461932%_ (cons _%$%hd6190161922%_ '()))
                      (|gerbil/core/contract~Using[1]#!class-slot-checked-method-contract?|
                       _%type61807%_
                       _%part61887%_)
                      (|gerbil/core/contract~Using[1]#!class-slot-nullable?|
                       _%type61807%_
                       _%part61887%_)
                      '#f))
                   (gx#raise-syntax-error
                    '#f
                    '"unresolved dotted reference value; unknown type for slot"
                    _%stx61543%_
                    _%$%g6156861754%_
                    _%part61887%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g6189661911%_
                                                  _%$%g6189761915%_))))
                                         (_%$%g6189661911%_
                                          _%$%g6189761915%_))))
                                 (_%$%g6189661911%_ _%$%g6189761915%_)))))
                     (_%$%g6189561980%_
                      (list (if _%nil-check?61811%_
                                (cons 'check-nil! (cons _%object61808%_ '()))
                                _%object61808%_)
                            (|gerbil/core/contract~Using[1]#get-slot-accessor__%|
                             _%stx61543%_
                             _%type61807%_
                             _%part61887%_
                             _%checked-receiver?61810%_))))
                   (if (let ()
                         (declare (not safe))
                         (class-instance?
                          gerbil/core/contract~InterfaceInfo#interface-info::t
                          _%type61807%_))
                       (if (null? _%rest61885%_)
                           (let* ((_%$%g6198662001%_
                                   (lambda (_%$%g6198761997%_)
                                     (gx#raise-syntax-error
                                      '#f
                                      '"Bad syntax; invalid match target"
                                      _%$%g6198761997%_)))
                                  (_%$%g6198562054%_
                                   (lambda (_%$%g6198762005%_)
                                     (if (gx#stx-pair? _%$%g6198762005%_)
                                         (let ((_%$%e6199062008%_
                                                (gx#syntax-e
                                                 _%$%g6198762005%_)))
                                           (let ((_%$%hd6199162012%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e6199062008%_)))
                                                 (_%$%tl6199262015%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e6199062008%_))))
                                             (if (gx#stx-pair?
                                                  _%$%tl6199262015%_)
                                                 (let ((_%$%e6199362018%_
                                                        (gx#syntax-e
                                                         _%$%tl6199262015%_)))
                                                   (let ((_%$%hd6199462022%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e6199362018%_)))
                                                         (_%$%tl6199562025%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e6199362018%_))))
                                                     (if (gx#stx-null?
                                                          _%$%tl6199562025%_)
                                                         (cons _%$%hd6199462022%_
                                                               (cons _%$%hd6199162012%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (foldr (lambda (_%$%g6204562048%_
                                             _%$%g6204662051%_)
                                      (cons _%$%g6204562048%_
                                            _%$%g6204662051%_))
                                    '()
                                    _%$%g6156761752%_)))
                 (_%$%g6198662001%_ _%$%g6198762005%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g6198662001%_
                                                  _%$%g6198762005%_))))
                                         (_%$%g6198662001%_
                                          _%$%g6198762005%_)))))
                             (_%$%g6198562054%_
                              (list (if _%nil-check?61811%_
                                        (cons 'check-nil!
                                              (cons _%object61808%_ '()))
                                        _%object61808%_)
                                    (gx#stx-identifier
                                     _%$%g6156861754%_
                                     (if _%checked-method?61809%_ '"" '"&")
                                     (let ((__obj107232 _%type61807%_))
                                       (if (let ()
                                             (declare (not safe))
                                             (##structure-direct-instance-of?
                                              __obj107232
                                              'gerbil/core/contract~InterfaceInfo#interface-info::t))
                                           (let ()
                                             (declare (not safe))
                                             (##unchecked-structure-ref
                                              __obj107232
                                              '2
                                              '#f
                                              '#f))
                                           (unchecked-slot-ref
                                            __obj107232
                                            'name)))
                                     '"-"
                                     _%part61887%_))))
                           (gx#raise-syntax-error
                            '#f
                            '"illegal dotted reference; interface has no slots"
                            _%stx61543%_
                            _%$%g6156861754%_
                            _%part61887%_))
                       (gx#raise-syntax-error
                        '#f
                        '"unexpected type"
                        _%stx61543%_
                        _%type61807%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (if (pair? _%$%parts6181261820%_)
                                               (let ((_%$%hd6181762064%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%parts6181261820%_)))
                                                     (_%$%tl6181862067%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%parts6181261820%_))))
                                                 (let* ((_%part62070%_
                                                         _%$%hd6181762064%_)
                                                        (_%rest62073%_
                                                         _%$%tl6181862067%_))
                                                   (_%$%K6181662060%_
                                                    _%rest62073%_
                                                    _%part62070%_)))
                                               (_%$%else6181461881%_))))
                                       (cons (gx#datum->syntax '#f '%%app)
                                             (cons _%$%g6156861754%_
                                                   (foldr (lambda (_%$%g6207762080%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%g6207862083%_)
                    (cons _%$%g6207762080%_ _%$%g6207862083%_))
                  '()
                  _%$%g6156761752%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                         (if (pair? _%$%g6177461781%_)
                             (let ((_%$%hd6177862090%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%g6177461781%_)))
                                   (_%$%tl6177962093%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%g6177461781%_))))
                               (let* ((_%var62096%_ _%$%hd6177862090%_)
                                      (_%parts62099%_ _%$%tl6177962093%_))
                                 (_%$%K6177762086%_
                                  _%parts62099%_
                                  _%var62096%_)))
                             (_%$%E6177661787%_)))
                       (cons (gx#datum->syntax '#f '%%app)
                             (cons _%$%g6156861754%_
                                   (foldr (lambda (_%$%g6210162104%_
                                                   _%$%g6210262107%_)
                                            (cons _%$%g6210162104%_
                                                  _%$%g6210262107%_))
                                          '()
                                          _%$%g6156761752%_))))))
                (_%__kont101597101598%_
                 (lambda (_%$%g6159061653%_)
                   (cons (gx#datum->syntax '#f '%%app)
                         (foldr (lambda (_%$%g6166861671%_ _%$%g6166961674%_)
                                  (cons _%$%g6166861671%_ _%$%g6166961674%_))
                                '()
                                _%$%g6159061653%_)))))
            (let* ((_%__match101673101674%_
                    (lambda (_%$%e6159161615%_
                             _%$%hd6159261619%_
                             _%$%tl6159361622%_
                             _%__splice101599101600%_
                             _%$%target6159461625%_
                             _%$%tl6159661628%_)
                      (letrec ((_%$%loop6159761631%_
                                (lambda (_%$%hd6159561635%_
                                         _%$%arg6160161638%_)
                                  (if (gx#stx-pair? _%$%hd6159561635%_)
                                      (let ((_%$%e6159861640%_
                                             (gx#syntax-e _%$%hd6159561635%_)))
                                        (let ((_%$%lp-tl6160061647%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6159861640%_)))
                                              (_%$%lp-hd6159961644%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6159861640%_))))
                                          (_%$%loop6159761631%_
                                           _%$%lp-tl6160061647%_
                                           (cons _%$%lp-hd6159961644%_
                                                 _%$%arg6160161638%_))))
                                      (let ((_%$%arg6160261650%_
                                             (reverse _%$%arg6160161638%_)))
                                        (_%__kont101597101598%_
                                         _%$%arg6160261650%_))))))
                        (_%$%loop6159761631%_ _%$%target6159461625%_ '()))))
                   (_%__match101659101660%_
                    (lambda (_%$%e6156961684%_
                             _%$%hd6157061688%_
                             _%$%tl6157161691%_
                             _%$%e6157261694%_
                             _%$%hd6157361698%_
                             _%$%tl6157461701%_
                             _%$%e6157561704%_
                             _%$%hd6157661708%_
                             _%$%tl6157761711%_
                             _%$%e6157861714%_
                             _%$%hd6157961718%_
                             _%$%tl6158061721%_
                             _%__splice101595101596%_
                             _%$%target6158161724%_
                             _%$%tl6158361727%_)
                      (letrec ((_%$%loop6158461730%_
                                (lambda (_%$%hd6158261734%_
                                         _%$%rand6158861737%_)
                                  (if (gx#stx-pair? _%$%hd6158261734%_)
                                      (let ((_%$%e6158561739%_
                                             (gx#syntax-e _%$%hd6158261734%_)))
                                        (let ((_%$%lp-tl6158761746%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6158561739%_)))
                                              (_%$%lp-hd6158661743%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6158561739%_))))
                                          (_%$%loop6158461730%_
                                           _%$%lp-tl6158761746%_
                                           (cons _%$%lp-hd6158661743%_
                                                 _%$%rand6158861737%_))))
                                      (let ((_%$%rand6158961749%_
                                             (reverse _%$%rand6158861737%_)))
                                        (_%__kont101593101594%_
                                         _%$%rand6158961749%_
                                         _%$%hd6157961718%_))))))
                        (_%$%loop6158461730%_ _%$%target6158161724%_ '()))))
                   (_%__match101633101634%_
                    (lambda (_%$%e6156961684%_
                             _%$%hd6157061688%_
                             _%$%tl6157161691%_
                             _%$%e6157261694%_
                             _%$%hd6157361698%_
                             _%$%tl6157461701%_)
                      (if (gx#stx-pair? _%$%hd6157361698%_)
                          (let ((_%$%e6157561704%_
                                 (gx#syntax-e _%$%hd6157361698%_)))
                            (let ((_%$%tl6157761711%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e6157561704%_)))
                                  (_%$%hd6157661708%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e6157561704%_))))
                              (if (gx#identifier? _%$%hd6157661708%_)
                                  (if (gx#free-identifier=?
                                       |gerbil/core/contract~Using[1]#_g107457_|
                                       _%$%hd6157661708%_)
                                      (if (gx#stx-pair? _%$%tl6157761711%_)
                                          (let ((_%$%e6157861714%_
                                                 (gx#syntax-e
                                                  _%$%tl6157761711%_)))
                                            (let ((_%$%tl6158061721%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e6157861714%_)))
                                                  (_%$%hd6157961718%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e6157861714%_))))
                                              (if (gx#stx-null?
                                                   _%$%tl6158061721%_)
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl6157461701%_)
                                                      (let ((_%__splice101595101596%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl6157461701%_
                                                              '0)))
                                                        (let ((_%$%tl6158361727%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice101595101596%_ '1)))
                      (_%$%target6158161724%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice101595101596%_ '0))))
                  (if (gx#stx-null? _%$%tl6158361727%_)
                      (_%__match101659101660%_
                       _%$%e6156961684%_
                       _%$%hd6157061688%_
                       _%$%tl6157161691%_
                       _%$%e6157261694%_
                       _%$%hd6157361698%_
                       _%$%tl6157461701%_
                       _%$%e6157561704%_
                       _%$%hd6157661708%_
                       _%$%tl6157761711%_
                       _%$%e6157861714%_
                       _%$%hd6157961718%_
                       _%$%tl6158061721%_
                       _%__splice101595101596%_
                       _%$%target6158161724%_
                       _%$%tl6158361727%_)
                      (if (gx#stx-pair/null? _%$%tl6157161691%_)
                          (let ((_%__splice101599101600%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl6157161691%_
                                  '0)))
                            (let ((_%$%tl6159661628%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice101599101600%_
                                      '1)))
                                  (_%$%target6159461625%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice101599101600%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl6159661628%_)
                                  (_%__match101673101674%_
                                   _%$%e6156961684%_
                                   _%$%hd6157061688%_
                                   _%$%tl6157161691%_
                                   _%__splice101599101600%_
                                   _%$%target6159461625%_
                                   _%$%tl6159661628%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g6154861608%_)))))
                          (let () (declare (not safe)) (_%$%g6154861608%_))))))
              (if (gx#stx-pair/null? _%$%tl6157161691%_)
                  (let ((_%__splice101599101600%_
                         (gx#syntax-split-splice->vector
                          _%$%tl6157161691%_
                          '0)))
                    (let ((_%$%tl6159661628%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice101599101600%_ '1)))
                          (_%$%target6159461625%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice101599101600%_ '0))))
                      (if (gx#stx-null? _%$%tl6159661628%_)
                          (_%__match101673101674%_
                           _%$%e6156961684%_
                           _%$%hd6157061688%_
                           _%$%tl6157161691%_
                           _%__splice101599101600%_
                           _%$%target6159461625%_
                           _%$%tl6159661628%_)
                          (let () (declare (not safe)) (_%$%g6154861608%_)))))
                  (let () (declare (not safe)) (_%$%g6154861608%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl6157161691%_)
                                                      (let ((_%__splice101599101600%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl6157161691%_
                                                              '0)))
                                                        (let ((_%$%tl6159661628%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice101599101600%_ '1)))
                      (_%$%target6159461625%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice101599101600%_ '0))))
                  (if (gx#stx-null? _%$%tl6159661628%_)
                      (_%__match101673101674%_
                       _%$%e6156961684%_
                       _%$%hd6157061688%_
                       _%$%tl6157161691%_
                       _%__splice101599101600%_
                       _%$%target6159461625%_
                       _%$%tl6159661628%_)
                      (let () (declare (not safe)) (_%$%g6154861608%_)))))
              (let () (declare (not safe)) (_%$%g6154861608%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair/null?
                                               _%$%tl6157161691%_)
                                              (let ((_%__splice101599101600%_
                                                     (gx#syntax-split-splice->vector
                                                      _%$%tl6157161691%_
                                                      '0)))
                                                (let ((_%$%tl6159661628%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice101599101600%_
                                                          '1)))
                                                      (_%$%target6159461625%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice101599101600%_
                                                          '0))))
                                                  (if (gx#stx-null?
                                                       _%$%tl6159661628%_)
                                                      (_%__match101673101674%_
                                                       _%$%e6156961684%_
                                                       _%$%hd6157061688%_
                                                       _%$%tl6157161691%_
                                                       _%__splice101599101600%_
                                                       _%$%target6159461625%_
                                                       _%$%tl6159661628%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g6154861608%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g6154861608%_))))
                                      (if (gx#stx-pair/null?
                                           _%$%tl6157161691%_)
                                          (let ((_%__splice101599101600%_
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl6157161691%_
                                                  '0)))
                                            (let ((_%$%tl6159661628%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice101599101600%_
                                                      '1)))
                                                  (_%$%target6159461625%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice101599101600%_
                                                      '0))))
                                              (if (gx#stx-null?
                                                   _%$%tl6159661628%_)
                                                  (_%__match101673101674%_
                                                   _%$%e6156961684%_
                                                   _%$%hd6157061688%_
                                                   _%$%tl6157161691%_
                                                   _%__splice101599101600%_
                                                   _%$%target6159461625%_
                                                   _%$%tl6159661628%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g6154861608%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g6154861608%_))))
                                  (if (gx#stx-pair/null? _%$%tl6157161691%_)
                                      (let ((_%__splice101599101600%_
                                             (gx#syntax-split-splice->vector
                                              _%$%tl6157161691%_
                                              '0)))
                                        (let ((_%$%tl6159661628%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice101599101600%_
                                                  '1)))
                                              (_%$%target6159461625%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice101599101600%_
                                                  '0))))
                                          (if (gx#stx-null? _%$%tl6159661628%_)
                                              (_%__match101673101674%_
                                               _%$%e6156961684%_
                                               _%$%hd6157061688%_
                                               _%$%tl6157161691%_
                                               _%__splice101599101600%_
                                               _%$%target6159461625%_
                                               _%$%tl6159661628%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g6154861608%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g6154861608%_))))))
                          (if (gx#stx-pair/null? _%$%tl6157161691%_)
                              (let ((_%__splice101599101600%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl6157161691%_
                                      '0)))
                                (let ((_%$%tl6159661628%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice101599101600%_
                                          '1)))
                                      (_%$%target6159461625%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice101599101600%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl6159661628%_)
                                      (_%__match101673101674%_
                                       _%$%e6156961684%_
                                       _%$%hd6157061688%_
                                       _%$%tl6157161691%_
                                       _%__splice101599101600%_
                                       _%$%target6159461625%_
                                       _%$%tl6159661628%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g6154861608%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g6154861608%_))))))
                   (_%__match101621101622%_
                    (lambda (_%$%e6155262117%_
                             _%$%hd6155362121%_
                             _%$%tl6155462124%_
                             _%$%e6155562127%_
                             _%$%hd6155662131%_
                             _%$%tl6155762134%_
                             _%__splice101591101592%_
                             _%$%target6155862137%_
                             _%$%tl6156062140%_)
                      (letrec ((_%$%loop6156162143%_
                                (lambda (_%$%hd6155962147%_
                                         _%$%rand6156562150%_)
                                  (if (gx#stx-pair? _%$%hd6155962147%_)
                                      (let ((_%$%e6156262152%_
                                             (gx#syntax-e _%$%hd6155962147%_)))
                                        (let ((_%$%lp-tl6156462159%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6156262152%_)))
                                              (_%$%lp-hd6156362156%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6156262152%_))))
                                          (_%$%loop6156162143%_
                                           _%$%lp-tl6156462159%_
                                           (cons _%$%lp-hd6156362156%_
                                                 _%$%rand6156562150%_))))
                                      (let ((_%$%rand6156662162%_
                                             (reverse _%$%rand6156562150%_)))
                                        (let ((_%$%g6155062165%_
                                               _%$%rand6156662162%_)
                                              (_%$%g6155162167%_
                                               _%$%hd6155662131%_))
                                          (if (gx#identifier?
                                               _%$%g6155162167%_)
                                              (_%__kont101589101590%_
                                               _%$%g6155062165%_
                                               _%$%g6155162167%_)
                                              (_%__match101633101634%_
                                               _%$%e6155262117%_
                                               _%$%hd6155362121%_
                                               _%$%tl6155462124%_
                                               _%$%e6155562127%_
                                               _%$%hd6155662131%_
                                               _%$%tl6155762134%_))))))))
                        (_%$%loop6156162143%_ _%$%target6155862137%_ '())))))
              (if (gx#stx-pair? _%__stx101586101587%_)
                  (let ((_%$%e6155262117%_
                         (gx#syntax-e _%__stx101586101587%_)))
                    (let ((_%$%tl6155462124%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e6155262117%_)))
                          (_%$%hd6155362121%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e6155262117%_))))
                      (if (gx#stx-pair? _%$%tl6155462124%_)
                          (let ((_%$%e6155562127%_
                                 (gx#syntax-e _%$%tl6155462124%_)))
                            (let ((_%$%tl6155762134%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e6155562127%_)))
                                  (_%$%hd6155662131%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e6155562127%_))))
                              (if (gx#stx-pair/null? _%$%tl6155762134%_)
                                  (let ((_%__splice101591101592%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl6155762134%_
                                          '0)))
                                    (let ((_%$%tl6156062140%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice101591101592%_
                                              '1)))
                                          (_%$%target6155862137%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice101591101592%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl6156062140%_)
                                          (_%__match101621101622%_
                                           _%$%e6155262117%_
                                           _%$%hd6155362121%_
                                           _%$%tl6155462124%_
                                           _%$%e6155562127%_
                                           _%$%hd6155662131%_
                                           _%$%tl6155762134%_
                                           _%__splice101591101592%_
                                           _%$%target6155862137%_
                                           _%$%tl6156062140%_)
                                          (if (gx#stx-pair? _%$%hd6155662131%_)
                                              (let ((_%$%e6157561704%_
                                                     (gx#syntax-e
                                                      _%$%hd6155662131%_)))
                                                (let ((_%$%tl6157761711%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e6157561704%_)))
                                                      (_%$%hd6157661708%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e6157561704%_))))
                                                  (if (gx#identifier?
                                                       _%$%hd6157661708%_)
                                                      (if (gx#free-identifier=?
                                                           |gerbil/core/contract~Using[1]#_g107457_|
                                                           _%$%hd6157661708%_)
                                                          (if (gx#stx-pair?
                                                               _%$%tl6157761711%_)
                                                              (let ((_%$%e6157861714%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#syntax-e _%$%tl6157761711%_)))
                        (let ((_%$%tl6158061721%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e6157861714%_)))
                              (_%$%hd6157961718%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e6157861714%_))))
                          (if (gx#stx-pair/null? _%$%tl6155462124%_)
                              (let ((_%__splice101599101600%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl6155462124%_
                                      '0)))
                                (let ((_%$%tl6159661628%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice101599101600%_
                                          '1)))
                                      (_%$%target6159461625%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice101599101600%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl6159661628%_)
                                      (_%__match101673101674%_
                                       _%$%e6155262117%_
                                       _%$%hd6155362121%_
                                       _%$%tl6155462124%_
                                       _%__splice101599101600%_
                                       _%$%target6159461625%_
                                       _%$%tl6159661628%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g6154861608%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g6154861608%_)))))
                      (if (gx#stx-pair/null? _%$%tl6155462124%_)
                          (let ((_%__splice101599101600%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl6155462124%_
                                  '0)))
                            (let ((_%$%tl6159661628%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice101599101600%_
                                      '1)))
                                  (_%$%target6159461625%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice101599101600%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl6159661628%_)
                                  (_%__match101673101674%_
                                   _%$%e6155262117%_
                                   _%$%hd6155362121%_
                                   _%$%tl6155462124%_
                                   _%__splice101599101600%_
                                   _%$%target6159461625%_
                                   _%$%tl6159661628%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g6154861608%_)))))
                          (let () (declare (not safe)) (_%$%g6154861608%_))))
                  (if (gx#stx-pair/null? _%$%tl6155462124%_)
                      (let ((_%__splice101599101600%_
                             (gx#syntax-split-splice->vector
                              _%$%tl6155462124%_
                              '0)))
                        (let ((_%$%tl6159661628%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice101599101600%_ '1)))
                              (_%$%target6159461625%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice101599101600%_ '0))))
                          (if (gx#stx-null? _%$%tl6159661628%_)
                              (_%__match101673101674%_
                               _%$%e6155262117%_
                               _%$%hd6155362121%_
                               _%$%tl6155462124%_
                               _%__splice101599101600%_
                               _%$%target6159461625%_
                               _%$%tl6159661628%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g6154861608%_)))))
                      (let () (declare (not safe)) (_%$%g6154861608%_))))
              (if (gx#stx-pair/null? _%$%tl6155462124%_)
                  (let ((_%__splice101599101600%_
                         (gx#syntax-split-splice->vector
                          _%$%tl6155462124%_
                          '0)))
                    (let ((_%$%tl6159661628%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice101599101600%_ '1)))
                          (_%$%target6159461625%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice101599101600%_ '0))))
                      (if (gx#stx-null? _%$%tl6159661628%_)
                          (_%__match101673101674%_
                           _%$%e6155262117%_
                           _%$%hd6155362121%_
                           _%$%tl6155462124%_
                           _%__splice101599101600%_
                           _%$%target6159461625%_
                           _%$%tl6159661628%_)
                          (let () (declare (not safe)) (_%$%g6154861608%_)))))
                  (let () (declare (not safe)) (_%$%g6154861608%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#stx-pair/null?
                                                   _%$%tl6155462124%_)
                                                  (let ((_%__splice101599101600%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl6155462124%_
                                                          '0)))
                                                    (let ((_%$%tl6159661628%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice101599101600%_
                                                              '1)))
                                                          (_%$%target6159461625%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice101599101600%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl6159661628%_)
                                                          (_%__match101673101674%_
                                                           _%$%e6155262117%_
                                                           _%$%hd6155362121%_
                                                           _%$%tl6155462124%_
                                                           _%__splice101599101600%_
                                                           _%$%target6159461625%_
                                                           _%$%tl6159661628%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g6154861608%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g6154861608%_)))))))
                                  (if (gx#stx-pair? _%$%hd6155662131%_)
                                      (let ((_%$%e6157561704%_
                                             (gx#syntax-e _%$%hd6155662131%_)))
                                        (let ((_%$%tl6157761711%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6157561704%_)))
                                              (_%$%hd6157661708%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6157561704%_))))
                                          (if (gx#identifier?
                                               _%$%hd6157661708%_)
                                              (if (gx#free-identifier=?
                                                   |gerbil/core/contract~Using[1]#_g107457_|
                                                   _%$%hd6157661708%_)
                                                  (if (gx#stx-pair?
                                                       _%$%tl6157761711%_)
                                                      (let ((_%$%e6157861714%_
                                                             (gx#syntax-e
                                                              _%$%tl6157761711%_)))
                                                        (let ((_%$%tl6158061721%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e6157861714%_)))
                      (_%$%hd6157961718%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e6157861714%_))))
                  (if (gx#stx-pair/null? _%$%tl6155462124%_)
                      (let ((_%__splice101599101600%_
                             (gx#syntax-split-splice->vector
                              _%$%tl6155462124%_
                              '0)))
                        (let ((_%$%tl6159661628%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice101599101600%_ '1)))
                              (_%$%target6159461625%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice101599101600%_ '0))))
                          (if (gx#stx-null? _%$%tl6159661628%_)
                              (_%__match101673101674%_
                               _%$%e6155262117%_
                               _%$%hd6155362121%_
                               _%$%tl6155462124%_
                               _%__splice101599101600%_
                               _%$%target6159461625%_
                               _%$%tl6159661628%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g6154861608%_)))))
                      (let () (declare (not safe)) (_%$%g6154861608%_)))))
              (if (gx#stx-pair/null? _%$%tl6155462124%_)
                  (let ((_%__splice101599101600%_
                         (gx#syntax-split-splice->vector
                          _%$%tl6155462124%_
                          '0)))
                    (let ((_%$%tl6159661628%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice101599101600%_ '1)))
                          (_%$%target6159461625%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice101599101600%_ '0))))
                      (if (gx#stx-null? _%$%tl6159661628%_)
                          (_%__match101673101674%_
                           _%$%e6155262117%_
                           _%$%hd6155362121%_
                           _%$%tl6155462124%_
                           _%__splice101599101600%_
                           _%$%target6159461625%_
                           _%$%tl6159661628%_)
                          (let () (declare (not safe)) (_%$%g6154861608%_)))))
                  (let () (declare (not safe)) (_%$%g6154861608%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl6155462124%_)
                                                      (let ((_%__splice101599101600%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl6155462124%_
                                                              '0)))
                                                        (let ((_%$%tl6159661628%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice101599101600%_ '1)))
                      (_%$%target6159461625%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice101599101600%_ '0))))
                  (if (gx#stx-null? _%$%tl6159661628%_)
                      (_%__match101673101674%_
                       _%$%e6155262117%_
                       _%$%hd6155362121%_
                       _%$%tl6155462124%_
                       _%__splice101599101600%_
                       _%$%target6159461625%_
                       _%$%tl6159661628%_)
                      (let () (declare (not safe)) (_%$%g6154861608%_)))))
              (let () (declare (not safe)) (_%$%g6154861608%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#stx-pair/null?
                                                   _%$%tl6155462124%_)
                                                  (let ((_%__splice101599101600%_
                                                         (gx#syntax-split-splice->vector
                                                          _%$%tl6155462124%_
                                                          '0)))
                                                    (let ((_%$%tl6159661628%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice101599101600%_
                                                              '1)))
                                                          (_%$%target6159461625%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##vector-ref
                                                              _%__splice101599101600%_
                                                              '0))))
                                                      (if (gx#stx-null?
                                                           _%$%tl6159661628%_)
                                                          (_%__match101673101674%_
                                                           _%$%e6155262117%_
                                                           _%$%hd6155362121%_
                                                           _%$%tl6155462124%_
                                                           _%__splice101599101600%_
                                                           _%$%target6159461625%_
                                                           _%$%tl6159661628%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g6154861608%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g6154861608%_))))))
                                      (if (gx#stx-pair/null?
                                           _%$%tl6155462124%_)
                                          (let ((_%__splice101599101600%_
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl6155462124%_
                                                  '0)))
                                            (let ((_%$%tl6159661628%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice101599101600%_
                                                      '1)))
                                                  (_%$%target6159461625%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice101599101600%_
                                                      '0))))
                                              (if (gx#stx-null?
                                                   _%$%tl6159661628%_)
                                                  (_%__match101673101674%_
                                                   _%$%e6155262117%_
                                                   _%$%hd6155362121%_
                                                   _%$%tl6155462124%_
                                                   _%__splice101599101600%_
                                                   _%$%target6159461625%_
                                                   _%$%tl6159661628%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g6154861608%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g6154861608%_)))))))
                          (if (gx#stx-pair/null? _%$%tl6155462124%_)
                              (let ((_%__splice101599101600%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl6155462124%_
                                      '0)))
                                (let ((_%$%tl6159661628%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice101599101600%_
                                          '1)))
                                      (_%$%target6159461625%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice101599101600%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl6159661628%_)
                                      (_%__match101673101674%_
                                       _%$%e6155262117%_
                                       _%$%hd6155362121%_
                                       _%$%tl6155462124%_
                                       _%__splice101599101600%_
                                       _%$%target6159461625%_
                                       _%$%tl6159661628%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g6154861608%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g6154861608%_))))))
                  (let () (declare (not safe)) (_%$%g6154861608%_))))))))
    (define |gerbil/core/contract~Using[:0:]#%%ref-dotted|
      (lambda (_%stx62199%_)
        (let* ((_%__stx101676101677%_ _%stx62199%_)
               (_%$%g6220362224%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx101676101677%_))))
          (let ((_%__kont101679101680%_
                 (lambda (_%$%g6220562292%_)
                   (let* ((_%$%g6230462311%_
                           (|gerbil/core/contract~Using[1]#split-dotted-identifier|
                            _%stx62199%_
                            _%$%g6220562292%_))
                          (_%$%E6230662317%_
                           (lambda ()
                             (error '"No clause matching"
                                    _%$%g6230462311%_
                                    '([var . parts]))
                             (void)))
                          (_%$%K6230762532%_
                           (lambda (_%parts62321%_ _%var62323%_)
                             (let ((_%$e62325%_
                                    (let ()
                                      (declare (not safe))
                                      (gerbil/core/contract~TypeEnv#type-env-lookup
                                       _%var62323%_))))
                               (if _%$e62325%_
                                   (let _%loop62332%_ ((_%parts62335%_
                                                        _%parts62321%_)
                                                       (_%type62337%_
                                                        (##direct-structure-ref
                                                         _%$e62325%_
                                                         '2
                                                         gerbil/core/contract~TypeEnv#type-env::t
                                                         '#f))
                                                       (_%object62338%_
                                                        _%var62323%_)
                                                       (_%checked-receiver?62339%_
                                                        (##direct-structure-ref
                                                         _%$e62325%_
                                                         '4
                                                         gerbil/core/contract~TypeEnv#type-env::t
                                                         '#f))
                                                       (_%nil-check?62340%_
                                                        '#f))
                                     (let* ((_%$%parts6234162349%_
                                             _%parts62335%_)
                                            (_%$%else6234362361%_
                                             (lambda () _%object62338%_))
                                            (_%$%K6234562514%_
                                             (lambda (_%rest62365%_
                                                      _%part62367%_)
                                               (if (if _%nil-check?62340%_
                                                       '#f
                                                       (let ((__tmp107458
                                                              (symbol->string
                                                               _%part62367%_)))
                                                         (declare (not safe))
                                                         (##string-prefix?
                                                          '"?"
                                                          __tmp107458)))
                                                   (let ((_%str62371%_
                                                          (symbol->string
                                                           _%part62367%_)))
                                                     (_%loop62332%_
                                                      (cons (let ((__tmp107459
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (substring
                            _%str62371%_
                            '1
                            (let ()
                              (declare (not safe))
                              (##string-length _%str62371%_)))))
                      (declare (not safe))
                      (##string->symbol __tmp107459))
                    _%rest62365%_)
              _%type62337%_
              _%object62338%_
              _%checked-receiver?62339%_
              '#t))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (class-instance?
                                                          gerbil/core/mop~MOP-2#class-type-info::t
                                                          _%type62337%_))
                                                       (let* ((_%$%g6237662391%_
                                                               (lambda (_%$%g6237762387%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#raise-syntax-error
                          '#f
                          '"Bad syntax; invalid match target"
                          _%$%g6237762387%_)))
                      (_%$%g6237562506%_
                       (lambda (_%$%g6237762395%_)
                         (if (gx#stx-pair? _%$%g6237762395%_)
                             (let ((_%$%e6238062398%_
                                    (gx#syntax-e _%$%g6237762395%_)))
                               (let ((_%$%hd6238162402%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e6238062398%_)))
                                     (_%$%tl6238262405%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e6238062398%_))))
                                 (if (gx#stx-pair? _%$%tl6238262405%_)
                                     (let ((_%$%e6238362408%_
                                            (gx#syntax-e _%$%tl6238262405%_)))
                                       (let ((_%$%hd6238462412%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e6238362408%_)))
                                             (_%$%tl6238562415%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e6238362408%_))))
                                         (if (gx#stx-null? _%$%tl6238562415%_)
                                             (if (null? _%rest62365%_)
                                                 (let ((_%$e62450%_
                                                        (|gerbil/core/contract~Using[1]#!class-slot-type|
                                                         _%type62337%_
                                                         _%part62367%_)))
                                                   (if _%$e62450%_
                                                       (let* ((_%$%g6245762465%_
                                                               (lambda (_%$%g6245862461%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#raise-syntax-error
                          '#f
                          '"Bad syntax; invalid match target"
                          _%$%g6245862461%_)))
                      (_%$%g6245662488%_
                       (lambda (_%$%g6245862469%_)
                         (cons (gx#datum->syntax '#f 'begin-annotation)
                               (cons (cons (gx#datum->syntax '#f '@type)
                                           (cons _%$%g6245862469%_ '()))
                                     (cons (cons _%$%hd6238462412%_
                                                 (cons _%$%hd6238162402%_ '()))
                                           '()))))))
                 (_%$%g6245662488%_
                  (let ((_%descriptor62492%_
                         (let ()
                           (declare (not safe))
                           (|gerbil/core/contract~TypeReference[1]#resolve-type->type-descriptor|
                            _%stx62199%_
                            _%$e62450%_))))
                    (if (|gerbil/core/contract~Using[1]#!class-slot-nullable?|
                         _%type62337%_
                         _%part62367%_)
                        (cons 'nullable (cons _%descriptor62492%_ '()))
                        _%descriptor62492%_))))
               (cons _%$%hd6238462412%_ (cons _%$%hd6238162402%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (let ((_%$e62497%_
                                                        (|gerbil/core/contract~Using[1]#!class-slot-type|
                                                         _%type62337%_
                                                         _%part62367%_)))
                                                   (if _%$e62497%_
                                                       (_%loop62332%_
                                                        _%rest62365%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (|gerbil/core/contract~TypeReference[1]#resolve-type|
                                                           _%stx62199%_
                                                           _%$e62497%_))
                                                        (cons _%$%hd6238462412%_
                                                              (cons _%$%hd6238162402%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                (|gerbil/core/contract~Using[1]#!class-slot-nullable?|
                 _%type62337%_
                 _%part62367%_)
                '#f)
               (gx#raise-syntax-error
                '#f
                '"unresolved dotted reference; unknown type for slot"
                _%stx62199%_
                _%$%g6220562292%_
                _%part62367%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             (_%$%g6237662391%_
                                              _%$%g6237762395%_))))
                                     (_%$%g6237662391%_ _%$%g6237762395%_))))
                             (_%$%g6237662391%_ _%$%g6237762395%_)))))
                 (_%$%g6237562506%_
                  (list (if _%nil-check?62340%_
                            (list 'check-nil! _%object62338%_)
                            _%object62338%_)
                        (|gerbil/core/contract~Using[1]#get-slot-accessor__%|
                         _%stx62199%_
                         _%type62337%_
                         _%part62367%_
                         _%checked-receiver?62339%_))))
               (if (let ()
                     (declare (not safe))
                     (class-instance?
                      gerbil/core/contract~InterfaceInfo#interface-info::t
                      _%type62337%_))
                   (gx#raise-syntax-error
                    '#f
                    '"illegal dotted reference; interface has no slots"
                    _%stx62199%_
                    _%$%g6220562292%_)
                   (gx#raise-syntax-error
                    '#f
                    '"unexpected type"
                    _%stx62199%_
                    _%type62337%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (if (pair? _%$%parts6234162349%_)
                                           (let ((_%$%hd6234662518%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%parts6234162349%_)))
                                                 (_%$%tl6234762521%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%parts6234162349%_))))
                                             (let* ((_%part62524%_
                                                     _%$%hd6234662518%_)
                                                    (_%rest62527%_
                                                     _%$%tl6234762521%_))
                                               (_%$%K6234562514%_
                                                _%rest62527%_
                                                _%part62524%_)))
                                           (_%$%else6234362361%_))))
                                   (cons (gx#datum->syntax '#f '%%ref)
                                         (cons _%$%g6220562292%_ '())))))))
                     (if (pair? _%$%g6230462311%_)
                         (let ((_%$%hd6230862536%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%g6230462311%_)))
                               (_%$%tl6230962539%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%g6230462311%_))))
                           (let* ((_%var62542%_ _%$%hd6230862536%_)
                                  (_%parts62545%_ _%$%tl6230962539%_))
                             (_%$%K6230762532%_ _%parts62545%_ _%var62542%_)))
                         (_%$%E6230662317%_)))))
                (_%__kont101681101682%_
                 (lambda (_%$%g6221262251%_)
                   (cons (gx#datum->syntax '#f '%%ref)
                         (cons _%$%g6221262251%_ '())))))
            (let ((_%__match101697101698%_
                   (lambda (_%$%e6220662272%_
                            _%$%hd6220762276%_
                            _%$%tl6220862279%_
                            _%$%e6220962282%_
                            _%$%hd6221062286%_
                            _%$%tl6221162289%_)
                     (let ((_%$%g6220562292%_ _%$%hd6221062286%_))
                       (if (|gerbil/core/contract~Using[1]#dotted-identifier?|
                            _%$%g6220562292%_)
                           (_%__kont101679101680%_ _%$%g6220562292%_)
                           (_%__kont101681101682%_ _%$%hd6221062286%_))))))
              (if (gx#stx-pair? _%__stx101676101677%_)
                  (let ((_%$%e6220662272%_
                         (gx#syntax-e _%__stx101676101677%_)))
                    (let ((_%$%tl6220862279%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e6220662272%_)))
                          (_%$%hd6220762276%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e6220662272%_))))
                      (if (gx#stx-pair? _%$%tl6220862279%_)
                          (let ((_%$%e6220962282%_
                                 (gx#syntax-e _%$%tl6220862279%_)))
                            (let ((_%$%tl6221162289%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e6220962282%_)))
                                  (_%$%hd6221062286%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e6220962282%_))))
                              (if (gx#stx-null? _%$%tl6221162289%_)
                                  (_%__match101697101698%_
                                   _%$%e6220662272%_
                                   _%$%hd6220762276%_
                                   _%$%tl6220862279%_
                                   _%$%e6220962282%_
                                   _%$%hd6221062286%_
                                   _%$%tl6221162289%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g6220362224%_)))))
                          (let () (declare (not safe)) (_%$%g6220362224%_)))))
                  (let () (declare (not safe)) (_%$%g6220362224%_))))))))
    (define |gerbil/core/contract~Using[:0:]#%%set-dotted!|
      (lambda (_%stx62552%_)
        (let* ((_%__stx101714101715%_ _%stx62552%_)
               (_%$%g6255662585%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx101714101715%_))))
          (let ((_%__kont101717101718%_
                 (lambda (_%$%g6255862677%_ _%$%g6255962679%_)
                   (let* ((_%$%g6269362700%_
                           (|gerbil/core/contract~Using[1]#split-dotted-identifier|
                            _%stx62552%_
                            _%$%g6255962679%_))
                          (_%$%E6269562706%_
                           (lambda ()
                             (error '"No clause matching"
                                    _%$%g6269362700%_
                                    '([var . parts]))
                             (void)))
                          (_%$%K6269662941%_
                           (lambda (_%parts62710%_ _%var62712%_)
                             (let ((_%$e62714%_
                                    (let ()
                                      (declare (not safe))
                                      (gerbil/core/contract~TypeEnv#type-env-lookup
                                       _%var62712%_))))
                               (if _%$e62714%_
                                   (let _%loop62721%_ ((_%parts62724%_
                                                        _%parts62710%_)
                                                       (_%type62726%_
                                                        (##direct-structure-ref
                                                         _%$e62714%_
                                                         '2
                                                         gerbil/core/contract~TypeEnv#type-env::t
                                                         '#f))
                                                       (_%object62727%_
                                                        _%var62712%_)
                                                       (_%checked-mutator?62728%_
                                                        (##direct-structure-ref
                                                         _%$e62714%_
                                                         '3
                                                         gerbil/core/contract~TypeEnv#type-env::t
                                                         '#f))
                                                       (_%checked-receiver?62729%_
                                                        (##direct-structure-ref
                                                         _%$e62714%_
                                                         '4
                                                         gerbil/core/contract~TypeEnv#type-env::t
                                                         '#f))
                                                       (_%nil-check?62730%_
                                                        '#f))
                                     (let* ((_%$%parts6273162738%_
                                             _%parts62724%_)
                                            (_%$%E6273362744%_
                                             (lambda ()
                                               (error '"No clause matching"
                                                      _%$%parts6273162738%_
                                                      '([part . rest]))
                                               (void)))
                                            (_%$%K6273462923%_
                                             (lambda (_%rest62748%_
                                                      _%part62750%_)
                                               (if (if _%nil-check?62730%_
                                                       '#f
                                                       (let ((__tmp107460
                                                              (symbol->string
                                                               _%part62750%_)))
                                                         (declare (not safe))
                                                         (##string-prefix?
                                                          '"?"
                                                          __tmp107460)))
                                                   (let ((_%str62754%_
                                                          (symbol->string
                                                           _%part62750%_)))
                                                     (_%loop62721%_
                                                      (cons (let ((__tmp107461
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (substring
                            _%str62754%_
                            '1
                            (let ()
                              (declare (not safe))
                              (##string-length _%str62754%_)))))
                      (declare (not safe))
                      (##string->symbol __tmp107461))
                    _%rest62748%_)
              _%type62726%_
              _%object62727%_
              _%checked-mutator?62728%_
              _%checked-receiver?62729%_
              '#t))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (class-instance?
                                                          gerbil/core/mop~MOP-2#class-type-info::t
                                                          _%type62726%_))
                                                       (if (null? _%rest62748%_)
                                                           (let* ((_%$%g6276162776%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (lambda (_%$%g6276262772%_)
                             (gx#raise-syntax-error
                              '#f
                              '"Bad syntax; invalid match target"
                              _%$%g6276262772%_)))
                          (_%$%g6276062833%_
                           (lambda (_%$%g6276262780%_)
                             (if (gx#stx-pair? _%$%g6276262780%_)
                                 (let ((_%$%e6276562783%_
                                        (gx#syntax-e _%$%g6276262780%_)))
                                   (let ((_%$%hd6276662787%_
                                          (let ()
                                            (declare (not safe))
                                            (##car _%$%e6276562783%_)))
                                         (_%$%tl6276762790%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%e6276562783%_))))
                                     (if (gx#stx-pair? _%$%tl6276762790%_)
                                         (let ((_%$%e6276862793%_
                                                (gx#syntax-e
                                                 _%$%tl6276762790%_)))
                                           (let ((_%$%hd6276962797%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e6276862793%_)))
                                                 (_%$%tl6277062800%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e6276862793%_))))
                                             (if (gx#stx-null?
                                                  _%$%tl6277062800%_)
                                                 (if _%nil-check?62730%_
                                                     (cons _%$%hd6276962797%_
                                                           (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                '#f
                                'check-nil!)
                               (cons _%$%hd6276662787%_ '()))
                         (cons _%$%g6255862677%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons _%$%hd6276962797%_
                                                           (cons _%$%hd6276662787%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons _%$%g6255862677%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g6276162776%_
                                                  _%$%g6276262780%_))))
                                         (_%$%g6276162776%_
                                          _%$%g6276262780%_))))
                                 (_%$%g6276162776%_ _%$%g6276262780%_)))))
                     (_%$%g6276062833%_
                      (list _%object62727%_
                            (|gerbil/core/contract~Using[1]#get-slot-mutator|
                             _%stx62552%_
                             _%type62726%_
                             _%part62750%_
                             (let ((_%$e62837%_ _%checked-receiver?62729%_))
                               (if _%$e62837%_
                                   _%$e62837%_
                                   (if _%checked-mutator?62728%_
                                       (|gerbil/core/contract~Using[1]#!class-slot-contract|
                                        _%type62726%_
                                        _%part62750%_)
                                       '#f)))))))
                   (let ((_%$e62841%_
                          (|gerbil/core/contract~Using[1]#!class-slot-type|
                           _%type62726%_
                           _%part62750%_)))
                     (if _%$e62841%_
                         (let* ((_%next-type62848%_
                                 (let ()
                                   (declare (not safe))
                                   (|gerbil/core/contract~TypeReference[1]#resolve-type|
                                    _%stx62552%_
                                    _%$e62841%_)))
                                (_%$%g6285162866%_
                                 (lambda (_%$%g6285262862%_)
                                   (gx#raise-syntax-error
                                    '#f
                                    '"Bad syntax; invalid match target"
                                    _%$%g6285262862%_)))
                                (_%$%g6285062913%_
                                 (lambda (_%$%g6285262870%_)
                                   (if (gx#stx-pair? _%$%g6285262870%_)
                                       (let ((_%$%e6285562873%_
                                              (gx#syntax-e _%$%g6285262870%_)))
                                         (let ((_%$%hd6285662877%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e6285562873%_)))
                                               (_%$%tl6285762880%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e6285562873%_))))
                                           (if (gx#stx-pair?
                                                _%$%tl6285762880%_)
                                               (let ((_%$%e6285862883%_
                                                      (gx#syntax-e
                                                       _%$%tl6285762880%_)))
                                                 (let ((_%$%hd6285962887%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e6285862883%_)))
                                                       (_%$%tl6286062890%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e6285862883%_))))
                                                   (if (gx#stx-null?
                                                        _%$%tl6286062890%_)
                                                       (_%loop62721%_
                                                        _%rest62748%_
                                                        _%next-type62848%_
                                                        (cons _%$%hd6285962887%_
                                                              (cons _%$%hd6285662877%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                (|gerbil/core/contract~Using[1]#!class-slot-checked-mutator-contract?|
                 _%type62726%_
                 _%part62750%_)
                (|gerbil/core/contract~Using[1]#!class-slot-nullable?|
                 _%type62726%_
                 _%part62750%_)
                '#f)
               (_%$%g6285162866%_ _%$%g6285262870%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g6285162866%_
                                                _%$%g6285262870%_))))
                                       (_%$%g6285162866%_
                                        _%$%g6285262870%_)))))
                           (_%$%g6285062913%_
                            (list (if _%nil-check?62730%_
                                      (list 'check-nil! _%object62727%_)
                                      _%object62727%_)
                                  (|gerbil/core/contract~Using[1]#get-slot-accessor__%|
                                   _%stx62552%_
                                   _%type62726%_
                                   _%part62750%_
                                   _%checked-receiver?62729%_))))
                         (gx#raise-syntax-error
                          '#f
                          '"unresolved dotted setter; unknown type for slot"
                          _%stx62552%_
                          _%$%g6255962679%_
                          _%part62750%_))))
               (if (let ()
                     (declare (not safe))
                     (class-instance?
                      gerbil/core/contract~InterfaceInfo#interface-info::t
                      _%type62726%_))
                   (gx#raise-syntax-error
                    '#f
                    '"illegal dotted setter; interface has no slots"
                    _%stx62552%_
                    _%$%g6255962679%_)
                   (gx#raise-syntax-error
                    '#f
                    '"unexpected type"
                    _%stx62552%_
                    _%type62726%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (if (pair? _%$%parts6273162738%_)
                                           (let ((_%$%hd6273562927%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%parts6273162738%_)))
                                                 (_%$%tl6273662930%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%parts6273162738%_))))
                                             (let* ((_%part62933%_
                                                     _%$%hd6273562927%_)
                                                    (_%rest62936%_
                                                     _%$%tl6273662930%_))
                                               (_%$%K6273462923%_
                                                _%rest62936%_
                                                _%part62933%_)))
                                           (_%$%E6273362744%_))))
                                   (let ()
                                     (declare (not safe))
                                     (|gerbil/core/more-sugar[1]#expand-set!|
                                      _%stx62552%_)))))))
                     (if (pair? _%$%g6269362700%_)
                         (let ((_%$%hd6269762945%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%g6269362700%_)))
                               (_%$%tl6269862948%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%g6269362700%_))))
                           (let* ((_%var62951%_ _%$%hd6269762945%_)
                                  (_%parts62954%_ _%$%tl6269862948%_))
                             (_%$%K6269662941%_ _%parts62954%_ _%var62951%_)))
                         (_%$%E6269562706%_)))))
                (_%__kont101719101720%_
                 (lambda (_%$%g6256962622%_ _%$%g6257062624%_)
                   (let ()
                     (declare (not safe))
                     (|gerbil/core/more-sugar[1]#expand-set!| _%stx62552%_)))))
            (let ((_%__match101741101742%_
                   (lambda (_%$%e6256062647%_
                            _%$%hd6256162651%_
                            _%$%tl6256262654%_
                            _%$%e6256362657%_
                            _%$%hd6256462661%_
                            _%$%tl6256562664%_
                            _%$%e6256662667%_
                            _%$%hd6256762671%_
                            _%$%tl6256862674%_)
                     (let ((_%$%g6255862677%_ _%$%hd6256762671%_)
                           (_%$%g6255962679%_ _%$%hd6256462661%_))
                       (if (|gerbil/core/contract~Using[1]#dotted-identifier?|
                            _%$%g6255962679%_)
                           (_%__kont101717101718%_
                            _%$%g6255862677%_
                            _%$%g6255962679%_)
                           (_%__kont101719101720%_
                            _%$%hd6256762671%_
                            _%$%hd6256462661%_))))))
              (if (gx#stx-pair? _%__stx101714101715%_)
                  (let ((_%$%e6256062647%_
                         (gx#syntax-e _%__stx101714101715%_)))
                    (let ((_%$%tl6256262654%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e6256062647%_)))
                          (_%$%hd6256162651%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e6256062647%_))))
                      (if (gx#stx-pair? _%$%tl6256262654%_)
                          (let ((_%$%e6256362657%_
                                 (gx#syntax-e _%$%tl6256262654%_)))
                            (let ((_%$%tl6256562664%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e6256362657%_)))
                                  (_%$%hd6256462661%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e6256362657%_))))
                              (if (gx#stx-pair? _%$%tl6256562664%_)
                                  (let ((_%$%e6256662667%_
                                         (gx#syntax-e _%$%tl6256562664%_)))
                                    (let ((_%$%tl6256862674%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e6256662667%_)))
                                          (_%$%hd6256762671%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e6256662667%_))))
                                      (if (gx#stx-null? _%$%tl6256862674%_)
                                          (_%__match101741101742%_
                                           _%$%e6256062647%_
                                           _%$%hd6256162651%_
                                           _%$%tl6256262654%_
                                           _%$%e6256362657%_
                                           _%$%hd6256462661%_
                                           _%$%tl6256562664%_
                                           _%$%e6256662667%_
                                           _%$%hd6256762671%_
                                           _%$%tl6256862674%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g6255662585%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g6255662585%_)))))
                          (let () (declare (not safe)) (_%$%g6255662585%_)))))
                  (let () (declare (not safe)) (_%$%g6255662585%_))))))))))
