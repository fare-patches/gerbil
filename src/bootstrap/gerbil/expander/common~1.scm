(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gx[1]#_g184075_|
    (##structure
     gx#syntax-quote::t
     'AST::t
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184077_|
    (##structure
     gx#syntax-quote::t
     'make-AST
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184079_|
    (##structure
     gx#syntax-quote::t
     'AST?
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184081_|
    (##structure
     gx#syntax-quote::t
     'AST-e
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184082_|
    (##structure
     gx#syntax-quote::t
     'AST-source
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184084_|
    (##structure
     gx#syntax-quote::t
     'AST-e-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184085_|
    (##structure
     gx#syntax-quote::t
     'AST-source-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184087_|
    (##structure
     gx#syntax-quote::t
     '&AST-e
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184088_|
    (##structure
     gx#syntax-quote::t
     '&AST-source
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184090_|
    (##structure
     gx#syntax-quote::t
     '&AST-e-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184091_|
    (##structure
     gx#syntax-quote::t
     '&AST-source-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g184093_|
    (##structure
     gx#syntax-quote::t
     'else
     #f
     (gx#current-expander-context)
     '()))
  (begin
    (define |gx[:0:]#AST|
      (let ((__obj184071
             (let ()
               (declare (not safe))
               (##structure
                gerbil/core/mop~MOP-2#class-type-info::t
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f))))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 'gerbil#AST::t '2 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 'syntax '3 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '(e source) '6 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '(e source) '8 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '() '5 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '#t '9 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '#f '10 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '#f '12 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '#f '13 '#f '#f))
        (let ((__tmp184074 |gx[1]#_g184075_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184074 '4 '#f '#f))
        (let ((__tmp184076 |gx[1]#_g184077_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184076 '14 '#f '#f))
        (let ((__tmp184078 |gx[1]#_g184079_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184078 '15 '#f '#f))
        (let ((__tmp184080
               (cons (cons 'e |gx[1]#_g184081_|)
                     (cons (cons 'source |gx[1]#_g184082_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184080 '16 '#f '#f))
        (let ((__tmp184083
               (cons (cons 'e |gx[1]#_g184084_|)
                     (cons (cons 'source |gx[1]#_g184085_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184083 '17 '#f '#f))
        (let ((__tmp184086
               (cons (cons 'e |gx[1]#_g184087_|)
                     (cons (cons 'source |gx[1]#_g184088_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184086 '18 '#f '#f))
        (let ((__tmp184089
               (cons (cons 'e |gx[1]#_g184090_|)
                     (cons (cons 'source |gx[1]#_g184091_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 __tmp184089 '19 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '() '20 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '() '22 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj184071 '() '21 '#f '#f))
        __obj184071))
    (define |gx[:0:]#check-procedure|
      (lambda (_%$stx182668%_)
        (let* ((_%$%g182672182686%_
                (lambda (_%$%g182673182682%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g182673182682%_)))
               (_%$%g182671182728%_
                (lambda (_%$%g182673182690%_)
                  (if (gx#stx-pair? _%$%g182673182690%_)
                      (let ((_%$%e182675182693%_
                             (gx#syntax-e _%$%g182673182690%_)))
                        (let ((_%$%hd182676182697%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e182675182693%_)))
                              (_%$%tl182677182700%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e182675182693%_))))
                          (if (gx#stx-pair? _%$%tl182677182700%_)
                              (let ((_%$%e182678182703%_
                                     (gx#syntax-e _%$%tl182677182700%_)))
                                (let ((_%$%hd182679182707%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e182678182703%_)))
                                      (_%$%tl182680182710%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e182678182703%_))))
                                  (if (gx#stx-null? _%$%tl182680182710%_)
                                      (cons (gx#datum->syntax '#f 'unless)
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'procedure?)
                                                        (cons _%$%hd182679182707%_
                                                              '()))
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'error)
                                                              (cons '"expected procedure"
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%$%hd182679182707%_ '())))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (_%$%g182672182686%_
                                       _%$%g182673182690%_))))
                              (_%$%g182672182686%_ _%$%g182673182690%_))))
                      (_%$%g182672182686%_ _%$%g182673182690%_)))))
          (_%$%g182671182728%_ _%$stx182668%_))))
    (define |gx[:0:]#core-syntax-case|
      (lambda (_%stx182732%_)
        (letrec ((_%generate182735%_
                  (lambda (_%tgt182884%_ _%kws182886%_ _%clauses182887%_)
                    (letrec ((_%generate-clause182889%_
                              (lambda (_%hd183822%_ _%E183824%_)
                                (let* ((_%__stx183974183975%_ _%hd183822%_)
                                       (_%$%g183828183855%_
                                        (lambda ()
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid match target"
                                           _%__stx183974183975%_))))
                                  (let ((_%__kont183977183978%_
                                         (lambda (_%$%g183830183951%_
                                                  _%$%g183831183953%_)
                                           (_%generate1182891%_
                                            _%hd183822%_
                                            _%$%g183831183953%_
                                            '#t
                                            _%$%g183830183951%_
                                            _%E183824%_)))
                                        (_%__kont183979183980%_
                                         (lambda (_%$%g183838183903%_
                                                  _%$%g183839183905%_
                                                  _%$%g183840183906%_)
                                           (_%generate1182891%_
                                            _%hd183822%_
                                            _%$%g183840183906%_
                                            _%$%g183839183905%_
                                            _%$%g183838183903%_
                                            _%E183824%_)))
                                        (_%__kont183981183982%_
                                         (lambda ()
                                           (gx#raise-syntax-error
                                            '#f
                                            '"Bad syntax; invalid syntax-case pattern"
                                            _%stx182732%_
                                            _%hd183822%_))))
                                    (if (gx#stx-pair? _%__stx183974183975%_)
                                        (let ((_%$%e183832183931%_
                                               (gx#syntax-e
                                                _%__stx183974183975%_)))
                                          (let ((_%$%tl183834183938%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e183832183931%_)))
                                                (_%$%hd183833183935%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e183832183931%_))))
                                            (if (gx#stx-pair?
                                                 _%$%tl183834183938%_)
                                                (let ((_%$%e183835183941%_
                                                       (gx#syntax-e
                                                        _%$%tl183834183938%_)))
                                                  (let ((_%$%tl183837183948%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e183835183941%_)))
                                                        (_%$%hd183836183945%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e183835183941%_))))
                                                    (if (gx#stx-null?
                                                         _%$%tl183837183948%_)
                                                        (_%__kont183977183978%_
                                                         _%$%hd183836183945%_
                                                         _%$%hd183833183935%_)
                                                        (if (gx#stx-pair?
                                                             _%$%tl183837183948%_)
                                                            (let ((_%$%e183847183893%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-e _%$%tl183837183948%_)))
                      (let ((_%$%tl183849183900%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e183847183893%_)))
                            (_%$%hd183848183897%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e183847183893%_))))
                        (if (gx#stx-null? _%$%tl183849183900%_)
                            (_%__kont183979183980%_
                             _%$%hd183848183897%_
                             _%$%hd183836183945%_
                             _%$%hd183833183935%_)
                            (_%__kont183981183982%_))))
                    (_%__kont183981183982%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__kont183981183982%_))))
                                        (_%__kont183981183982%_))))))
                             (_%generate1182891%_
                              (lambda (_%where183275%_
                                       _%hd183277%_
                                       _%fender183278%_
                                       _%body183279%_
                                       _%E183280%_)
                                (letrec ((_%recur183282%_
                                          (lambda (_%hd183285%_
                                                   _%tgt183287%_
                                                   _%K183288%_)
                                            (let* ((_%__stx184020184021%_
                                                    _%hd183285%_)
                                                   (_%$%g183291183303%_
                                                    (lambda ()
                                                      (gx#raise-syntax-error
                                                       '#f
                                                       '"Bad syntax; invalid match target"
                                                       _%__stx184020184021%_))))
                                              (let ((_%__kont184023184024%_
                                                     (lambda (_%$%g183293183612%_
                                                              _%$%g183294183614%_)
                                                       (let* ((_%$%g183625183633%_
                                                               (lambda (_%$%g183626183629%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#raise-syntax-error
                          '#f
                          '"Bad syntax; invalid match target"
                          _%$%g183626183629%_)))
                      (_%$%g183624183814%_
                       (lambda (_%$%g183626183637%_)
                         (let* ((_%$%g183652183660%_
                                 (lambda (_%$%g183653183656%_)
                                   (gx#raise-syntax-error
                                    '#f
                                    '"Bad syntax; invalid match target"
                                    _%$%g183653183656%_)))
                                (_%$%g183651183810%_
                                 (lambda (_%$%g183653183664%_)
                                   (let* ((_%$%g183680183688%_
                                           (lambda (_%$%g183681183684%_)
                                             (gx#raise-syntax-error
                                              '#f
                                              '"Bad syntax; invalid match target"
                                              _%$%g183681183684%_)))
                                          (_%$%g183679183806%_
                                           (lambda (_%$%g183681183692%_)
                                             (let* ((_%$%g183708183716%_
                                                     (lambda (_%$%g183709183712%_)
                                                       (gx#raise-syntax-error
                                                        '#f
                                                        '"Bad syntax; invalid match target"
                                                        _%$%g183709183712%_)))
                                                    (_%$%g183707183802%_
                                                     (lambda (_%$%g183709183720%_)
                                                       (let* ((_%$%g183736183744%_
                                                               (lambda (_%$%g183737183740%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#raise-syntax-error
                          '#f
                          '"Bad syntax; invalid match target"
                          _%$%g183737183740%_)))
                      (_%$%g183735183798%_
                       (lambda (_%$%g183737183748%_)
                         (let* ((_%$%g183764183772%_
                                 (lambda (_%$%g183765183768%_)
                                   (gx#raise-syntax-error
                                    '#f
                                    '"Bad syntax; invalid match target"
                                    _%$%g183765183768%_)))
                                (_%$%g183763183794%_
                                 (lambda (_%$%g183765183776%_)
                                   (cons (gx#datum->syntax '#f 'if)
                                         (cons (cons (gx#datum->syntax
                                                      '#f
                                                      'stx-pair?)
                                                     (cons _%$%g183626183637%_
                                                           '()))
                                               (cons (cons (gx#datum->syntax
                                                            '#f
                                                            'let)
                                                           (cons (cons (cons _%$%g183653183664%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                     (cons (cons (gx#datum->syntax
                                                  '#f
                                                  'syntax-e)
                                                 (cons _%$%g183626183637%_
                                                       '()))
                                           '()))
                               '())
                         (cons (cons (gx#datum->syntax '#f 'let)
                                     (cons (cons (cons _%$%g183681183692%_
                                                       (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            '##car)
                           (cons _%$%g183653183664%_ '()))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons _%$%g183709183720%_
                                                             (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  '#f
                                  '##cdr)
                                 (cons _%$%g183653183664%_ '()))
                           '()))
               '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (cons _%$%g183737183748%_ '())))
                               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons _%$%g183765183776%_
                                                           '())))))))
                           (_%$%g183763183794%_ _%E183280%_)))))
                 (_%$%g183735183798%_
                  (_%recur183282%_
                   _%$%g183294183614%_
                   _%$%g183681183692%_
                   (_%recur183282%_
                    _%$%g183293183612%_
                    _%$%g183709183720%_
                    _%K183288%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g183707183802%_
                                                (gx#genident 'tl))))))
                                     (_%$%g183679183806%_
                                      (gx#genident 'hd))))))
                           (_%$%g183651183810%_ (gx#genident 'e))))))
                 (_%$%g183624183814%_ _%tgt183287%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont184025184026%_
                                                     (lambda ()
                                                       (if (gx#identifier?
                                                            _%hd183285%_)
                                                           (if (gx#underscore?
                                                                _%hd183285%_)
                                                               _%K183288%_
                                                               (if (let ((__tmp184092
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (lambda (_%$%g183317183319%_)
                                    (gx#bound-identifier=?
                                     _%$%g183317183319%_
                                     _%hd183285%_))))
                             (declare (not safe))
                             (__find __tmp184092 _%kws182886%_))
                           (let* ((_%$%g183325183340%_
                                   (lambda (_%$%g183326183336%_)
                                     (gx#raise-syntax-error
                                      '#f
                                      '"Bad syntax; invalid match target"
                                      _%$%g183326183336%_)))
                                  (_%$%g183324183393%_
                                   (lambda (_%$%g183326183344%_)
                                     (if (gx#stx-pair? _%$%g183326183344%_)
                                         (let ((_%$%e183329183347%_
                                                (gx#syntax-e
                                                 _%$%g183326183344%_)))
                                           (let ((_%$%hd183330183351%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e183329183347%_)))
                                                 (_%$%tl183331183354%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e183329183347%_))))
                                             (if (gx#stx-pair?
                                                  _%$%tl183331183354%_)
                                                 (let ((_%$%e183332183357%_
                                                        (gx#syntax-e
                                                         _%$%tl183331183354%_)))
                                                   (let ((_%$%hd183333183361%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e183332183357%_)))
                                                         (_%$%tl183334183364%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e183332183357%_))))
                                                     (if (gx#stx-null?
                                                          _%$%tl183334183364%_)
                                                         (cons (gx#datum->syntax
                                                                '#f
                                                                'if)
                                                               (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    '#f
                                    'and)
                                   (cons (cons (gx#datum->syntax
                                                '#f
                                                'identifier?)
                                               (cons _%$%hd183330183351%_ '()))
                                         (cons (cons (gx#datum->syntax
                                                      '#f
                                                      'core-identifier=?)
                                                     (cons _%$%hd183330183351%_
                                                           (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                '#f
                                'quote)
                               (cons _%$%hd183333183361%_ '()))
                         '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               '())))
                             (cons _%K183288%_ (cons _%E183280%_ '()))))
                 (_%$%g183325183340%_ _%$%g183326183344%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g183325183340%_
                                                  _%$%g183326183344%_))))
                                         (_%$%g183325183340%_
                                          _%$%g183326183344%_)))))
                             (_%$%g183324183393%_
                              (list _%tgt183287%_ _%hd183285%_)))
                           (let* ((_%$%g183399183414%_
                                   (lambda (_%$%g183400183410%_)
                                     (gx#raise-syntax-error
                                      '#f
                                      '"Bad syntax; invalid match target"
                                      _%$%g183400183410%_)))
                                  (_%$%g183398183459%_
                                   (lambda (_%$%g183400183418%_)
                                     (if (gx#stx-pair? _%$%g183400183418%_)
                                         (let ((_%$%e183403183421%_
                                                (gx#syntax-e
                                                 _%$%g183400183418%_)))
                                           (let ((_%$%hd183404183425%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e183403183421%_)))
                                                 (_%$%tl183405183428%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e183403183421%_))))
                                             (if (gx#stx-pair?
                                                  _%$%tl183405183428%_)
                                                 (let ((_%$%e183406183431%_
                                                        (gx#syntax-e
                                                         _%$%tl183405183428%_)))
                                                   (let ((_%$%hd183407183435%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e183406183431%_)))
                                                         (_%$%tl183408183438%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e183406183431%_))))
                                                     (if (gx#stx-null?
                                                          _%$%tl183408183438%_)
                                                         (cons (gx#datum->syntax
                                                                '#f
                                                                'let)
                                                               (cons (cons (cons _%$%hd183407183435%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                         (cons _%$%hd183404183425%_ '()))
                                   '())
                             (cons _%K183288%_ '())))
                 (_%$%g183399183414%_ _%$%g183400183418%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g183399183414%_
                                                  _%$%g183400183418%_))))
                                         (_%$%g183399183414%_
                                          _%$%g183400183418%_)))))
                             (_%$%g183398183459%_
                              (list _%tgt183287%_ _%hd183285%_)))))
                   (if (gx#stx-null? _%hd183285%_)
                       (let* ((_%$%g183465183473%_
                               (lambda (_%$%g183466183469%_)
                                 (gx#raise-syntax-error
                                  '#f
                                  '"Bad syntax; invalid match target"
                                  _%$%g183466183469%_)))
                              (_%$%g183464183492%_
                               (lambda (_%$%g183466183477%_)
                                 (cons (gx#datum->syntax '#f 'if)
                                       (cons (cons (gx#datum->syntax
                                                    '#f
                                                    'stx-null?)
                                                   (cons _%$%g183466183477%_
                                                         '()))
                                             (cons _%K183288%_
                                                   (cons _%E183280%_ '())))))))
                         (_%$%g183464183492%_ _%tgt183287%_))
                       (if (gx#stx-datum? _%hd183285%_)
                           (let* ((_%$%g183498183517%_
                                   (lambda (_%$%g183499183513%_)
                                     (gx#raise-syntax-error
                                      '#f
                                      '"Bad syntax; invalid match target"
                                      _%$%g183499183513%_)))
                                  (_%$%g183497183576%_
                                   (lambda (_%$%g183499183521%_)
                                     (if (gx#stx-pair? _%$%g183499183521%_)
                                         (let ((_%$%e183503183524%_
                                                (gx#syntax-e
                                                 _%$%g183499183521%_)))
                                           (let ((_%$%hd183504183528%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e183503183524%_)))
                                                 (_%$%tl183505183531%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e183503183524%_))))
                                             (if (gx#stx-pair?
                                                  _%$%tl183505183531%_)
                                                 (let ((_%$%e183506183534%_
                                                        (gx#syntax-e
                                                         _%$%tl183505183531%_)))
                                                   (let ((_%$%hd183507183538%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e183506183534%_)))
                                                         (_%$%tl183508183541%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e183506183534%_))))
                                                     (if (gx#stx-pair?
                                                          _%$%tl183508183541%_)
                                                         (let ((_%$%e183509183544%_
                                                                (gx#syntax-e
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%tl183508183541%_)))
                   (let ((_%$%hd183510183548%_
                          (let ()
                            (declare (not safe))
                            (##car _%$%e183509183544%_)))
                         (_%$%tl183511183551%_
                          (let ()
                            (declare (not safe))
                            (##cdr _%$%e183509183544%_))))
                     (if (gx#stx-null? _%$%tl183511183551%_)
                         (cons (gx#datum->syntax '#f 'if)
                               (cons (cons _%$%hd183510183548%_
                                           (cons (cons (gx#datum->syntax
                                                        '#f
                                                        'stx-e)
                                                       (cons _%$%hd183504183528%_
                                                             '()))
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'quote)
                                                             (cons _%$%hd183507183538%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (cons _%K183288%_
                                           (cons _%E183280%_ '()))))
                         (_%$%g183498183517%_ _%$%g183499183521%_))))
                 (_%$%g183498183517%_ _%$%g183499183521%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g183498183517%_
                                                  _%$%g183499183521%_))))
                                         (_%$%g183498183517%_
                                          _%$%g183499183521%_)))))
                             (_%$%g183497183576%_
                              (list _%tgt183287%_
                                    _%hd183285%_
                                    (let ((_%e183580%_
                                           (gx#stx-e _%hd183285%_)))
                                      (if (or (keyword? _%e183580%_)
                                              (let ()
                                                (declare (not safe))
                                                (immediate? _%e183580%_)))
                                          (gx#datum->syntax '#f 'eq?)
                                          (if (number? _%e183580%_)
                                              (gx#datum->syntax '#f 'eqv?)
                                              (gx#datum->syntax
                                               '#f
                                               'equal?)))))))
                           (gx#raise-syntax-error
                            '#f
                            '"Bad syntax; invalid syntax-case head"
                            _%stx182732%_
                            _%where183275%_
                            _%hd183285%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (gx#stx-pair?
                                                     _%__stx184020184021%_)
                                                    (let ((_%$%e183295183602%_
                                                           (gx#syntax-e
                                                            _%__stx184020184021%_)))
                                                      (let ((_%$%tl183297183609%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e183295183602%_)))
                    (_%$%hd183296183606%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e183295183602%_))))
                (_%__kont184023184024%_
                 _%$%tl183297183609%_
                 _%$%hd183296183606%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont184025184026%_)))))))
                                  (_%recur183282%_
                                   _%hd183277%_
                                   _%tgt182884%_
                                   (cons (gx#datum->syntax '#f 'if)
                                         (cons _%fender183278%_
                                               (cons _%body183279%_
                                                     (cons _%E183280%_
                                                           '()))))))))
                             (_%generate-clauses182892%_
                              (lambda (_%clauses183013%_)
                                (let _%lp183016%_ ((_%rest183019%_
                                                    _%clauses183013%_)
                                                   (_%E183021%_
                                                    (gx#genident 'E))
                                                   (_%r183022%_ '()))
                                  (let* ((_%__stx184056184057%_ _%rest183019%_)
                                         (_%$%g183025183037%_
                                          (lambda ()
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Bad syntax; invalid match target"
                                             _%__stx184056184057%_))))
                                    (let ((_%__kont184059184060%_
                                           (lambda (_%$%g183027183102%_
                                                    _%$%g183028183104%_)
                                             (let* ((_%__stx184036184037%_
                                                     _%$%g183028183104%_)
                                                    (_%$%g183116183127%_
                                                     (lambda ()
                                                       (gx#raise-syntax-error
                                                        '#f
                                                        '"Bad syntax; invalid match target"
                                                        _%__stx184036184037%_))))
                                               (let ((_%__kont184039184040%_
                                                      (lambda (_%$%g183118183256%_)
                                                        (if (gx#stx-null?
                                                             _%$%g183027183102%_)
                                                            (if (and (gx#stx-list?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%g183118183256%_)
                             (not (gx#stx-null? _%$%g183118183256%_)))
                        (cons (cons _%E183021%_
                                    (cons (gx#stx-wrap-source
                                           (cons (gx#datum->syntax '#f 'lambda)
                                                 (cons '()
                                                       (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'begin)
                           _%$%g183118183256%_)
                     '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (gx#stx-source _%$%g183028183104%_))
                                          '()))
                              _%r183022%_)
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; invalid else body"
                         _%stx182732%_
                         _%$%g183028183104%_))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; misplaced else"
                     _%stx182732%_
                     _%$%g183028183104%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%__kont184041184042%_
                                                      (lambda ()
                                                        (let* ((_%$%g183138183146%_
                                                                (lambda (_%$%g183139183142%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (gx#raise-syntax-error
                           '#f
                           '"Bad syntax; invalid match target"
                           _%$%g183139183142%_)))
                       (_%$%g183137183235%_
                        (lambda (_%$%g183139183150%_)
                          (let* ((_%$%g183169183177%_
                                  (lambda (_%$%g183170183173%_)
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Bad syntax; invalid match target"
                                     _%$%g183170183173%_)))
                                 (_%$%g183168183231%_
                                  (lambda (_%$%g183170183181%_)
                                    (let* ((_%$%g183197183205%_
                                            (lambda (_%$%g183198183201%_)
                                              (gx#raise-syntax-error
                                               '#f
                                               '"Bad syntax; invalid match target"
                                               _%$%g183198183201%_)))
                                           (_%$%g183196183227%_
                                            (lambda (_%$%g183198183209%_)
                                              (_%lp183016%_
                                               _%$%g183027183102%_
                                               _%$%g183139183150%_
                                               (cons (cons _%E183021%_
                                                           (cons _%$%g183198183209%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%r183022%_)))))
                                      (_%$%g183196183227%_
                                       (gx#stx-wrap-source
                                        (cons (gx#datum->syntax '#f 'lambda)
                                              (cons '()
                                                    (cons _%$%g183170183181%_
                                                          '())))
                                        (gx#stx-source
                                         _%$%g183028183104%_)))))))
                            (_%$%g183168183231%_
                             (_%generate-clause182889%_
                              _%$%g183028183104%_
                              (cons _%$%g183139183150%_ '())))))))
                  (_%$%g183137183235%_ (gx#genident 'E))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (if (gx#stx-pair?
                                                      _%__stx184036184037%_)
                                                     (let ((_%$%e183119183246%_
                                                            (gx#syntax-e
                                                             _%__stx184036184037%_)))
                                                       (let ((_%$%tl183121183253%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##cdr _%$%e183119183246%_)))
                     (_%$%hd183120183250%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%e183119183246%_))))
                 (if (gx#identifier? _%$%hd183120183250%_)
                     (if (gx#free-identifier=?
                          |gx[1]#_g184093_|
                          _%$%hd183120183250%_)
                         (_%__kont184039184040%_ _%$%tl183121183253%_)
                         (_%__kont184041184042%_))
                     (_%__kont184041184042%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%__kont184041184042%_))))))
                                          (_%__kont184061184062%_
                                           (lambda ()
                                             (let* ((_%$%g183048183056%_
                                                     (lambda (_%$%g183049183052%_)
                                                       (gx#raise-syntax-error
                                                        '#f
                                                        '"Bad syntax; invalid match target"
                                                        _%$%g183049183052%_)))
                                                    (_%$%g183047183081%_
                                                     (lambda (_%$%g183049183060%_)
                                                       (cons (cons _%E183021%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons (gx#stx-wrap-source
                                  (cons (gx#datum->syntax '#f 'lambda)
                                        (cons '()
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'raise-syntax-error)
                                                          (cons '#f
                                                                (cons '"Bad syntax; invalid syntax-case clause"
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%$%g183049183060%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  (gx#stx-source _%stx182732%_))
                                 '()))
                     _%r183022%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g183047183081%_
                                                _%tgt182884%_)))))
                                      (if (gx#stx-pair? _%__stx184056184057%_)
                                          (let ((_%$%e183029183092%_
                                                 (gx#syntax-e
                                                  _%__stx184056184057%_)))
                                            (let ((_%$%tl183031183099%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e183029183092%_)))
                                                  (_%$%hd183030183096%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e183029183092%_))))
                                              (_%__kont184059184060%_
                                               _%$%tl183031183099%_
                                               _%$%hd183030183096%_)))
                                          (_%__kont184061184062%_))))))))
                      (let* ((_%bind182894%_
                              (_%generate-clauses182892%_ _%clauses182887%_))
                             (_%$%g182897182914%_
                              (lambda (_%$%g182898182910%_)
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%$%g182898182910%_)))
                             (_%$%g182896183009%_
                              (lambda (_%$%g182898182918%_)
                                (if (gx#stx-pair/null? _%$%g182898182918%_)
                                    (let ((_g184094_
                                           (gx#syntax-split-splice
                                            _%$%g182898182918%_
                                            '0)))
                                      (begin
                                        (let ((_g184095_
                                               (let ()
                                                 (declare (not safe))
                                                 (if (##values? _g184094_)
                                                     (##values-length
                                                      _g184094_)
                                                     1))))
                                          (if (not (let ()
                                                     (declare (not safe))
                                                     (##fx= _g184095_ 2)))
                                              (error "Context expects 2 values"
                                                     _g184095_)))
                                        (let ((_%$%target182900182921%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##values-ref _g184094_ 0)))
                                              (_%$%tl182902182924%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##values-ref _g184094_ 1))))
                                          (if (gx#stx-null?
                                               _%$%tl182902182924%_)
                                              (letrec ((_%$%loop182903182927%_
                                                        (lambda (_%$%hd182901182931%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%bind-try182907182934%_)
                  (if (gx#stx-pair? _%$%hd182901182931%_)
                      (let ((_%$%e182904182936%_
                             (gx#syntax-e _%$%hd182901182931%_)))
                        (let ((_%$%lp-hd182905182940%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e182904182936%_)))
                              (_%$%lp-tl182906182943%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e182904182936%_))))
                          (_%$%loop182903182927%_
                           _%$%lp-tl182906182943%_
                           (cons _%$%lp-hd182905182940%_
                                 _%$%bind-try182907182934%_))))
                      (let* ((_%$%bind-try182908182946%_
                              (reverse _%$%bind-try182907182934%_))
                             (_%$%g182967182975%_
                              (lambda (_%$%g182968182971%_)
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%$%g182968182971%_)))
                             (_%$%g182966183005%_
                              (lambda (_%$%g182968182979%_)
                                (cons (gx#datum->syntax '#f 'let*)
                                      (cons (let ((__tmp184096
                                                   (lambda (_%$%g182996182999%_
                                                            _%$%g182997183002%_)
                                                     (cons _%$%g182996182999%_
                                                           _%$%g182997183002%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp184096
                                               '()
                                               _%$%bind-try182908182946%_))
                                            (cons (cons _%$%g182968182979%_
                                                        '())
                                                  '()))))))
                        (_%$%g182966183005%_ (car (last _%bind182894%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%loop182903182927%_
                                                 _%$%target182900182921%_
                                                 '()))
                                              (_%$%g182897182914%_
                                               _%$%g182898182918%_)))))
                                    (_%$%g182897182914%_
                                     _%$%g182898182918%_)))))
                        (_%$%g182896183009%_ _%bind182894%_))))))
          (let* ((_%$%g182738182757%_
                  (lambda (_%$%g182739182753%_)
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g182739182753%_)))
                 (_%$%g182737182880%_
                  (lambda (_%$%g182739182761%_)
                    (if (gx#stx-pair? _%$%g182739182761%_)
                        (let ((_%$%e182743182764%_
                               (gx#syntax-e _%$%g182739182761%_)))
                          (let ((_%$%hd182744182768%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e182743182764%_)))
                                (_%$%tl182745182771%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e182743182764%_))))
                            (if (gx#stx-pair? _%$%tl182745182771%_)
                                (let ((_%$%e182746182774%_
                                       (gx#syntax-e _%$%tl182745182771%_)))
                                  (let ((_%$%hd182747182778%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e182746182774%_)))
                                        (_%$%tl182748182781%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e182746182774%_))))
                                    (if (gx#stx-pair? _%$%tl182748182781%_)
                                        (let ((_%$%e182749182784%_
                                               (gx#syntax-e
                                                _%$%tl182748182781%_)))
                                          (let ((_%$%hd182750182788%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e182749182784%_)))
                                                (_%$%tl182751182791%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e182749182784%_))))
                                            (if (and (gx#identifier-list?
                                                      _%$%hd182750182788%_)
                                                     (gx#stx-list?
                                                      _%$%tl182751182791%_))
                                                (let* ((_%$%g182815182823%_
                                                        (lambda (_%$%g182816182819%_)
                                                          (gx#raise-syntax-error
                                                           '#f
                                                           '"Bad syntax; invalid match target"
                                                           _%$%g182816182819%_)))
                                                       (_%$%g182814182876%_
                                                        (lambda (_%$%g182816182827%_)
                                                          (let* ((_%$%g182842182850%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (lambda (_%$%g182843182846%_)
                            (gx#raise-syntax-error
                             '#f
                             '"Bad syntax; invalid match target"
                             _%$%g182843182846%_)))
                         (_%$%g182841182872%_
                          (lambda (_%$%g182843182854%_)
                            (cons (gx#datum->syntax '#f 'let)
                                  (cons (cons (cons _%$%g182816182827%_
                                                    (cons _%$%hd182747182778%_
                                                          '()))
                                              '())
                                        (cons _%$%g182843182854%_ '()))))))
                    (_%$%g182841182872%_
                     (_%generate182735%_
                      _%$%g182816182827%_
                      (gx#syntax->list _%$%hd182750182788%_)
                      _%$%tl182751182791%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g182814182876%_
                                                   (gx#genident 'e)))
                                                (_%$%g182738182757%_
                                                 _%$%g182739182761%_))))
                                        (_%$%g182738182757%_
                                         _%$%g182739182761%_))))
                                (_%$%g182738182757%_ _%$%g182739182761%_))))
                        (_%$%g182738182757%_ _%$%g182739182761%_)))))
            (_%$%g182737182880%_ _%stx182732%_)))))))
