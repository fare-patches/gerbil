(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gerbil/core/contract~TypeCast[1]#_g107396_|
    (##structure gx#syntax-quote::t ':- #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~TypeCast[1]#_g107397_|
    (##structure gx#syntax-quote::t ': #f (gx#current-expander-context) '()))
  (define |gerbil/core/contract~TypeCast[1]#_g107398_|
    (##structure gx#syntax-quote::t ':- #f (gx#current-expander-context) '()))
  (begin
    (define |gerbil/core/contract~TypeCast[:0:]#return-contract|
      (lambda (_%stx54142%_)
        (let* ((_%__stx100148100149%_ _%stx54142%_)
               (_%$%g5414654179%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx100148100149%_))))
          (let ((_%__kont100151100152%_
                 (lambda (_%$%g5414854387%_
                          _%$%g5414954389%_
                          _%$%g5415054390%_)
                   (let ((_g107389_
                          (let ()
                            (declare (not safe))
                            (|gerbil/core/contract~TypeReference[1]#resolve-return-type|
                             _%stx54142%_
                             _%$%g5414954389%_))))
                     (begin
                       (let ((_g107390_
                              (let ()
                                (declare (not safe))
                                (if (##values? _g107389_)
                                    (##values-length _g107389_)
                                    1))))
                         (if (not (let ()
                                    (declare (not safe))
                                    (##fx= _g107390_ 2)))
                             (error "Context expects 2 values" _g107390_)))
                       (let ((_%base54408%_
                              (let ()
                                (declare (not safe))
                                (##values-ref _g107389_ 0)))
                             (_%maybe?54410%_
                              (let ()
                                (declare (not safe))
                                (##values-ref _g107389_ 1))))
                         (let* ((_%$%g5441254420%_
                                 (lambda (_%$%g5441354416%_)
                                   (gx#raise-syntax-error
                                    '#f
                                    '"Bad syntax; invalid match target"
                                    _%$%g5441354416%_)))
                                (_%$%g5441154446%_
                                 (lambda (_%$%g5441354424%_)
                                   (if _%maybe?54410%_
                                       (cons (gx#datum->syntax
                                              '#f
                                              'return-contract)
                                             (cons _%$%g5415054390%_
                                                   (cons _%$%g5414954389%_
                                                         '())))
                                       (if (gx#stx-e _%$%g5414854387%_)
                                           (cons (gx#datum->syntax '#f ':)
                                                 (cons _%$%g5415054390%_
                                                       (cons _%$%g5441354424%_
                                                             '())))
                                           (cons (gx#datum->syntax '#f ':-)
                                                 (cons _%$%g5415054390%_
                                                       (cons _%$%g5441354424%_
                                                             '()))))))))
                           (_%$%g5441154446%_ _%base54408%_)))))))
                (_%__kont100153100154%_
                 (lambda (_%$%g5416354216%_ _%$%g5416454218%_)
                   (let ((_g107391_
                          (let ()
                            (declare (not safe))
                            (|gerbil/core/contract~TypeReference[1]#resolve-return-type|
                             _%stx54142%_
                             _%$%g5416354216%_))))
                     (begin
                       (let ((_g107392_
                              (let ()
                                (declare (not safe))
                                (if (##values? _g107391_)
                                    (##values-length _g107391_)
                                    1))))
                         (if (not (let ()
                                    (declare (not safe))
                                    (##fx= _g107392_ 2)))
                             (error "Context expects 2 values" _g107392_)))
                       (let ((_%base54235%_
                              (let ()
                                (declare (not safe))
                                (##values-ref _g107391_ 0)))
                             (_%maybe?54237%_
                              (let ()
                                (declare (not safe))
                                (##values-ref _g107391_ 1))))
                         (if _%maybe?54237%_
                             (let* ((_%meta54239%_
                                     (let ()
                                       (declare (not safe))
                                       (|gerbil/core/contract~TypeReference[1]#resolve-type|
                                        _%stx54142%_
                                        _%base54235%_)))
                                    (_%$%g5424254257%_
                                     (lambda (_%$%g5424354253%_)
                                       (gx#raise-syntax-error
                                        '#f
                                        '"Bad syntax; invalid match target"
                                        _%$%g5424354253%_)))
                                    (_%$%g5424154336%_
                                     (lambda (_%$%g5424354261%_)
                                       (if (gx#stx-pair? _%$%g5424354261%_)
                                           (let ((_%$%e5424654264%_
                                                  (gx#syntax-e
                                                   _%$%g5424354261%_)))
                                             (let ((_%$%hd5424754268%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e5424654264%_)))
                                                   (_%$%tl5424854271%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e5424654264%_))))
                                               (if (gx#stx-pair?
                                                    _%$%tl5424854271%_)
                                                   (let ((_%$%e5424954274%_
                                                          (gx#syntax-e
                                                           _%$%tl5424854271%_)))
                                                     (let ((_%$%hd5425054278%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e5424954274%_)))
                                                           (_%$%tl5425154281%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e5424954274%_))))
                                                       (if (gx#stx-null?
                                                            _%$%tl5425154281%_)
                                                           (if (and (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (declare (not safe))
                              (class-instance?
                               gerbil/core/mop~MOP-2#class-type-info::t
                               _%meta54239%_))
                            (eq? (let ((__obj107197 _%meta54239%_))
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-direct-instance-of?
                                          __obj107197
                                          'gerbil/core#class-type-info::t))
                                       (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          __obj107197
                                          '2
                                          '#f
                                          '#f))
                                       (unchecked-slot-ref __obj107197 'id)))
                                 'void))
                       (let* ((_%$%g5430454312%_
                               (lambda (_%$%g5430554308%_)
                                 (gx#raise-syntax-error
                                  '#f
                                  '"Bad syntax; invalid match target"
                                  _%$%g5430554308%_)))
                              (_%$%g5430354332%_
                               (lambda (_%$%g5430554316%_)
                                 (cons (gx#datum->syntax '#f 'begin-annotation)
                                       (cons (cons (gx#datum->syntax
                                                    '#f
                                                    '@type)
                                                   (cons (cons (gx#datum->syntax
                                                                '#f
                                                                'nullable)
                                                               (cons _%$%hd5425054278%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '()))
                 '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             (cons (cons (gx#datum->syntax
                                                          '#f
                                                          'let)
                                                         (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '#f
                              'val)
                             (cons (cons (gx#datum->syntax
                                          '#f
                                          'begin-annotation)
                                         (cons (cons (gx#datum->syntax
                                                      '#f
                                                      '@type.return)
                                                     (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#f
                          'nullable)
                         (cons _%$%hd5425054278%_ '()))
                   '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (cons _%$%g5416454218%_ '())))
                                   '()))
                       (cons (cons (gx#datum->syntax '#f 'if)
                                   (cons (cons (gx#datum->syntax '#f 'or)
                                               (cons (cons (gx#datum->syntax
                                                            '#f
                                                            'not)
                                                           (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#f
                          'val)
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons _%$%g5430554316%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (gx#datum->syntax '#f 'val) '()))
                   '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         (cons (gx#datum->syntax '#f 'val)
                                               (cons (cons (gx#datum->syntax
                                                            '#f
                                                            'contract-violation!)
                                                           (cons _%$%g5416454218%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (cons _%$%g5430554316%_
                                     (cons (gx#datum->syntax '#f 'val) '()))
                               (cons (gx#datum->syntax '#f 'val) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '()))))
                             '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   '()))))))
                         (_%$%g5430354332%_
                          (let ((__obj107198 _%meta54239%_))
                            (if (let ()
                                  (declare (not safe))
                                  (##structure-direct-instance-of?
                                   __obj107198
                                   'gerbil/core#class-type-info::t))
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   __obj107198
                                   '15
                                   '#f
                                   '#f))
                                (class-slot-ref
                                 gerbil/core/mop~MOP-2#class-type-info::t
                                 __obj107198
                                 'predicate)))))
                       (cons (gx#datum->syntax '#f ':?)
                             (cons (cons (gx#datum->syntax
                                          '#f
                                          'begin-annotation)
                                         (cons (cons (gx#datum->syntax
                                                      '#f
                                                      '@type.return)
                                                     (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#f
                          'nullable)
                         (cons _%$%hd5425054278%_ '()))
                   '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (cons _%$%g5416454218%_ '())))
                                   (cons _%$%hd5424754268%_ '()))))
                   (_%$%g5424254257%_ _%$%g5424354261%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g5424254257%_
                                                    _%$%g5424354261%_))))
                                           (_%$%g5424254257%_
                                            _%$%g5424354261%_)))))
                               (_%$%g5424154336%_
                                (list _%base54235%_
                                      (let ()
                                        (declare (not safe))
                                        (|gerbil/core/contract~TypeReference[1]#resolve-type->type-descriptor|
                                         _%stx54142%_
                                         _%base54235%_)))))
                             _%$%g5416454218%_)))))))
            (if (gx#stx-pair? _%__stx100148100149%_)
                (let ((_%$%e5415154347%_ (gx#syntax-e _%__stx100148100149%_)))
                  (let ((_%$%tl5415354354%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e5415154347%_)))
                        (_%$%hd5415254351%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e5415154347%_))))
                    (if (gx#stx-pair? _%$%tl5415354354%_)
                        (let ((_%$%e5415454357%_
                               (gx#syntax-e _%$%tl5415354354%_)))
                          (let ((_%$%tl5415654364%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e5415454357%_)))
                                (_%$%hd5415554361%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e5415454357%_))))
                            (if (gx#stx-pair? _%$%tl5415654364%_)
                                (let ((_%$%e5415754367%_
                                       (gx#syntax-e _%$%tl5415654364%_)))
                                  (let ((_%$%tl5415954374%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e5415754367%_)))
                                        (_%$%hd5415854371%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e5415754367%_))))
                                    (if (gx#stx-pair? _%$%tl5415954374%_)
                                        (let ((_%$%e5416054377%_
                                               (gx#syntax-e
                                                _%$%tl5415954374%_)))
                                          (let ((_%$%tl5416254384%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e5416054377%_)))
                                                (_%$%hd5416154381%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e5416054377%_))))
                                            (if (gx#stx-null?
                                                 _%$%tl5416254384%_)
                                                (_%__kont100151100152%_
                                                 _%$%hd5416154381%_
                                                 _%$%hd5415854371%_
                                                 _%$%hd5415554361%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g5414654179%_)))))
                                        (if (gx#stx-null? _%$%tl5415954374%_)
                                            (_%__kont100153100154%_
                                             _%$%hd5415854371%_
                                             _%$%hd5415554361%_)
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5414654179%_))))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5414654179%_)))))
                        (let () (declare (not safe)) (_%$%g5414654179%_)))))
                (let () (declare (not safe)) (_%$%g5414654179%_)))))))
    (define |gerbil/core/contract~TypeCast[:0:]#:|
      (lambda (_%stx54456%_)
        (let* ((_%__stx100204100205%_ _%stx54456%_)
               (_%$%g5446054493%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx100204100205%_))))
          (let ((_%__kont100207100208%_
                 (lambda (_%$%g5446254741%_ _%$%g5446354743%_)
                   (let ((_%meta54758%_
                          (let ()
                            (declare (not safe))
                            (|gerbil/core/contract~TypeReference[1]#resolve-type|
                             _%stx54456%_
                             _%$%g5446254741%_))))
                     (if (let ()
                           (declare (not safe))
                           (class-instance?
                            gerbil/core/mop~MOP-2#class-type-info::t
                            _%meta54758%_))
                         (let* ((_%$%g5476354778%_
                                 (lambda (_%$%g5476454774%_)
                                   (gx#raise-syntax-error
                                    '#f
                                    '"Bad syntax; invalid match target"
                                    _%$%g5476454774%_)))
                                (_%$%g5476254825%_
                                 (lambda (_%$%g5476454782%_)
                                   (if (gx#stx-pair? _%$%g5476454782%_)
                                       (let ((_%$%e5476754785%_
                                              (gx#syntax-e _%$%g5476454782%_)))
                                         (let ((_%$%hd5476854789%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e5476754785%_)))
                                               (_%$%tl5476954792%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e5476754785%_))))
                                           (if (gx#stx-pair?
                                                _%$%tl5476954792%_)
                                               (let ((_%$%e5477054795%_
                                                      (gx#syntax-e
                                                       _%$%tl5476954792%_)))
                                                 (let ((_%$%hd5477154799%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e5477054795%_)))
                                                       (_%$%tl5477254802%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e5477054795%_))))
                                                   (if (gx#stx-null?
                                                        _%$%tl5477254802%_)
                                                       (if (let ((__tmp107393
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ((__obj107200 _%meta54758%_))
                            (if (let ()
                                  (declare (not safe))
                                  (##structure-direct-instance-of?
                                   __obj107200
                                   'gerbil/core#class-type-info::t))
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   __obj107200
                                   '2
                                   '#f
                                   '#f))
                                (unchecked-slot-ref __obj107200 'id)))))
                     (declare (not safe))
                     (##memq __tmp107393 '(t void)))
                   (cons (gx#datum->syntax '#f 'begin-annotation)
                         (cons (cons (gx#datum->syntax '#f '@type)
                                     (cons _%$%hd5476854789%_ '()))
                               (cons _%$%g5446354743%_ '())))
                   (cons (gx#datum->syntax '#f 'begin-annotation)
                         (cons (cons (gx#datum->syntax '#f '@type)
                                     (cons _%$%hd5476854789%_ '()))
                               (cons (cons (gx#datum->syntax '#f 'let)
                                           (cons (cons (gx#datum->syntax
                                                        '#f
                                                        'val)
                                                       (cons _%$%g5446354743%_
                                                             '()))
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'if)
                                                             (cons (cons _%$%hd5477154799%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons (gx#datum->syntax '#f 'val) '()))
                           (cons (gx#datum->syntax '#f 'val)
                                 (cons (cons (gx#datum->syntax
                                              '#f
                                              'contract-violation!)
                                             (cons _%$%g5446354743%_
                                                   (cons (cons _%$%hd5477154799%_
                                                               (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '#f
                              'val)
                             '()))
                 (cons (gx#datum->syntax '#f 'val) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       '()))))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '()))))
               (_%$%g5476354778%_ _%$%g5476454782%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g5476354778%_
                                                _%$%g5476454782%_))))
                                       (_%$%g5476354778%_
                                        _%$%g5476454782%_)))))
                           (_%$%g5476254825%_
                            (list (let ((__obj107201 _%meta54758%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##structure-direct-instance-of?
                                           __obj107201
                                           'gerbil/core#class-type-info::t))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           __obj107201
                                           '4
                                           '#f
                                           '#f))
                                        (unchecked-slot-ref
                                         __obj107201
                                         'type-descriptor)))
                                  (let ((__obj107202 _%meta54758%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##structure-direct-instance-of?
                                           __obj107202
                                           'gerbil/core#class-type-info::t))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           __obj107202
                                           '15
                                           '#f
                                           '#f))
                                        (unchecked-slot-ref
                                         __obj107202
                                         'predicate))))))
                         (if (let ()
                               (declare (not safe))
                               (class-instance?
                                gerbil/core/contract~InterfaceInfo#interface-info::t
                                _%meta54758%_))
                             (let* ((_%$%g5483154846%_
                                     (lambda (_%$%g5483254842%_)
                                       (gx#raise-syntax-error
                                        '#f
                                        '"Bad syntax; invalid match target"
                                        _%$%g5483254842%_)))
                                    (_%$%g5483054891%_
                                     (lambda (_%$%g5483254850%_)
                                       (if (gx#stx-pair? _%$%g5483254850%_)
                                           (let ((_%$%e5483554853%_
                                                  (gx#syntax-e
                                                   _%$%g5483254850%_)))
                                             (let ((_%$%hd5483654857%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e5483554853%_)))
                                                   (_%$%tl5483754860%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e5483554853%_))))
                                               (if (gx#stx-pair?
                                                    _%$%tl5483754860%_)
                                                   (let ((_%$%e5483854863%_
                                                          (gx#syntax-e
                                                           _%$%tl5483754860%_)))
                                                     (let ((_%$%hd5483954867%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e5483854863%_)))
                                                           (_%$%tl5484054870%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e5483854863%_))))
                                                       (if (gx#stx-null?
                                                            _%$%tl5484054870%_)
                                                           (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#f
                          'begin-annotation)
                         (cons (cons (gx#datum->syntax '#f '@type)
                                     (cons _%$%hd5483654857%_ '()))
                               (cons (cons _%$%hd5483954867%_
                                           (cons _%$%g5446354743%_ '()))
                                     '())))
                   (_%$%g5483154846%_ _%$%g5483254850%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g5483154846%_
                                                    _%$%g5483254850%_))))
                                           (_%$%g5483154846%_
                                            _%$%g5483254850%_)))))
                               (_%$%g5483054891%_
                                (list (let ((__obj107199 _%meta54758%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (##structure-direct-instance-of?
                                               __obj107199
                                               'gerbil/core#runtime-type-info::t))
                                            (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               __obj107199
                                               '3
                                               '#f
                                               '#f))
                                            (unchecked-slot-ref
                                             __obj107199
                                             'type-descriptor)))
                                      (let ()
                                        (declare (not safe))
                                        (|gerbil/core/contract~TypeReference[1]#resolve-type->identifier|
                                         _%stx54456%_
                                         _%$%g5446254741%_)))))
                             (gx#raise-syntax-error
                              '#f
                              '"not a class type or interface"
                              _%stx54456%_
                              _%$%g5446254741%_))))))
                (_%__kont100209100210%_
                 (lambda (_%$%g5447354544%_ _%$%g5447454546%_)
                   (let ((_%meta54565%_
                          (let ()
                            (declare (not safe))
                            (|gerbil/core/contract~TypeReference[1]#resolve-type|
                             _%stx54456%_
                             _%$%g5447354544%_))))
                     (if (let ()
                           (declare (not safe))
                           (class-instance?
                            gerbil/core/mop~MOP-2#class-type-info::t
                            _%meta54565%_))
                         (let* ((_%$%g5457054585%_
                                 (lambda (_%$%g5457154581%_)
                                   (gx#raise-syntax-error
                                    '#f
                                    '"Bad syntax; invalid match target"
                                    _%$%g5457154581%_)))
                                (_%$%g5456954632%_
                                 (lambda (_%$%g5457154589%_)
                                   (if (gx#stx-pair? _%$%g5457154589%_)
                                       (let ((_%$%e5457454592%_
                                              (gx#syntax-e _%$%g5457154589%_)))
                                         (let ((_%$%hd5457554596%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e5457454592%_)))
                                               (_%$%tl5457654599%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e5457454592%_))))
                                           (if (gx#stx-pair?
                                                _%$%tl5457654599%_)
                                               (let ((_%$%e5457754602%_
                                                      (gx#syntax-e
                                                       _%$%tl5457654599%_)))
                                                 (let ((_%$%hd5457854606%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e5457754602%_)))
                                                       (_%$%tl5457954609%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e5457754602%_))))
                                                   (if (gx#stx-null?
                                                        _%$%tl5457954609%_)
                                                       (if (let ((__tmp107394
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ((__obj107204 _%meta54565%_))
                            (if (let ()
                                  (declare (not safe))
                                  (##structure-direct-instance-of?
                                   __obj107204
                                   'gerbil/core#class-type-info::t))
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   __obj107204
                                   '2
                                   '#f
                                   '#f))
                                (unchecked-slot-ref __obj107204 'id)))))
                     (declare (not safe))
                     (##memq __tmp107394 '(t void)))
                   (cons (gx#datum->syntax '#f 'begin-annotation)
                         (cons (cons (gx#datum->syntax '#f '@type)
                                     (cons _%$%hd5457554596%_ '()))
                               (cons _%$%g5447454546%_ '())))
                   (cons (gx#datum->syntax '#f 'begin-annotation)
                         (cons (cons (gx#datum->syntax '#f '@type)
                                     (cons _%$%hd5457554596%_ '()))
                               (cons (cons (gx#datum->syntax '#f 'let)
                                           (cons (cons (gx#datum->syntax
                                                        '#f
                                                        'val)
                                                       (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'begin-annotation)
                           (cons (cons (gx#datum->syntax '#f '@type)
                                       (cons (gx#datum->syntax '#f 't::t) '()))
                                 (cons _%$%g5447454546%_ '())))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'if)
                                                             (cons (cons _%$%hd5457854606%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons (gx#datum->syntax '#f 'val) '()))
                           (cons (gx#datum->syntax '#f 'val)
                                 (cons (cons (gx#datum->syntax
                                              '#f
                                              'runtime-contract-violation!)
                                             (cons _%$%g5447454546%_
                                                   (cons (cons _%$%hd5457854606%_
                                                               (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '#f
                              'val)
                             '()))
                 (cons (gx#datum->syntax '#f 'val) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       '()))))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '()))))
               (_%$%g5457054585%_ _%$%g5457154589%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g5457054585%_
                                                _%$%g5457154589%_))))
                                       (_%$%g5457054585%_
                                        _%$%g5457154589%_)))))
                           (_%$%g5456954632%_
                            (list (let ((__obj107205 _%meta54565%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##structure-direct-instance-of?
                                           __obj107205
                                           'gerbil/core#class-type-info::t))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           __obj107205
                                           '4
                                           '#f
                                           '#f))
                                        (unchecked-slot-ref
                                         __obj107205
                                         'type-descriptor)))
                                  (let ((__obj107206 _%meta54565%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##structure-direct-instance-of?
                                           __obj107206
                                           'gerbil/core#class-type-info::t))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           __obj107206
                                           '15
                                           '#f
                                           '#f))
                                        (unchecked-slot-ref
                                         __obj107206
                                         'predicate))))))
                         (if (let ()
                               (declare (not safe))
                               (class-instance?
                                gerbil/core/contract~InterfaceInfo#interface-info::t
                                _%meta54565%_))
                             (let* ((_%$%g5463854653%_
                                     (lambda (_%$%g5463954649%_)
                                       (gx#raise-syntax-error
                                        '#f
                                        '"Bad syntax; invalid match target"
                                        _%$%g5463954649%_)))
                                    (_%$%g5463754698%_
                                     (lambda (_%$%g5463954657%_)
                                       (if (gx#stx-pair? _%$%g5463954657%_)
                                           (let ((_%$%e5464254660%_
                                                  (gx#syntax-e
                                                   _%$%g5463954657%_)))
                                             (let ((_%$%hd5464354664%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e5464254660%_)))
                                                   (_%$%tl5464454667%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e5464254660%_))))
                                               (if (gx#stx-pair?
                                                    _%$%tl5464454667%_)
                                                   (let ((_%$%e5464554670%_
                                                          (gx#syntax-e
                                                           _%$%tl5464454667%_)))
                                                     (let ((_%$%hd5464654674%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e5464554670%_)))
                                                           (_%$%tl5464754677%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e5464554670%_))))
                                                       (if (gx#stx-null?
                                                            _%$%tl5464754677%_)
                                                           (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#f
                          'begin-annotation)
                         (cons (cons (gx#datum->syntax '#f '@type)
                                     (cons _%$%hd5464354664%_ '()))
                               (cons (cons _%$%hd5464654674%_
                                           (cons _%$%g5447454546%_ '()))
                                     '())))
                   (_%$%g5463854653%_ _%$%g5463954657%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g5463854653%_
                                                    _%$%g5463954657%_))))
                                           (_%$%g5463854653%_
                                            _%$%g5463954657%_)))))
                               (_%$%g5463754698%_
                                (list (let ((__obj107203 _%meta54565%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (##structure-direct-instance-of?
                                               __obj107203
                                               'gerbil/core#runtime-type-info::t))
                                            (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               __obj107203
                                               '3
                                               '#f
                                               '#f))
                                            (unchecked-slot-ref
                                             __obj107203
                                             'type-descriptor)))
                                      (let ()
                                        (declare (not safe))
                                        (|gerbil/core/contract~TypeReference[1]#resolve-type->identifier|
                                         _%stx54456%_
                                         _%$%g5447354544%_)))))
                             (gx#raise-syntax-error
                              '#f
                              '"not a class type or interface"
                              _%stx54456%_
                              _%$%g5447354544%_)))))))
            (let* ((_%__match100263100264%_
                    (lambda (_%$%e5447554500%_
                             _%$%hd5447654504%_
                             _%$%tl5447754507%_
                             _%$%e5447854510%_
                             _%$%hd5447954514%_
                             _%$%tl5448054517%_
                             _%$%e5448154520%_
                             _%$%hd5448254524%_
                             _%$%tl5448354527%_
                             _%$%e5448454530%_
                             _%$%e5448554534%_
                             _%$%hd5448654538%_
                             _%$%tl5448754541%_)
                      (let ((_%$%g5447354544%_ _%$%hd5448654538%_)
                            (_%$%g5447454546%_ _%$%hd5447954514%_))
                        (if (gx#identifier? _%$%g5447354544%_)
                            (_%__kont100209100210%_
                             _%$%g5447354544%_
                             _%$%g5447454546%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g5446054493%_))))))
                   (_%__match100231100232%_
                    (lambda (_%$%e5446454711%_
                             _%$%hd5446554715%_
                             _%$%tl5446654718%_
                             _%$%e5446754721%_
                             _%$%hd5446854725%_
                             _%$%tl5446954728%_
                             _%$%e5447054731%_
                             _%$%hd5447154735%_
                             _%$%tl5447254738%_)
                      (let ((_%$%g5446254741%_ _%$%hd5447154735%_)
                            (_%$%g5446354743%_ _%$%hd5446854725%_))
                        (if (gx#identifier? _%$%g5446254741%_)
                            (_%__kont100207100208%_
                             _%$%g5446254741%_
                             _%$%g5446354743%_)
                            (if (gx#stx-datum? _%$%hd5447154735%_)
                                (let ((_%$%e5448454530%_
                                       (gx#stx-e _%$%hd5447154735%_)))
                                  (declare (not safe))
                                  (_%$%g5446054493%_))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5446054493%_))))))))
              (if (gx#stx-pair? _%__stx100204100205%_)
                  (let ((_%$%e5446454711%_
                         (gx#syntax-e _%__stx100204100205%_)))
                    (let ((_%$%tl5446654718%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5446454711%_)))
                          (_%$%hd5446554715%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5446454711%_))))
                      (if (gx#stx-pair? _%$%tl5446654718%_)
                          (let ((_%$%e5446754721%_
                                 (gx#syntax-e _%$%tl5446654718%_)))
                            (let ((_%$%tl5446954728%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5446754721%_)))
                                  (_%$%hd5446854725%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5446754721%_))))
                              (if (gx#stx-pair? _%$%tl5446954728%_)
                                  (let ((_%$%e5447054731%_
                                         (gx#syntax-e _%$%tl5446954728%_)))
                                    (let ((_%$%tl5447254738%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5447054731%_)))
                                          (_%$%hd5447154735%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5447054731%_))))
                                      (if (gx#stx-null? _%$%tl5447254738%_)
                                          (_%__match100231100232%_
                                           _%$%e5446454711%_
                                           _%$%hd5446554715%_
                                           _%$%tl5446654718%_
                                           _%$%e5446754721%_
                                           _%$%hd5446854725%_
                                           _%$%tl5446954728%_
                                           _%$%e5447054731%_
                                           _%$%hd5447154735%_
                                           _%$%tl5447254738%_)
                                          (if (gx#stx-datum?
                                               _%$%hd5447154735%_)
                                              (let ((_%$%e5448454530%_
                                                     (gx#stx-e
                                                      _%$%hd5447154735%_)))
                                                (if (equal? _%$%e5448454530%_
                                                            'runtime:)
                                                    (if (gx#stx-pair?
                                                         _%$%tl5447254738%_)
                                                        (let ((_%$%e5448554534%_
                                                               (gx#syntax-e
                                                                _%$%tl5447254738%_)))
                                                          (let ((_%$%tl5448754541%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e5448554534%_)))
                        (_%$%hd5448654538%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e5448554534%_))))
                    (if (gx#stx-null? _%$%tl5448754541%_)
                        (_%__match100263100264%_
                         _%$%e5446454711%_
                         _%$%hd5446554715%_
                         _%$%tl5446654718%_
                         _%$%e5446754721%_
                         _%$%hd5446854725%_
                         _%$%tl5446954728%_
                         _%$%e5447054731%_
                         _%$%hd5447154735%_
                         _%$%tl5447254738%_
                         _%$%e5448454530%_
                         _%$%e5448554534%_
                         _%$%hd5448654538%_
                         _%$%tl5448754541%_)
                        (let () (declare (not safe)) (_%$%g5446054493%_)))))
                (let () (declare (not safe)) (_%$%g5446054493%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g5446054493%_))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5446054493%_))))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5446054493%_)))))
                          (let () (declare (not safe)) (_%$%g5446054493%_)))))
                  (let () (declare (not safe)) (_%$%g5446054493%_))))))))
    (define |gerbil/core/contract~TypeCast[:0:]#:?|
      (lambda (_%stx54901%_)
        (let* ((_%$%g5490454922%_
                (lambda (_%$%g5490554918%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5490554918%_)))
               (_%$%g5490355116%_
                (lambda (_%$%g5490554926%_)
                  (if (gx#stx-pair? _%$%g5490554926%_)
                      (let ((_%$%e5490854929%_
                             (gx#syntax-e _%$%g5490554926%_)))
                        (let ((_%$%hd5490954933%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5490854929%_)))
                              (_%$%tl5491054936%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5490854929%_))))
                          (if (gx#stx-pair? _%$%tl5491054936%_)
                              (let ((_%$%e5491154939%_
                                     (gx#syntax-e _%$%tl5491054936%_)))
                                (let ((_%$%hd5491254943%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5491154939%_)))
                                      (_%$%tl5491354946%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5491154939%_))))
                                  (if (gx#stx-pair? _%$%tl5491354946%_)
                                      (let ((_%$%e5491454949%_
                                             (gx#syntax-e _%$%tl5491354946%_)))
                                        (let ((_%$%hd5491554953%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5491454949%_)))
                                              (_%$%tl5491654956%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5491454949%_))))
                                          (if (gx#stx-null? _%$%tl5491654956%_)
                                              (if (gx#identifier?
                                                   _%$%hd5491554953%_)
                                                  (let ((_%meta54977%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (|gerbil/core/contract~TypeReference[1]#resolve-type|
                                                            _%stx54901%_
                                                            _%$%hd5491554953%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (class-instance?
                                                           gerbil/core/mop~MOP-2#class-type-info::t
                                                           _%meta54977%_))
                                                        (let* ((_%$%g5498254997%_
                                                                (lambda (_%$%g5498354993%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (gx#raise-syntax-error
                           '#f
                           '"Bad syntax; invalid match target"
                           _%$%g5498354993%_)))
                       (_%$%g5498155044%_
                        (lambda (_%$%g5498355001%_)
                          (if (gx#stx-pair? _%$%g5498355001%_)
                              (let ((_%$%e5498655004%_
                                     (gx#syntax-e _%$%g5498355001%_)))
                                (let ((_%$%hd5498755008%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5498655004%_)))
                                      (_%$%tl5498855011%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5498655004%_))))
                                  (if (gx#stx-pair? _%$%tl5498855011%_)
                                      (let ((_%$%e5498955014%_
                                             (gx#syntax-e _%$%tl5498855011%_)))
                                        (let ((_%$%hd5499055018%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5498955014%_)))
                                              (_%$%tl5499155021%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5498955014%_))))
                                          (if (gx#stx-null? _%$%tl5499155021%_)
                                              (if (let ((__tmp107395
                                                         (let ((__obj107208
                                                                _%meta54977%_))
                                                           (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##structure-direct-instance-of?
                          __obj107208
                          'gerbil/core#class-type-info::t))
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref __obj107208 '2 '#f '#f))
                       (unchecked-slot-ref __obj107208 'id)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (##memq __tmp107395
                                                            '(t void)))
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'begin-annotation)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             '@type)
                            (cons (cons (gx#datum->syntax '#f 'nullable)
                                        (cons _%$%hd5498755008%_ '()))
                                  '()))
                      (cons _%$%hd5491254943%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'begin-annotation)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             '@type)
                            (cons (cons (gx#datum->syntax '#f 'nullable)
                                        (cons _%$%hd5498755008%_ '()))
                                  '()))
                      (cons (cons (gx#datum->syntax '#f 'let)
                                  (cons (cons (gx#datum->syntax '#f 'val)
                                              (cons _%$%hd5491254943%_ '()))
                                        (cons (cons (gx#datum->syntax '#f 'if)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'or)
                        (cons (cons (gx#datum->syntax '#f 'not)
                                    (cons (gx#datum->syntax '#f 'val) '()))
                              (cons (cons _%$%hd5499055018%_
                                          (cons (gx#datum->syntax '#f 'val)
                                                '()))
                                    '())))
                  (cons (gx#datum->syntax '#f 'val)
                        (cons (cons (gx#datum->syntax '#f 'contract-violation!)
                                    (cons _%$%hd5491254943%_
                                          (cons (cons _%$%hd5499055018%_
                                                      (cons (gx#datum->syntax
                                                             '#f
                                                             'val)
                                                            '()))
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'val)
                                                      '()))))
                              '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))
                            '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g5498254997%_
                                               _%$%g5498355001%_))))
                                      (_%$%g5498254997%_ _%$%g5498355001%_))))
                              (_%$%g5498254997%_ _%$%g5498355001%_)))))
                  (_%$%g5498155044%_
                   (list (let ((__obj107209 _%meta54977%_))
                           (if (let ()
                                 (declare (not safe))
                                 (##structure-direct-instance-of?
                                  __obj107209
                                  'gerbil/core#class-type-info::t))
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  __obj107209
                                  '4
                                  '#f
                                  '#f))
                               (unchecked-slot-ref
                                __obj107209
                                'type-descriptor)))
                         (let ((__obj107210 _%meta54977%_))
                           (if (let ()
                                 (declare (not safe))
                                 (##structure-direct-instance-of?
                                  __obj107210
                                  'gerbil/core#class-type-info::t))
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  __obj107210
                                  '15
                                  '#f
                                  '#f))
                               (unchecked-slot-ref __obj107210 'predicate))))))
                (if (let ()
                      (declare (not safe))
                      (class-instance?
                       gerbil/core/contract~InterfaceInfo#interface-info::t
                       _%meta54977%_))
                    (let* ((_%$%g5505055065%_
                            (lambda (_%$%g5505155061%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%$%g5505155061%_)))
                           (_%$%g5504955110%_
                            (lambda (_%$%g5505155069%_)
                              (if (gx#stx-pair? _%$%g5505155069%_)
                                  (let ((_%$%e5505455072%_
                                         (gx#syntax-e _%$%g5505155069%_)))
                                    (let ((_%$%hd5505555076%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5505455072%_)))
                                          (_%$%tl5505655079%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5505455072%_))))
                                      (if (gx#stx-pair? _%$%tl5505655079%_)
                                          (let ((_%$%e5505755082%_
                                                 (gx#syntax-e
                                                  _%$%tl5505655079%_)))
                                            (let ((_%$%hd5505855086%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e5505755082%_)))
                                                  (_%$%tl5505955089%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e5505755082%_))))
                                              (if (gx#stx-null?
                                                   _%$%tl5505955089%_)
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'begin-annotation)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             '@type)
                            (cons (cons (gx#datum->syntax '#f 'nullable)
                                        (cons _%$%hd5505555076%_ '()))
                                  '()))
                      (cons (cons (gx#datum->syntax '#f 'let)
                                  (cons (cons (gx#datum->syntax '#f 'val)
                                              (cons _%$%hd5491254943%_ '()))
                                        (cons (cons (gx#datum->syntax '#f 'and)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'val)
                                                          (cons (cons _%$%hd5505855086%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (gx#datum->syntax '#f 'val) '()))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5505055065%_
                                                   _%$%g5505155069%_))))
                                          (_%$%g5505055065%_
                                           _%$%g5505155069%_))))
                                  (_%$%g5505055065%_ _%$%g5505155069%_)))))
                      (_%$%g5504955110%_
                       (list (let ((__obj107207 _%meta54977%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-direct-instance-of?
                                      __obj107207
                                      'gerbil/core#runtime-type-info::t))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      __obj107207
                                      '3
                                      '#f
                                      '#f))
                                   (unchecked-slot-ref
                                    __obj107207
                                    'type-descriptor)))
                             (let ()
                               (declare (not safe))
                               (|gerbil/core/contract~TypeReference[1]#resolve-type->identifier|
                                _%stx54901%_
                                _%$%hd5491554953%_)))))
                    (gx#raise-syntax-error
                     '#f
                     '"not a class type or interface"
                     _%stx54901%_
                     _%$%hd5491554953%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5490454922%_
                                                   _%$%g5490554926%_))
                                              (_%$%g5490454922%_
                                               _%$%g5490554926%_))))
                                      (_%$%g5490454922%_ _%$%g5490554926%_))))
                              (_%$%g5490454922%_ _%$%g5490554926%_))))
                      (_%$%g5490454922%_ _%$%g5490554926%_)))))
          (_%$%g5490355116%_ _%stx54901%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#:-|
      (lambda (_%stx55120%_)
        (let* ((_%$%g5512355141%_
                (lambda (_%$%g5512455137%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5512455137%_)))
               (_%$%g5512255227%_
                (lambda (_%$%g5512455145%_)
                  (if (gx#stx-pair? _%$%g5512455145%_)
                      (let ((_%$%e5512755148%_
                             (gx#syntax-e _%$%g5512455145%_)))
                        (let ((_%$%hd5512855152%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5512755148%_)))
                              (_%$%tl5512955155%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5512755148%_))))
                          (if (gx#stx-pair? _%$%tl5512955155%_)
                              (let ((_%$%e5513055158%_
                                     (gx#syntax-e _%$%tl5512955155%_)))
                                (let ((_%$%hd5513155162%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5513055158%_)))
                                      (_%$%tl5513255165%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5513055158%_))))
                                  (if (gx#stx-pair? _%$%tl5513255165%_)
                                      (let ((_%$%e5513355168%_
                                             (gx#syntax-e _%$%tl5513255165%_)))
                                        (let ((_%$%hd5513455172%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5513355168%_)))
                                              (_%$%tl5513555175%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5513355168%_))))
                                          (if (gx#stx-null? _%$%tl5513555175%_)
                                              (if (gx#identifier?
                                                   _%$%hd5513455172%_)
                                                  (let* ((_%$%g5519655204%_
                                                          (lambda (_%$%g5519755200%_)
                                                            (gx#raise-syntax-error
                                                             '#f
                                                             '"Bad syntax; invalid match target"
                                                             _%$%g5519755200%_)))
                                                         (_%$%g5519555223%_
                                                          (lambda (_%$%g5519755208%_)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'begin-annotation)
                          (cons (cons (gx#datum->syntax '#f '@type)
                                      (cons _%$%g5519755208%_ '()))
                                (cons _%$%hd5513155162%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g5519555223%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (|gerbil/core/contract~TypeReference[1]#resolve-type->type-descriptor|
                                                        _%stx55120%_
                                                        _%$%hd5513455172%_))))
                                                  (_%$%g5512355141%_
                                                   _%$%g5512455145%_))
                                              (_%$%g5512355141%_
                                               _%$%g5512455145%_))))
                                      (_%$%g5512355141%_ _%$%g5512455145%_))))
                              (_%$%g5512355141%_ _%$%g5512455145%_))))
                      (_%$%g5512355141%_ _%$%g5512455145%_)))))
          (_%$%g5512255227%_ _%stx55120%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#do-with-lock|
      (lambda (_%$stx55231%_)
        (let* ((_%__stx100266100267%_ _%$stx55231%_)
               (_%$%g5523755321%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx100266100267%_))))
          (let ((_%__kont100269100270%_
                 (lambda (_%$%g5523955625%_
                          _%$%g5524055627%_
                          _%$%g5524155628%_
                          _%$%g5524255629%_)
                   (cons (gx#datum->syntax '#f ':-)
                         (cons (cons (gx#datum->syntax '#f 'do-with-lock)
                                     (cons _%$%g5524255629%_
                                           (cons _%$%g5524055627%_
                                                 (foldr (lambda (_%$%g5565355656%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g5565455659%_)
                  (cons _%$%g5565355656%_ _%$%g5565455659%_))
                '()
                _%$%g5523955625%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                               (cons _%$%g5524155628%_ '())))))
                (_%__kont100273100274%_
                 (lambda (_%$%g5526755503%_
                          _%$%g5526855505%_
                          _%$%g5526955506%_
                          _%$%g5527055507%_)
                   (cons (gx#datum->syntax '#f ':)
                         (cons (cons (gx#datum->syntax '#f 'do-with-lock)
                                     (cons _%$%g5527055507%_
                                           (cons _%$%g5526855505%_
                                                 (foldr (lambda (_%$%g5553155534%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g5553255537%_)
                  (cons _%$%g5553155534%_ _%$%g5553255537%_))
                '()
                _%$%g5526755503%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                               (cons _%$%g5526955506%_ '())))))
                (_%__kont100277100278%_
                 (lambda (_%$%g5529555386%_
                          _%$%g5529655388%_
                          _%$%g5529755389%_)
                   (cons (gx#datum->syntax '#f 'with-lock)
                         (cons _%$%g5529755389%_
                               (cons (cons (gx#datum->syntax '#f 'lambda)
                                           (cons '()
                                                 (cons _%$%g5529655388%_
                                                       (foldr (lambda (_%$%g5540955412%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               _%$%g5541055415%_)
                        (cons _%$%g5540955412%_ _%$%g5541055415%_))
                      '()
                      _%$%g5529555386%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '()))))))
            (let* ((_%__match100391100392%_
                    (lambda (_%$%e5529855328%_
                             _%$%hd5529955332%_
                             _%$%tl5530055335%_
                             _%$%e5530155338%_
                             _%$%hd5530255342%_
                             _%$%tl5530355345%_
                             _%$%e5530455348%_
                             _%$%hd5530555352%_
                             _%$%tl5530655355%_
                             _%__splice100279100280%_
                             _%$%target5530755358%_
                             _%$%tl5530955361%_)
                      (letrec ((_%$%loop5531055364%_
                                (lambda (_%$%hd5530855368%_
                                         _%$%rest5531455371%_)
                                  (if (gx#stx-pair? _%$%hd5530855368%_)
                                      (let ((_%$%e5531155373%_
                                             (gx#syntax-e _%$%hd5530855368%_)))
                                        (let ((_%$%lp-tl5531355380%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5531155373%_)))
                                              (_%$%lp-hd5531255377%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5531155373%_))))
                                          (_%$%loop5531055364%_
                                           _%$%lp-tl5531355380%_
                                           (cons _%$%lp-hd5531255377%_
                                                 _%$%rest5531455371%_))))
                                      (let ((_%$%rest5531555383%_
                                             (reverse _%$%rest5531455371%_)))
                                        (_%__kont100277100278%_
                                         _%$%rest5531555383%_
                                         _%$%hd5530555352%_
                                         _%$%hd5530255342%_))))))
                        (_%$%loop5531055364%_ _%$%target5530755358%_ '()))))
                   (_%__match100365100366%_
                    (lambda (_%$%e5527155425%_
                             _%$%hd5527255429%_
                             _%$%tl5527355432%_
                             _%$%e5527455435%_
                             _%$%hd5527555439%_
                             _%$%tl5527655442%_
                             _%$%e5527755445%_
                             _%$%hd5527855449%_
                             _%$%tl5527955452%_
                             _%$%e5528055455%_
                             _%$%hd5528155459%_
                             _%$%tl5528255462%_
                             _%$%e5528355465%_
                             _%$%hd5528455469%_
                             _%$%tl5528555472%_
                             _%__splice100275100276%_
                             _%$%target5528655475%_
                             _%$%tl5528855478%_)
                      (letrec ((_%$%loop5528955481%_
                                (lambda (_%$%hd5528755485%_
                                         _%$%rest5529355488%_)
                                  (if (gx#stx-pair? _%$%hd5528755485%_)
                                      (let ((_%$%e5529055490%_
                                             (gx#syntax-e _%$%hd5528755485%_)))
                                        (let ((_%$%lp-tl5529255497%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5529055490%_)))
                                              (_%$%lp-hd5529155494%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5529055490%_))))
                                          (_%$%loop5528955481%_
                                           _%$%lp-tl5529255497%_
                                           (cons _%$%lp-hd5529155494%_
                                                 _%$%rest5529355488%_))))
                                      (let ((_%$%rest5529455500%_
                                             (reverse _%$%rest5529355488%_)))
                                        (_%__kont100273100274%_
                                         _%$%rest5529455500%_
                                         _%$%hd5528455469%_
                                         _%$%hd5528155459%_
                                         _%$%hd5527555439%_))))))
                        (_%$%loop5528955481%_ _%$%target5528655475%_ '()))))
                   (_%__match100323100324%_
                    (lambda (_%$%e5524355547%_
                             _%$%hd5524455551%_
                             _%$%tl5524555554%_
                             _%$%e5524655557%_
                             _%$%hd5524755561%_
                             _%$%tl5524855564%_
                             _%$%e5524955567%_
                             _%$%hd5525055571%_
                             _%$%tl5525155574%_
                             _%$%e5525255577%_
                             _%$%hd5525355581%_
                             _%$%tl5525455584%_
                             _%$%e5525555587%_
                             _%$%hd5525655591%_
                             _%$%tl5525755594%_
                             _%__splice100271100272%_
                             _%$%target5525855597%_
                             _%$%tl5526055600%_)
                      (letrec ((_%$%loop5526155603%_
                                (lambda (_%$%hd5525955607%_
                                         _%$%rest5526555610%_)
                                  (if (gx#stx-pair? _%$%hd5525955607%_)
                                      (let ((_%$%e5526255612%_
                                             (gx#syntax-e _%$%hd5525955607%_)))
                                        (let ((_%$%lp-tl5526455619%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5526255612%_)))
                                              (_%$%lp-hd5526355616%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5526255612%_))))
                                          (_%$%loop5526155603%_
                                           _%$%lp-tl5526455619%_
                                           (cons _%$%lp-hd5526355616%_
                                                 _%$%rest5526555610%_))))
                                      (let ((_%$%rest5526655622%_
                                             (reverse _%$%rest5526555610%_)))
                                        (_%__kont100269100270%_
                                         _%$%rest5526655622%_
                                         _%$%hd5525655591%_
                                         _%$%hd5525355581%_
                                         _%$%hd5524755561%_))))))
                        (_%$%loop5526155603%_ _%$%target5525855597%_ '())))))
              (if (gx#stx-pair? _%__stx100266100267%_)
                  (let ((_%$%e5524355547%_
                         (gx#syntax-e _%__stx100266100267%_)))
                    (let ((_%$%tl5524555554%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5524355547%_)))
                          (_%$%hd5524455551%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5524355547%_))))
                      (if (gx#stx-pair? _%$%tl5524555554%_)
                          (let ((_%$%e5524655557%_
                                 (gx#syntax-e _%$%tl5524555554%_)))
                            (let ((_%$%tl5524855564%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e5524655557%_)))
                                  (_%$%hd5524755561%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e5524655557%_))))
                              (if (gx#stx-pair? _%$%tl5524855564%_)
                                  (let ((_%$%e5524955567%_
                                         (gx#syntax-e _%$%tl5524855564%_)))
                                    (let ((_%$%tl5525155574%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e5524955567%_)))
                                          (_%$%hd5525055571%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e5524955567%_))))
                                      (if (gx#identifier? _%$%hd5525055571%_)
                                          (if (gx#free-identifier=?
                                               |gerbil/core/contract~TypeCast[1]#_g107396_|
                                               _%$%hd5525055571%_)
                                              (if (gx#stx-pair?
                                                   _%$%tl5525155574%_)
                                                  (let ((_%$%e5525255577%_
                                                         (gx#syntax-e
                                                          _%$%tl5525155574%_)))
                                                    (let ((_%$%tl5525455584%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e5525255577%_)))
                                                          (_%$%hd5525355581%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e5525255577%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl5525455584%_)
                                                          (let ((_%$%e5525555587%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl5525455584%_)))
                    (let ((_%$%tl5525755594%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e5525555587%_)))
                          (_%$%hd5525655591%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e5525555587%_))))
                      (if (gx#stx-pair/null? _%$%tl5525755594%_)
                          (let ((_%__splice100271100272%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5525755594%_
                                  '0)))
                            (let ((_%$%tl5526055600%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100271100272%_
                                      '1)))
                                  (_%$%target5525855597%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100271100272%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5526055600%_)
                                  (_%__match100323100324%_
                                   _%$%e5524355547%_
                                   _%$%hd5524455551%_
                                   _%$%tl5524555554%_
                                   _%$%e5524655557%_
                                   _%$%hd5524755561%_
                                   _%$%tl5524855564%_
                                   _%$%e5524955567%_
                                   _%$%hd5525055571%_
                                   _%$%tl5525155574%_
                                   _%$%e5525255577%_
                                   _%$%hd5525355581%_
                                   _%$%tl5525455584%_
                                   _%$%e5525555587%_
                                   _%$%hd5525655591%_
                                   _%$%tl5525755594%_
                                   _%__splice100271100272%_
                                   _%$%target5525855597%_
                                   _%$%tl5526055600%_)
                                  (if (gx#stx-pair/null? _%$%tl5525155574%_)
                                      (let ((_%__splice100279100280%_
                                             (gx#syntax-split-splice->vector
                                              _%$%tl5525155574%_
                                              '0)))
                                        (let ((_%$%tl5530955361%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice100279100280%_
                                                  '1)))
                                              (_%$%target5530755358%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice100279100280%_
                                                  '0))))
                                          (if (gx#stx-null? _%$%tl5530955361%_)
                                              (_%__match100391100392%_
                                               _%$%e5524355547%_
                                               _%$%hd5524455551%_
                                               _%$%tl5524555554%_
                                               _%$%e5524655557%_
                                               _%$%hd5524755561%_
                                               _%$%tl5524855564%_
                                               _%$%e5524955567%_
                                               _%$%hd5525055571%_
                                               _%$%tl5525155574%_
                                               _%__splice100279100280%_
                                               _%$%target5530755358%_
                                               _%$%tl5530955361%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5523755321%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5523755321%_))))))
                          (if (gx#stx-pair/null? _%$%tl5525155574%_)
                              (let ((_%__splice100279100280%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5525155574%_
                                      '0)))
                                (let ((_%$%tl5530955361%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100279100280%_
                                          '1)))
                                      (_%$%target5530755358%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100279100280%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5530955361%_)
                                      (_%__match100391100392%_
                                       _%$%e5524355547%_
                                       _%$%hd5524455551%_
                                       _%$%tl5524555554%_
                                       _%$%e5524655557%_
                                       _%$%hd5524755561%_
                                       _%$%tl5524855564%_
                                       _%$%e5524955567%_
                                       _%$%hd5525055571%_
                                       _%$%tl5525155574%_
                                       _%__splice100279100280%_
                                       _%$%target5530755358%_
                                       _%$%tl5530955361%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g5523755321%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g5523755321%_))))))
                  (if (gx#stx-pair/null? _%$%tl5525155574%_)
                      (let ((_%__splice100279100280%_
                             (gx#syntax-split-splice->vector
                              _%$%tl5525155574%_
                              '0)))
                        (let ((_%$%tl5530955361%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100279100280%_ '1)))
                              (_%$%target5530755358%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice100279100280%_ '0))))
                          (if (gx#stx-null? _%$%tl5530955361%_)
                              (_%__match100391100392%_
                               _%$%e5524355547%_
                               _%$%hd5524455551%_
                               _%$%tl5524555554%_
                               _%$%e5524655557%_
                               _%$%hd5524755561%_
                               _%$%tl5524855564%_
                               _%$%e5524955567%_
                               _%$%hd5525055571%_
                               _%$%tl5525155574%_
                               _%__splice100279100280%_
                               _%$%target5530755358%_
                               _%$%tl5530955361%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g5523755321%_)))))
                      (let () (declare (not safe)) (_%$%g5523755321%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5525155574%_)
                                                      (let ((_%__splice100279100280%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5525155574%_
                                                              '0)))
                                                        (let ((_%$%tl5530955361%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100279100280%_ '1)))
                      (_%$%target5530755358%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100279100280%_ '0))))
                  (if (gx#stx-null? _%$%tl5530955361%_)
                      (_%__match100391100392%_
                       _%$%e5524355547%_
                       _%$%hd5524455551%_
                       _%$%tl5524555554%_
                       _%$%e5524655557%_
                       _%$%hd5524755561%_
                       _%$%tl5524855564%_
                       _%$%e5524955567%_
                       _%$%hd5525055571%_
                       _%$%tl5525155574%_
                       _%__splice100279100280%_
                       _%$%target5530755358%_
                       _%$%tl5530955361%_)
                      (let () (declare (not safe)) (_%$%g5523755321%_)))))
              (let () (declare (not safe)) (_%$%g5523755321%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (gx#free-identifier=?
                                                   |gerbil/core/contract~TypeCast[1]#_g107397_|
                                                   _%$%hd5525055571%_)
                                                  (if (gx#stx-pair?
                                                       _%$%tl5525155574%_)
                                                      (let ((_%$%e5528055455%_
                                                             (gx#syntax-e
                                                              _%$%tl5525155574%_)))
                                                        (let ((_%$%tl5528255462%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%e5528055455%_)))
                      (_%$%hd5528155459%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e5528055455%_))))
                  (if (gx#stx-pair? _%$%tl5528255462%_)
                      (let ((_%$%e5528355465%_
                             (gx#syntax-e _%$%tl5528255462%_)))
                        (let ((_%$%tl5528555472%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5528355465%_)))
                              (_%$%hd5528455469%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5528355465%_))))
                          (if (gx#stx-pair/null? _%$%tl5528555472%_)
                              (let ((_%__splice100275100276%_
                                     (gx#syntax-split-splice->vector
                                      _%$%tl5528555472%_
                                      '0)))
                                (let ((_%$%tl5528855478%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100275100276%_
                                          '1)))
                                      (_%$%target5528655475%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice100275100276%_
                                          '0))))
                                  (if (gx#stx-null? _%$%tl5528855478%_)
                                      (_%__match100365100366%_
                                       _%$%e5524355547%_
                                       _%$%hd5524455551%_
                                       _%$%tl5524555554%_
                                       _%$%e5524655557%_
                                       _%$%hd5524755561%_
                                       _%$%tl5524855564%_
                                       _%$%e5524955567%_
                                       _%$%hd5525055571%_
                                       _%$%tl5525155574%_
                                       _%$%e5528055455%_
                                       _%$%hd5528155459%_
                                       _%$%tl5528255462%_
                                       _%$%e5528355465%_
                                       _%$%hd5528455469%_
                                       _%$%tl5528555472%_
                                       _%__splice100275100276%_
                                       _%$%target5528655475%_
                                       _%$%tl5528855478%_)
                                      (if (gx#stx-pair/null?
                                           _%$%tl5525155574%_)
                                          (let ((_%__splice100279100280%_
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl5525155574%_
                                                  '0)))
                                            (let ((_%$%tl5530955361%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100279100280%_
                                                      '1)))
                                                  (_%$%target5530755358%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##vector-ref
                                                      _%__splice100279100280%_
                                                      '0))))
                                              (if (gx#stx-null?
                                                   _%$%tl5530955361%_)
                                                  (_%__match100391100392%_
                                                   _%$%e5524355547%_
                                                   _%$%hd5524455551%_
                                                   _%$%tl5524555554%_
                                                   _%$%e5524655557%_
                                                   _%$%hd5524755561%_
                                                   _%$%tl5524855564%_
                                                   _%$%e5524955567%_
                                                   _%$%hd5525055571%_
                                                   _%$%tl5525155574%_
                                                   _%__splice100279100280%_
                                                   _%$%target5530755358%_
                                                   _%$%tl5530955361%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g5523755321%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5523755321%_))))))
                              (if (gx#stx-pair/null? _%$%tl5525155574%_)
                                  (let ((_%__splice100279100280%_
                                         (gx#syntax-split-splice->vector
                                          _%$%tl5525155574%_
                                          '0)))
                                    (let ((_%$%tl5530955361%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100279100280%_
                                              '1)))
                                          (_%$%target5530755358%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice100279100280%_
                                              '0))))
                                      (if (gx#stx-null? _%$%tl5530955361%_)
                                          (_%__match100391100392%_
                                           _%$%e5524355547%_
                                           _%$%hd5524455551%_
                                           _%$%tl5524555554%_
                                           _%$%e5524655557%_
                                           _%$%hd5524755561%_
                                           _%$%tl5524855564%_
                                           _%$%e5524955567%_
                                           _%$%hd5525055571%_
                                           _%$%tl5525155574%_
                                           _%__splice100279100280%_
                                           _%$%target5530755358%_
                                           _%$%tl5530955361%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g5523755321%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5523755321%_))))))
                      (if (gx#stx-pair/null? _%$%tl5525155574%_)
                          (let ((_%__splice100279100280%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl5525155574%_
                                  '0)))
                            (let ((_%$%tl5530955361%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100279100280%_
                                      '1)))
                                  (_%$%target5530755358%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice100279100280%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl5530955361%_)
                                  (_%__match100391100392%_
                                   _%$%e5524355547%_
                                   _%$%hd5524455551%_
                                   _%$%tl5524555554%_
                                   _%$%e5524655557%_
                                   _%$%hd5524755561%_
                                   _%$%tl5524855564%_
                                   _%$%e5524955567%_
                                   _%$%hd5525055571%_
                                   _%$%tl5525155574%_
                                   _%__splice100279100280%_
                                   _%$%target5530755358%_
                                   _%$%tl5530955361%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5523755321%_)))))
                          (let () (declare (not safe)) (_%$%g5523755321%_))))))
              (if (gx#stx-pair/null? _%$%tl5525155574%_)
                  (let ((_%__splice100279100280%_
                         (gx#syntax-split-splice->vector
                          _%$%tl5525155574%_
                          '0)))
                    (let ((_%$%tl5530955361%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100279100280%_ '1)))
                          (_%$%target5530755358%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice100279100280%_ '0))))
                      (if (gx#stx-null? _%$%tl5530955361%_)
                          (_%__match100391100392%_
                           _%$%e5524355547%_
                           _%$%hd5524455551%_
                           _%$%tl5524555554%_
                           _%$%e5524655557%_
                           _%$%hd5524755561%_
                           _%$%tl5524855564%_
                           _%$%e5524955567%_
                           _%$%hd5525055571%_
                           _%$%tl5525155574%_
                           _%__splice100279100280%_
                           _%$%target5530755358%_
                           _%$%tl5530955361%_)
                          (let () (declare (not safe)) (_%$%g5523755321%_)))))
                  (let () (declare (not safe)) (_%$%g5523755321%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (gx#stx-pair/null?
                                                       _%$%tl5525155574%_)
                                                      (let ((_%__splice100279100280%_
                                                             (gx#syntax-split-splice->vector
                                                              _%$%tl5525155574%_
                                                              '0)))
                                                        (let ((_%$%tl5530955361%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##vector-ref _%__splice100279100280%_ '1)))
                      (_%$%target5530755358%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice100279100280%_ '0))))
                  (if (gx#stx-null? _%$%tl5530955361%_)
                      (_%__match100391100392%_
                       _%$%e5524355547%_
                       _%$%hd5524455551%_
                       _%$%tl5524555554%_
                       _%$%e5524655557%_
                       _%$%hd5524755561%_
                       _%$%tl5524855564%_
                       _%$%e5524955567%_
                       _%$%hd5525055571%_
                       _%$%tl5525155574%_
                       _%__splice100279100280%_
                       _%$%target5530755358%_
                       _%$%tl5530955361%_)
                      (let () (declare (not safe)) (_%$%g5523755321%_)))))
              (let () (declare (not safe)) (_%$%g5523755321%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (gx#stx-pair/null?
                                               _%$%tl5525155574%_)
                                              (let ((_%__splice100279100280%_
                                                     (gx#syntax-split-splice->vector
                                                      _%$%tl5525155574%_
                                                      '0)))
                                                (let ((_%$%tl5530955361%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100279100280%_
                                                          '1)))
                                                      (_%$%target5530755358%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice100279100280%_
                                                          '0))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5530955361%_)
                                                      (_%__match100391100392%_
                                                       _%$%e5524355547%_
                                                       _%$%hd5524455551%_
                                                       _%$%tl5524555554%_
                                                       _%$%e5524655557%_
                                                       _%$%hd5524755561%_
                                                       _%$%tl5524855564%_
                                                       _%$%e5524955567%_
                                                       _%$%hd5525055571%_
                                                       _%$%tl5525155574%_
                                                       _%__splice100279100280%_
                                                       _%$%target5530755358%_
                                                       _%$%tl5530955361%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g5523755321%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g5523755321%_))))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g5523755321%_)))))
                          (let () (declare (not safe)) (_%$%g5523755321%_)))))
                  (let () (declare (not safe)) (_%$%g5523755321%_))))))))
    (define |gerbil/core/contract~TypeCast[:0:]#:~|
      (lambda (_%$stx55669%_)
        (let* ((_%__stx100394100395%_ _%$stx55669%_)
               (_%$%g5567455710%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx100394100395%_))))
          (let ((_%__kont100397100398%_
                 (lambda (_%$%g5567655828%_ _%$%g5567755830%_)
                   (cons (gx#datum->syntax '#f 'let)
                         (cons (cons (gx#datum->syntax '#f 'val)
                                     (cons _%$%g5567755830%_ '()))
                               (cons (cons (gx#datum->syntax '#f 'if)
                                           (cons (cons _%$%g5567655828%_
                                                       (cons (gx#datum->syntax
                                                              '#f
                                                              'val)
                                                             '()))
                                                 (cons (gx#datum->syntax
                                                        '#f
                                                        'val)
                                                       (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'contract-violation!)
                           (cons _%$%g5567755830%_
                                 (cons _%$%g5567655828%_
                                       (cons (gx#datum->syntax '#f 'val)
                                             '()))))
                     '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont100399100400%_
                 (lambda (_%$%g5568755767%_
                          _%$%g5568855769%_
                          _%$%g5568955770%_)
                   (cons (gx#datum->syntax '#f ':-)
                         (cons (cons (gx#datum->syntax '#f ':~)
                                     (cons _%$%g5568955770%_
                                           (cons _%$%g5568855769%_ '())))
                               (cons _%$%g5568755767%_ '()))))))
            (if (gx#stx-pair? _%__stx100394100395%_)
                (let ((_%$%e5567855798%_ (gx#syntax-e _%__stx100394100395%_)))
                  (let ((_%$%tl5568055805%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e5567855798%_)))
                        (_%$%hd5567955802%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e5567855798%_))))
                    (if (gx#stx-pair? _%$%tl5568055805%_)
                        (let ((_%$%e5568155808%_
                               (gx#syntax-e _%$%tl5568055805%_)))
                          (let ((_%$%tl5568355815%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e5568155808%_)))
                                (_%$%hd5568255812%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e5568155808%_))))
                            (if (gx#stx-pair? _%$%tl5568355815%_)
                                (let ((_%$%e5568455818%_
                                       (gx#syntax-e _%$%tl5568355815%_)))
                                  (let ((_%$%tl5568655825%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e5568455818%_)))
                                        (_%$%hd5568555822%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e5568455818%_))))
                                    (if (gx#stx-null? _%$%tl5568655825%_)
                                        (_%__kont100397100398%_
                                         _%$%hd5568555822%_
                                         _%$%hd5568255812%_)
                                        (if (gx#stx-pair? _%$%tl5568655825%_)
                                            (let ((_%$%e5569955747%_
                                                   (gx#syntax-e
                                                    _%$%tl5568655825%_)))
                                              (let ((_%$%tl5570155754%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e5569955747%_)))
                                                    (_%$%hd5570055751%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e5569955747%_))))
                                                (if (gx#identifier?
                                                     _%$%hd5570055751%_)
                                                    (if (gx#free-identifier=?
                                                         |gerbil/core/contract~TypeCast[1]#_g107398_|
                                                         _%$%hd5570055751%_)
                                                        (if (gx#stx-pair?
                                                             _%$%tl5570155754%_)
                                                            (let ((_%$%e5570255757%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-e _%$%tl5570155754%_)))
                      (let ((_%$%tl5570455764%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5570255757%_)))
                            (_%$%hd5570355761%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5570255757%_))))
                        (if (gx#stx-null? _%$%tl5570455764%_)
                            (_%__kont100399100400%_
                             _%$%hd5570355761%_
                             _%$%hd5568555822%_
                             _%$%hd5568255812%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g5567455710%_)))))
                    (let () (declare (not safe)) (_%$%g5567455710%_)))
                (let () (declare (not safe)) (_%$%g5567455710%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g5567455710%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g5567455710%_))))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5567455710%_)))))
                        (let () (declare (not safe)) (_%$%g5567455710%_)))))
                (let () (declare (not safe)) (_%$%g5567455710%_)))))))
    (define |gerbil/core/contract~TypeCast[:0:]#::-|
      (lambda (_%$stx55849%_)
        (let ((_%$%g5585255859%_
               (lambda (_%$%g5585355855%_)
                 (gx#raise-syntax-error
                  '#f
                  '"Bad syntax; invalid match target"
                  _%$%g5585355855%_))))
          (_%$%g5585255859%_ _%$stx55849%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#:=|
      (lambda (_%$stx55863%_)
        (let ((_%$%g5586655873%_
               (lambda (_%$%g5586755869%_)
                 (gx#raise-syntax-error
                  '#f
                  '"Bad syntax; invalid match target"
                  _%$%g5586755869%_))))
          (_%$%g5586655873%_ _%$stx55863%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#check-nil!|
      (lambda (_%$stx55877%_)
        (let* ((_%$%g5588155895%_
                (lambda (_%$%g5588255891%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5588255891%_)))
               (_%$%g5588055936%_
                (lambda (_%$%g5588255899%_)
                  (if (gx#stx-pair? _%$%g5588255899%_)
                      (let ((_%$%e5588455902%_
                             (gx#syntax-e _%$%g5588255899%_)))
                        (let ((_%$%hd5588555906%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5588455902%_)))
                              (_%$%tl5588655909%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5588455902%_))))
                          (if (gx#stx-pair? _%$%tl5588655909%_)
                              (let ((_%$%e5588755912%_
                                     (gx#syntax-e _%$%tl5588655909%_)))
                                (let ((_%$%hd5588855916%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5588755912%_)))
                                      (_%$%tl5588955919%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5588755912%_))))
                                  (if (gx#stx-null? _%$%tl5588955919%_)
                                      (cons (gx#datum->syntax '#f 'or)
                                            (cons _%$%hd5588855916%_
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'nil-dereference!)
                                                              (cons _%$%hd5588855916%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (_%$%g5588155895%_ _%$%g5588255899%_))))
                              (_%$%g5588155895%_ _%$%g5588255899%_))))
                      (_%$%g5588155895%_ _%$%g5588255899%_)))))
          (_%$%g5588055936%_ _%$stx55877%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#contract-violation!|
      (lambda (_%stx55940%_)
        (let* ((_%$%g5594355966%_
                (lambda (_%$%g5594455962%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5594455962%_)))
               (_%$%g5594256090%_
                (lambda (_%$%g5594455970%_)
                  (if (gx#stx-pair? _%$%g5594455970%_)
                      (let ((_%$%e5594955973%_
                             (gx#syntax-e _%$%g5594455970%_)))
                        (let ((_%$%hd5595055977%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5594955973%_)))
                              (_%$%tl5595155980%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5594955973%_))))
                          (if (gx#stx-pair? _%$%tl5595155980%_)
                              (let ((_%$%e5595255983%_
                                     (gx#syntax-e _%$%tl5595155980%_)))
                                (let ((_%$%hd5595355987%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5595255983%_)))
                                      (_%$%tl5595455990%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5595255983%_))))
                                  (if (gx#stx-pair? _%$%tl5595455990%_)
                                      (let ((_%$%e5595555993%_
                                             (gx#syntax-e _%$%tl5595455990%_)))
                                        (let ((_%$%hd5595655997%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5595555993%_)))
                                              (_%$%tl5595756000%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5595555993%_))))
                                          (if (gx#stx-pair? _%$%tl5595756000%_)
                                              (let ((_%$%e5595856003%_
                                                     (gx#syntax-e
                                                      _%$%tl5595756000%_)))
                                                (let ((_%$%hd5595956007%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5595856003%_)))
                                                      (_%$%tl5596056010%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5595856003%_))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5596056010%_)
                                                      (let* ((_%$%g5603756045%_
                                                              (lambda (_%$%g5603856041%_)
                                                                (gx#raise-syntax-error
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         '"Bad syntax; invalid match target"
                         _%$%g5603856041%_)))
                     (_%$%g5603656064%_
                      (lambda (_%$%g5603856049%_)
                        (cons (gx#datum->syntax '#f 'begin-annotation)
                              (cons (cons (gx#datum->syntax
                                           '#f
                                           '@contract-violation)
                                          (cons _%$%g5603856049%_
                                                (cons _%$%hd5595655997%_
                                                      (cons _%$%hd5595956007%_
                                                            '()))))
                                    (cons (cons (gx#datum->syntax '#f 'abort!)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'raise-contract-violation-error)
                                                            (cons '"contract violation"
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons 'context:
                                (cons (cons (gx#datum->syntax '#f 'quote)
                                            (cons _%$%g5603856049%_ '()))
                                      (cons 'contract:
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'quote)
                                                        (cons _%$%hd5595655997%_
                                                              '()))
                                                  (cons 'value:
                                                        (cons _%$%hd5595956007%_
                                                              '()))))))))
              '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          '()))))))
                (_%$%g5603656064%_
                 (let ((_%$e56076%_
                        (let ((_%$e56068%_ (gx#stx-source _%$%hd5595355987%_)))
                          (if _%$e56068%_
                              _%$e56068%_
                              (let ((_%$e56072%_ (gx#stx-source _%stx55940%_)))
                                (if _%$e56072%_
                                    _%$e56072%_
                                    (gx#stx-source _%$%hd5595055977%_)))))))
                   (if _%$e56076%_
                       (call-with-output-string
                        '""
                        (lambda (_%$%g5608256084%_)
                          (let ()
                            (declare (not safe))
                            (##display-locat
                             _%$e56076%_
                             '#t
                             _%$%g5608256084%_))))
                       (gx#expander-context-id (gx#core-context-top))))))
              (_%$%g5594355966%_ _%$%g5594455970%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g5594355966%_
                                               _%$%g5594455970%_))))
                                      (_%$%g5594355966%_ _%$%g5594455970%_))))
                              (_%$%g5594355966%_ _%$%g5594455970%_))))
                      (_%$%g5594355966%_ _%$%g5594455970%_)))))
          (_%$%g5594256090%_ _%stx55940%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#runtime-contract-violation!|
      (lambda (_%stx56094%_)
        (let* ((_%$%g5609756120%_
                (lambda (_%$%g5609856116%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5609856116%_)))
               (_%$%g5609656244%_
                (lambda (_%$%g5609856124%_)
                  (if (gx#stx-pair? _%$%g5609856124%_)
                      (let ((_%$%e5610356127%_
                             (gx#syntax-e _%$%g5609856124%_)))
                        (let ((_%$%hd5610456131%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5610356127%_)))
                              (_%$%tl5610556134%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5610356127%_))))
                          (if (gx#stx-pair? _%$%tl5610556134%_)
                              (let ((_%$%e5610656137%_
                                     (gx#syntax-e _%$%tl5610556134%_)))
                                (let ((_%$%hd5610756141%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5610656137%_)))
                                      (_%$%tl5610856144%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5610656137%_))))
                                  (if (gx#stx-pair? _%$%tl5610856144%_)
                                      (let ((_%$%e5610956147%_
                                             (gx#syntax-e _%$%tl5610856144%_)))
                                        (let ((_%$%hd5611056151%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5610956147%_)))
                                              (_%$%tl5611156154%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5610956147%_))))
                                          (if (gx#stx-pair? _%$%tl5611156154%_)
                                              (let ((_%$%e5611256157%_
                                                     (gx#syntax-e
                                                      _%$%tl5611156154%_)))
                                                (let ((_%$%hd5611356161%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e5611256157%_)))
                                                      (_%$%tl5611456164%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e5611256157%_))))
                                                  (if (gx#stx-null?
                                                       _%$%tl5611456164%_)
                                                      (let* ((_%$%g5619156199%_
                                                              (lambda (_%$%g5619256195%_)
                                                                (gx#raise-syntax-error
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         '"Bad syntax; invalid match target"
                         _%$%g5619256195%_)))
                     (_%$%g5619056218%_
                      (lambda (_%$%g5619256203%_)
                        (cons (gx#datum->syntax '#f 'abort!)
                              (cons (cons (gx#datum->syntax
                                           '#f
                                           'raise-contract-violation-error)
                                          (cons '"contract violation"
                                                (cons 'context:
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'quote)
                          (cons _%$%g5619256203%_ '()))
                    (cons 'contract:
                          (cons (cons (gx#datum->syntax '#f 'quote)
                                      (cons _%$%hd5611056151%_ '()))
                                (cons 'value:
                                      (cons _%$%hd5611356161%_ '()))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '())))))
                (_%$%g5619056218%_
                 (let ((_%$e56230%_
                        (let ((_%$e56222%_ (gx#stx-source _%$%hd5610756141%_)))
                          (if _%$e56222%_
                              _%$e56222%_
                              (let ((_%$e56226%_ (gx#stx-source _%stx56094%_)))
                                (if _%$e56226%_
                                    _%$e56226%_
                                    (gx#stx-source _%$%hd5610456131%_)))))))
                   (if _%$e56230%_
                       (call-with-output-string
                        '""
                        (lambda (_%$%g5623656238%_)
                          (let ()
                            (declare (not safe))
                            (##display-locat
                             _%$e56230%_
                             '#t
                             _%$%g5623656238%_))))
                       (gx#expander-context-id (gx#core-context-top))))))
              (_%$%g5609756120%_ _%$%g5609856124%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g5609756120%_
                                               _%$%g5609856124%_))))
                                      (_%$%g5609756120%_ _%$%g5609856124%_))))
                              (_%$%g5609756120%_ _%$%g5609856124%_))))
                      (_%$%g5609756120%_ _%$%g5609856124%_)))))
          (_%$%g5609656244%_ _%stx56094%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#nil-dereference!|
      (lambda (_%stx56248%_)
        (let* ((_%$%g5625156266%_
                (lambda (_%$%g5625256262%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5625256262%_)))
               (_%$%g5625056362%_
                (lambda (_%$%g5625256270%_)
                  (if (gx#stx-pair? _%$%g5625256270%_)
                      (let ((_%$%e5625556273%_
                             (gx#syntax-e _%$%g5625256270%_)))
                        (let ((_%$%hd5625656277%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5625556273%_)))
                              (_%$%tl5625756280%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5625556273%_))))
                          (if (gx#stx-pair? _%$%tl5625756280%_)
                              (let ((_%$%e5625856283%_
                                     (gx#syntax-e _%$%tl5625756280%_)))
                                (let ((_%$%hd5625956287%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5625856283%_)))
                                      (_%$%tl5626056290%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5625856283%_))))
                                  (if (gx#stx-null? _%$%tl5626056290%_)
                                      (let* ((_%$%g5630956317%_
                                              (lambda (_%$%g5631056313%_)
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Bad syntax; invalid match target"
                                                 _%$%g5631056313%_)))
                                             (_%$%g5630856336%_
                                              (lambda (_%$%g5631056321%_)
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'abort!)
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'raise-contract-violation-error)
                          (cons '"nil (#f) derefence"
                                (cons 'context:
                                      (cons (cons (gx#datum->syntax '#f 'quote)
                                                  (cons _%$%g5631056321%_ '()))
                                            (cons 'contract:
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'quote)
                                                              (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '#f
                                   'check-nil!)
                                  (cons _%$%hd5625956287%_ '()))
                            '()))
                (cons 'value: (cons '#f '()))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                    '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (_%$%g5630856336%_
                                         (let ((_%$e56348%_
                                                (let ((_%$e56340%_
                                                       (gx#stx-source
                                                        _%$%hd5625956287%_)))
                                                  (if _%$e56340%_
                                                      _%$e56340%_
                                                      (let ((_%$e56344%_
                                                             (gx#stx-source
                                                              _%stx56248%_)))
                                                        (if _%$e56344%_
                                                            _%$e56344%_
                                                            (gx#stx-source
                                                             _%$%hd5625656277%_)))))))
                                           (if _%$e56348%_
                                               (call-with-output-string
                                                '""
                                                (lambda (_%$%g5635456356%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (##display-locat
                                                     _%$e56348%_
                                                     '#t
                                                     _%$%g5635456356%_))))
                                               (gx#expander-context-id
                                                (gx#core-context-top))))))
                                      (_%$%g5625156266%_ _%$%g5625256270%_))))
                              (_%$%g5625156266%_ _%$%g5625256270%_))))
                      (_%$%g5625156266%_ _%$%g5625256270%_)))))
          (_%$%g5625056362%_ _%stx56248%_))))
    (define |gerbil/core/contract~TypeCast[:0:]#abort!|
      (lambda (_%$stx56366%_)
        (let* ((_%$%g5637056384%_
                (lambda (_%$%g5637156380%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5637156380%_)))
               (_%$%g5636956425%_
                (lambda (_%$%g5637156388%_)
                  (if (gx#stx-pair? _%$%g5637156388%_)
                      (let ((_%$%e5637356391%_
                             (gx#syntax-e _%$%g5637156388%_)))
                        (let ((_%$%hd5637456395%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5637356391%_)))
                              (_%$%tl5637556398%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5637356391%_))))
                          (if (gx#stx-pair? _%$%tl5637556398%_)
                              (let ((_%$%e5637656401%_
                                     (gx#syntax-e _%$%tl5637556398%_)))
                                (let ((_%$%hd5637756405%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5637656401%_)))
                                      (_%$%tl5637856408%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5637656401%_))))
                                  (if (gx#stx-null? _%$%tl5637856408%_)
                                      (cons (gx#datum->syntax
                                             '#f
                                             'begin-annotation)
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         '@abort)
                                                        '())
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'begin)
                                                              (cons _%$%hd5637756405%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons (cons (gx#datum->syntax '#f 'void) '())
                                  '())))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (_%$%g5637056384%_ _%$%g5637156388%_))))
                              (_%$%g5637056384%_ _%$%g5637156388%_))))
                      (_%$%g5637056384%_ _%$%g5637156388%_)))))
          (_%$%g5636956425%_ _%$stx56366%_))))))
