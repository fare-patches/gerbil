(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gerbil/core/contract~ClassMeta[1]#meta-object-methods!|
    (lambda (_%meta63351%_)
      (let ((_%$e63354%_
             (let ((__obj107239 _%meta63351%_))
               (if (let ()
                     (declare (not safe))
                     (##structure-direct-instance-of?
                      __obj107239
                      'gerbil/core#meta-object::t))
                   (let ()
                     (declare (not safe))
                     (##unchecked-structure-ref __obj107239 '1 '#f '#f))
                   (class-slot-ref
                    gerbil/core/mop~MOP-2#meta-object::t
                    __obj107239
                    'methods)))))
        (if _%$e63354%_
            _%$e63354%_
            (let ((_%tab63360%_ (make-hash-table-eq)))
              (let ((__obj107240 _%meta63351%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-direct-instance-of?
                       __obj107240
                       'gerbil/core#meta-object::t))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj107240
                       _%tab63360%_
                       '1
                       '#f
                       '#f))
                    (class-slot-set!
                     gerbil/core/mop~MOP-2#meta-object::t
                     __obj107240
                     'methods
                     _%tab63360%_)))
              _%tab63360%_)))))
  (define |gerbil/core/contract~ClassMeta[:0:]#@call-meta-object|
    (lambda (_%stx63363%_)
      (let* ((_%$%g6336663397%_
              (lambda (_%$%g6336763393%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6336763393%_)))
             (_%$%g6336563509%_
              (lambda (_%$%g6336763401%_)
                (if (gx#stx-pair? _%$%g6336763401%_)
                    (let ((_%$%e6337163404%_ (gx#syntax-e _%$%g6336763401%_)))
                      (let ((_%$%hd6337263408%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6337163404%_)))
                            (_%$%tl6337363411%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6337163404%_))))
                        (if (gx#stx-pair? _%$%tl6337363411%_)
                            (let ((_%$%e6337463414%_
                                   (gx#syntax-e _%$%tl6337363411%_)))
                              (let ((_%$%hd6337563418%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6337463414%_)))
                                    (_%$%tl6337663421%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6337463414%_))))
                                (if (gx#stx-pair? _%$%tl6337663421%_)
                                    (let ((_%$%e6337763424%_
                                           (gx#syntax-e _%$%tl6337663421%_)))
                                      (let ((_%$%hd6337863428%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e6337763424%_)))
                                            (_%$%tl6337963431%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e6337763424%_))))
                                        (if (gx#stx-pair? _%$%hd6337863428%_)
                                            (let ((_%$%e6338063434%_
                                                   (gx#syntax-e
                                                    _%$%hd6337863428%_)))
                                              (let ((_%$%hd6338163438%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e6338063434%_)))
                                                    (_%$%tl6338263441%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e6338063434%_))))
                                                (if (gx#stx-pair/null?
                                                     _%$%tl6338263441%_)
                                                    (let ((_g107464_
                                                           (gx#syntax-split-splice
                                                            _%$%tl6338263441%_
                                                            '0)))
                                                      (begin
                                                        (let ((_g107465_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (if (##values? _g107464_)
                             (##values-length _g107464_)
                             1))))
                  (if (not (let () (declare (not safe)) (##fx= _g107465_ 2)))
                      (error "Context expects 2 values" _g107465_)))
                (let ((_%$%target6338363444%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g107464_ 0)))
                      (_%$%tl6338563447%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g107464_ 1))))
                  (if (gx#stx-null? _%$%tl6338563447%_)
                      (letrec ((_%$%loop6338663450%_
                                (lambda (_%$%hd6338463454%_
                                         _%$%arg6339063457%_)
                                  (if (gx#stx-pair? _%$%hd6338463454%_)
                                      (let ((_%$%e6338763459%_
                                             (gx#syntax-e _%$%hd6338463454%_)))
                                        (let ((_%$%lp-hd6338863463%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6338763459%_)))
                                              (_%$%lp-tl6338963466%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6338763459%_))))
                                          (_%$%loop6338663450%_
                                           _%$%lp-tl6338963466%_
                                           (cons _%$%lp-hd6338863463%_
                                                 _%$%arg6339063457%_))))
                                      (let ((_%$%arg6339163469%_
                                             (reverse _%$%arg6339063457%_)))
                                        (if (gx#stx-null? _%$%tl6337963431%_)
                                            (if (gx#identifier?
                                                 _%$%hd6338163438%_)
                                                (let ((_%meta63498%_
                                                       (gx#syntax-local-value
                                                        _%$%hd6337563418%_
                                                        false)))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (class-instance?
                                                         gerbil/core/mop~MOP-2#meta-object::t
                                                         _%meta63498%_))
                                                      '#!void
                                                      (gx#raise-syntax-error
                                                       '#f
                                                       '"not a meta-object"
                                                       _%stx63363%_
                                                       _%$%hd6337563418%_
                                                       _%meta63498%_))
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'let)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'meta)
                            (cons (cons (gx#datum->syntax
                                         '#f
                                         'syntax-local-value)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'syntax)
                                                    (cons _%$%hd6337563418%_
                                                          '()))
                                              '()))
                                  '()))
                      (cons (cons (gx#datum->syntax '#f 'call-meta-object)
                                  (cons (gx#datum->syntax '#f 'meta)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'quote)
                                                    (cons _%$%hd6338163438%_
                                                          '()))
                                              (foldr (lambda (_%$%g6350063503%_
                                                              _%$%g6350163506%_)
                                                       (cons _%$%g6350063503%_
                                                             _%$%g6350163506%_))
                                                     '()
                                                     _%$%arg6339163469%_))))
                            '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g6336663397%_
                                                 _%$%g6336763401%_))
                                            (_%$%g6336663397%_
                                             _%$%g6336763401%_)))))))
                        (_%$%loop6338663450%_ _%$%target6338363444%_ '()))
                      (_%$%g6336663397%_ _%$%g6336763401%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g6336663397%_
                                                     _%$%g6336763401%_))))
                                            (_%$%g6336663397%_
                                             _%$%g6336763401%_))))
                                    (_%$%g6336663397%_ _%$%g6336763401%_))))
                            (_%$%g6336663397%_ _%$%g6336763401%_))))
                    (_%$%g6336663397%_ _%$%g6336763401%_)))))
        (_%$%g6336563509%_ _%stx63363%_))))
  (define |gerbil/core/contract~ClassMeta[:0:]#defmethod-for-meta|
    (lambda (_%stx63514%_)
      (let* ((_%$%g6351763562%_
              (lambda (_%$%g6351863558%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6351863558%_)))
             (_%$%g6351663730%_
              (lambda (_%$%g6351863566%_)
                (if (gx#stx-pair? _%$%g6351863566%_)
                    (let ((_%$%e6352463569%_ (gx#syntax-e _%$%g6351863566%_)))
                      (let ((_%$%hd6352563573%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6352463569%_)))
                            (_%$%tl6352663576%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6352463569%_))))
                        (if (gx#stx-pair? _%$%tl6352663576%_)
                            (let ((_%$%e6352763579%_
                                   (gx#syntax-e _%$%tl6352663576%_)))
                              (let ((_%$%hd6352863583%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6352763579%_)))
                                    (_%$%tl6352963586%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6352763579%_))))
                                (if (gx#stx-pair? _%$%tl6352963586%_)
                                    (let ((_%$%e6353063589%_
                                           (gx#syntax-e _%$%tl6352963586%_)))
                                      (let ((_%$%hd6353163593%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e6353063589%_)))
                                            (_%$%tl6353263596%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e6353063589%_))))
                                        (if (gx#stx-pair? _%$%hd6353163593%_)
                                            (let ((_%$%e6353363599%_
                                                   (gx#syntax-e
                                                    _%$%hd6353163593%_)))
                                              (let ((_%$%hd6353463603%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e6353363599%_)))
                                                    (_%$%tl6353563606%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e6353363599%_))))
                                                (if (gx#stx-pair/null?
                                                     _%$%tl6353563606%_)
                                                    (let ((_g107466_
                                                           (gx#syntax-split-splice
                                                            _%$%tl6353563606%_
                                                            '0)))
                                                      (begin
                                                        (let ((_g107467_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (if (##values? _g107466_)
                             (##values-length _g107466_)
                             1))))
                  (if (not (let () (declare (not safe)) (##fx= _g107467_ 2)))
                      (error "Context expects 2 values" _g107467_)))
                (let ((_%$%target6353663609%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g107466_ 0)))
                      (_%$%tl6353863612%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g107466_ 1))))
                  (if (gx#stx-null? _%$%tl6353863612%_)
                      (letrec ((_%$%loop6353963615%_
                                (lambda (_%$%hd6353763619%_
                                         _%$%arg6354363622%_)
                                  (if (gx#stx-pair? _%$%hd6353763619%_)
                                      (let ((_%$%e6354063624%_
                                             (gx#syntax-e _%$%hd6353763619%_)))
                                        (let ((_%$%lp-hd6354163628%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6354063624%_)))
                                              (_%$%lp-tl6354263631%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6354063624%_))))
                                          (_%$%loop6353963615%_
                                           _%$%lp-tl6354263631%_
                                           (cons _%$%lp-hd6354163628%_
                                                 _%$%arg6354363622%_))))
                                      (let ((_%$%arg6354463634%_
                                             (reverse _%$%arg6354363622%_)))
                                        (if (gx#stx-pair? _%$%tl6353263596%_)
                                            (let ((_%$%e6354563637%_
                                                   (gx#syntax-e
                                                    _%$%tl6353263596%_)))
                                              (let ((_%$%hd6354663641%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e6354563637%_)))
                                                    (_%$%tl6354763644%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e6354563637%_))))
                                                (if (gx#stx-pair/null?
                                                     _%$%tl6354763644%_)
                                                    (let ((_g107468_
                                                           (gx#syntax-split-splice
                                                            _%$%tl6354763644%_
                                                            '0)))
                                                      (begin
                                                        (let ((_g107469_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (if (##values? _g107468_)
                             (##values-length _g107468_)
                             1))))
                  (if (not (let () (declare (not safe)) (##fx= _g107469_ 2)))
                      (error "Context expects 2 values" _g107469_)))
                (let ((_%$%target6354863647%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g107468_ 0)))
                      (_%$%tl6355063650%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g107468_ 1))))
                  (if (gx#stx-null? _%$%tl6355063650%_)
                      (letrec ((_%$%loop6355163653%_
                                (lambda (_%$%hd6354963657%_
                                         _%$%rest6355563660%_)
                                  (if (gx#stx-pair? _%$%hd6354963657%_)
                                      (let ((_%$%e6355263662%_
                                             (gx#syntax-e _%$%hd6354963657%_)))
                                        (let ((_%$%lp-hd6355363666%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e6355263662%_)))
                                              (_%$%lp-tl6355463669%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e6355263662%_))))
                                          (_%$%loop6355163653%_
                                           _%$%lp-tl6355463669%_
                                           (cons _%$%lp-hd6355363666%_
                                                 _%$%rest6355563660%_))))
                                      (let ((_%$%rest6355663672%_
                                             (reverse _%$%rest6355563660%_)))
                                        (if (gx#identifier? _%$%hd6353463603%_)
                                            (let ((_%meta63711%_
                                                   (gx#syntax-local-value
                                                    _%$%hd6352863583%_
                                                    false)))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (class-instance?
                                                     gerbil/core/mop~MOP-2#meta-object::t
                                                     _%meta63711%_))
                                                  '#!void
                                                  (gx#raise-syntax-error
                                                   '#f
                                                   '"not a meta-object"
                                                   _%stx63514%_
                                                   _%$%hd6352863583%_
                                                   _%meta63711%_))
                                              (cons (gx#datum->syntax
                                                     '#f
                                                     'begin-syntax)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'let)
                        (cons (cons (gx#datum->syntax '#f 'tab)
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'meta-object-methods!)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'syntax-local-value)
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'syntax)
                                (cons _%$%hd6352863583%_ '()))
                          '()))
              '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          '()))
                              (cons (cons (gx#datum->syntax '#f 'hash-put!)
                                          (cons (gx#datum->syntax '#f 'tab)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'quote)
                                                            (cons _%$%hd6353463603%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              (cons (cons (gx#datum->syntax '#f 'lambda)
                          (cons (foldr (lambda (_%$%g6371363718%_
                                                _%$%g6371463721%_)
                                         (cons _%$%g6371363718%_
                                               _%$%g6371463721%_))
                                       '()
                                       _%$%arg6354463634%_)
                                (cons _%$%hd6354663641%_
                                      (foldr (lambda (_%$%g6371563724%_
                                                      _%$%g6371663727%_)
                                               (cons _%$%g6371563724%_
                                                     _%$%g6371663727%_))
                                             '()
                                             _%$%rest6355663672%_))))
                    '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '())))
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g6351763562%_
                                             _%$%g6351863566%_)))))))
                        (_%$%loop6355163653%_ _%$%target6354863647%_ '()))
                      (_%$%g6351763562%_ _%$%g6351863566%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g6351763562%_
                                                     _%$%g6351863566%_))))
                                            (_%$%g6351763562%_
                                             _%$%g6351863566%_)))))))
                        (_%$%loop6353963615%_ _%$%target6353663609%_ '()))
                      (_%$%g6351763562%_ _%$%g6351863566%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g6351763562%_
                                                     _%$%g6351863566%_))))
                                            (_%$%g6351763562%_
                                             _%$%g6351863566%_))))
                                    (_%$%g6351763562%_ _%$%g6351863566%_))))
                            (_%$%g6351763562%_ _%$%g6351863566%_))))
                    (_%$%g6351763562%_ _%$%g6351863566%_)))))
        (_%$%g6351663730%_ _%stx63514%_)))))
