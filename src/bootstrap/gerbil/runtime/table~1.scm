(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |[:0:]#do-raw-table-lock|
    (lambda (_%$stx123254%_)
      (let* ((_%$%g123258123276%_
              (lambda (_%$%g123259123272%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g123259123272%_)))
             (_%$%g123257123332%_
              (lambda (_%$%g123259123280%_)
                (if (gx#stx-pair? _%$%g123259123280%_)
                    (let ((_%$%e123262123283%_
                           (gx#syntax-e _%$%g123259123280%_)))
                      (let ((_%$%hd123263123287%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123262123283%_)))
                            (_%$%tl123264123290%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123262123283%_))))
                        (if (gx#stx-pair? _%$%tl123264123290%_)
                            (let ((_%$%e123265123293%_
                                   (gx#syntax-e _%$%tl123264123290%_)))
                              (let ((_%$%hd123266123297%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123265123293%_)))
                                    (_%$%tl123267123300%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123265123293%_))))
                                (if (gx#stx-pair? _%$%tl123267123300%_)
                                    (let ((_%$%e123268123303%_
                                           (gx#syntax-e _%$%tl123267123300%_)))
                                      (let ((_%$%hd123269123307%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e123268123303%_)))
                                            (_%$%tl123270123310%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e123268123303%_))))
                                        (if (gx#stx-null? _%$%tl123270123310%_)
                                            (cons (gx#datum->syntax '#f 'let)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'lock)
                                                              (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '#f
                                   '&raw-table-lock)
                                  (cons _%$%hd123266123297%_ '()))
                            '()))
                (cons (cons (gx#datum->syntax '#f '__do-inline-lock!)
                            (cons (gx#datum->syntax '#f 'lock)
                                  (cons _%$%hd123269123307%_ '())))
                      '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g123258123276%_
                                             _%$%g123259123280%_))))
                                    (_%$%g123258123276%_
                                     _%$%g123259123280%_))))
                            (_%$%g123258123276%_ _%$%g123259123280%_))))
                    (_%$%g123258123276%_ _%$%g123259123280%_)))))
        (_%$%g123257123332%_ _%$stx123254%_))))
  (define |[:0:]#deftable|
    (lambda (_%stx123336%_)
      (let* ((_%$%g123339123361%_
              (lambda (_%$%g123340123357%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g123340123357%_)))
             (_%$%g123338123674%_
              (lambda (_%$%g123340123365%_)
                (if (gx#stx-pair? _%$%g123340123365%_)
                    (let ((_%$%e123344123368%_
                           (gx#syntax-e _%$%g123340123365%_)))
                      (let ((_%$%hd123345123372%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123344123368%_)))
                            (_%$%tl123346123375%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123344123368%_))))
                        (if (gx#stx-pair? _%$%tl123346123375%_)
                            (let ((_%$%e123347123378%_
                                   (gx#syntax-e _%$%tl123346123375%_)))
                              (let ((_%$%hd123348123382%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123347123378%_)))
                                    (_%$%tl123349123385%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123347123378%_))))
                                (if (gx#stx-pair? _%$%tl123349123385%_)
                                    (let ((_%$%e123350123388%_
                                           (gx#syntax-e _%$%tl123349123385%_)))
                                      (let ((_%$%hd123351123392%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e123350123388%_)))
                                            (_%$%tl123352123395%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e123350123388%_))))
                                        (if (gx#stx-pair? _%$%tl123352123395%_)
                                            (let ((_%$%e123353123398%_
                                                   (gx#syntax-e
                                                    _%$%tl123352123395%_)))
                                              (let ((_%$%hd123354123402%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e123353123398%_)))
                                                    (_%$%tl123355123405%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e123353123398%_))))
                                                (if (gx#stx-null?
                                                     _%$%tl123355123405%_)
                                                    (let* ((_%$%g123430123485%_
                                                            (lambda (_%$%g123431123481%_)
                                                              (gx#raise-syntax-error
                                                               '#f
                                                               '"Bad syntax; invalid match target"
                                                               _%$%g123431123481%_)))
                                                           (_%$%g123429123670%_
                                                            (lambda (_%$%g123431123489%_)
                                                              (if (gx#stx-pair?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%g123431123489%_)
                          (let ((_%$%e123444123492%_
                                 (gx#syntax-e _%$%g123431123489%_)))
                            (let ((_%$%hd123445123496%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e123444123492%_)))
                                  (_%$%tl123446123499%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e123444123492%_))))
                              (if (gx#stx-pair? _%$%tl123446123499%_)
                                  (let ((_%$%e123447123502%_
                                         (gx#syntax-e _%$%tl123446123499%_)))
                                    (let ((_%$%hd123448123506%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e123447123502%_)))
                                          (_%$%tl123449123509%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e123447123502%_))))
                                      (if (gx#stx-pair? _%$%tl123449123509%_)
                                          (let ((_%$%e123450123512%_
                                                 (gx#syntax-e
                                                  _%$%tl123449123509%_)))
                                            (let ((_%$%hd123451123516%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e123450123512%_)))
                                                  (_%$%tl123452123519%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e123450123512%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl123452123519%_)
                                                  (let ((_%$%e123453123522%_
                                                         (gx#syntax-e
                                                          _%$%tl123452123519%_)))
                                                    (let ((_%$%hd123454123526%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e123453123522%_)))
                                                          (_%$%tl123455123529%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e123453123522%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl123455123529%_)
                                                          (let ((_%$%e123456123532%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl123455123529%_)))
                    (let ((_%$%hd123457123536%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e123456123532%_)))
                          (_%$%tl123458123539%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e123456123532%_))))
                      (if (gx#stx-pair? _%$%tl123458123539%_)
                          (let ((_%$%e123459123542%_
                                 (gx#syntax-e _%$%tl123458123539%_)))
                            (let ((_%$%hd123460123546%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e123459123542%_)))
                                  (_%$%tl123461123549%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e123459123542%_))))
                              (if (gx#stx-pair? _%$%tl123461123549%_)
                                  (let ((_%$%e123462123552%_
                                         (gx#syntax-e _%$%tl123461123549%_)))
                                    (let ((_%$%hd123463123556%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e123462123552%_)))
                                          (_%$%tl123464123559%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e123462123552%_))))
                                      (if (gx#stx-pair? _%$%tl123464123559%_)
                                          (let ((_%$%e123465123562%_
                                                 (gx#syntax-e
                                                  _%$%tl123464123559%_)))
                                            (let ((_%$%hd123466123566%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e123465123562%_)))
                                                  (_%$%tl123467123569%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e123465123562%_))))
                                              (if (gx#stx-pair?
                                                   _%$%tl123467123569%_)
                                                  (let ((_%$%e123468123572%_
                                                         (gx#syntax-e
                                                          _%$%tl123467123569%_)))
                                                    (let ((_%$%hd123469123576%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e123468123572%_)))
                                                          (_%$%tl123470123579%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e123468123572%_))))
                                                      (if (gx#stx-pair?
                                                           _%$%tl123470123579%_)
                                                          (let ((_%$%e123471123582%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl123470123579%_)))
                    (let ((_%$%hd123472123586%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e123471123582%_)))
                          (_%$%tl123473123589%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e123471123582%_))))
                      (if (gx#stx-pair? _%$%tl123473123589%_)
                          (let ((_%$%e123474123592%_
                                 (gx#syntax-e _%$%tl123473123589%_)))
                            (let ((_%$%hd123475123596%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e123474123592%_)))
                                  (_%$%tl123476123599%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e123474123592%_))))
                              (if (gx#stx-pair? _%$%tl123476123599%_)
                                  (let ((_%$%e123477123602%_
                                         (gx#syntax-e _%$%tl123476123599%_)))
                                    (let ((_%$%hd123478123606%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e123477123602%_)))
                                          (_%$%tl123479123609%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e123477123602%_))))
                                      (if (gx#stx-null? _%$%tl123479123609%_)
                                          (cons (gx#datum->syntax '#f 'begin)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'def)
                                                            (cons (cons _%$%hd123445123496%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (cons (cons (gx#datum->syntax '#f 'size-hint)
                                            (cons '#f '()))
                                      (cons (cons (gx#datum->syntax '#f 'seed)
                                                  (cons '0 '()))
                                            '())))
                          (cons (cons (gx#datum->syntax '#f 'make-raw-table)
                                      (cons (gx#datum->syntax '#f 'size-hint)
                                            (cons _%$%hd123351123392%_
                                                  (cons _%$%hd123354123402%_
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'seed)
                                                              '())))))
                                '())))
              (cons (cons (gx#datum->syntax '#f 'def)
                          (cons (cons _%$%hd123448123506%_
                                      (cons (cons (gx#datum->syntax
                                                   '#f
                                                   'size-hint)
                                                  (cons '#f '()))
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'seed)
                                                        (cons '0 '()))
                                                  '())))
                                (cons (cons (gx#datum->syntax
                                             '#f
                                             'make-raw-table/lock)
                                            (cons (gx#datum->syntax
                                                   '#f
                                                   'size-hint)
                                                  (cons _%$%hd123351123392%_
                                                        (cons _%$%hd123354123402%_
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'seed)
                            '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '())))
                    (cons (cons (gx#datum->syntax '#f 'def)
                                (cons (cons _%$%hd123451123516%_
                                            (cons (gx#datum->syntax '#f 'tab)
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'key)
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'default)
                                                              '()))))
                                      (cons (cons (gx#datum->syntax '#f 'let)
                                                  (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'table)
                            (cons (cons (gx#datum->syntax
                                         '#f
                                         '&raw-table-table)
                                        (cons (gx#datum->syntax '#f 'tab) '()))
                                  '()))
                      (cons (cons (gx#datum->syntax '#f 'seed)
                                  (cons (cons (gx#datum->syntax
                                               '#f
                                               '&raw-table-seed)
                                              (cons (gx#datum->syntax '#f 'tab)
                                                    '()))
                                        '()))
                            '()))
                (cons (cons (gx#datum->syntax '#f '__table-ref)
                            (cons (gx#datum->syntax '#f 'table)
                                  (cons (gx#datum->syntax '#f 'seed)
                                        (cons _%$%hd123351123392%_
                                              (cons _%$%hd123354123402%_
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'key)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'default)
                        '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                      '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '())))
                          (cons (cons (gx#datum->syntax '#f 'def)
                                      (cons (cons _%$%hd123454123526%_
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'tab)
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'key)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'default)
                            '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'do-raw-table-lock)
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'tab)
                                                              (cons (cons _%$%hd123451123516%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (cons (gx#datum->syntax '#f 'tab)
                                        (cons (gx#datum->syntax '#f 'key)
                                              (cons (gx#datum->syntax
                                                     '#f
                                                     'default)
                                                    '()))))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '())))
                                (cons (cons (gx#datum->syntax '#f 'def)
                                            (cons (cons _%$%hd123457123536%_
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'tab)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'key)
                            (cons (gx#datum->syntax '#f 'value) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'let)
                                                              (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                         '#f
                                         'table)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     '&raw-table-table)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'tab)
                                                          '()))
                                              '()))
                                  (cons (cons (gx#datum->syntax '#f 'seed)
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           '&raw-table-seed)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'tab)
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '()))
                                        '()))
                            (cons (cons (gx#datum->syntax '#f '__table-set!)
                                        (cons (gx#datum->syntax '#f 'table)
                                              (cons (gx#datum->syntax
                                                     '#f
                                                     'seed)
                                                    (cons _%$%hd123351123392%_
                                                          (cons _%$%hd123354123402%_
                                                                (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'key)
                              (cons (gx#datum->syntax '#f 'value)
                                    (cons (cons (gx#datum->syntax '#f 'lambda)
                                                (cons '()
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'set!)
                          (cons (cons (gx#datum->syntax '#f '&raw-table-free)
                                      (cons (gx#datum->syntax '#f 'tab) '()))
                                (cons (cons (gx#datum->syntax '#f 'fx-)
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         '&raw-table-free)
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'tab)
                                                              '()))
                                                  (cons '1 '())))
                                      '())))
                    (cons (cons (gx#datum->syntax '#f 'set!)
                                (cons (cons (gx#datum->syntax
                                             '#f
                                             '&raw-table-count)
                                            (cons (gx#datum->syntax '#f 'tab)
                                                  '()))
                                      (cons (cons (gx#datum->syntax '#f 'fx+)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               '&raw-table-count)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'tab)
                            '()))
                (cons '1 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '())))
                          '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       'lambda)
                                                      (cons '()
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'set!)
                                (cons (cons (gx#datum->syntax
                                             '#f
                                             '&raw-table-count)
                                            (cons (gx#datum->syntax '#f 'tab)
                                                  '()))
                                      (cons (cons (gx#datum->syntax '#f 'fx+)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               '&raw-table-count)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'tab)
                            '()))
                (cons '1 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '())))
                          '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '())))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  '())))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (cons (cons (gx#datum->syntax '#f 'def)
                                                  (cons (cons _%$%hd123460123546%_
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'tab)
                            (cons (gx#datum->syntax '#f 'key)
                                  (cons (gx#datum->syntax '#f 'value) '()))))
                (cons (cons (gx#datum->syntax '#f 'when)
                            (cons (cons (gx#datum->syntax '#f 'fx<)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     '&raw-table-free)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'tab)
                                                          '()))
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'fxquotient)
                                                          (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'vector-length)
                              (cons (cons (gx#datum->syntax
                                           '#f
                                           '&raw-table-table)
                                          (cons (gx#datum->syntax '#f 'tab)
                                                '()))
                                    '()))
                        (cons '4 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  (cons (cons (gx#datum->syntax
                                               '#f
                                               '__raw-table-rehash!)
                                              (cons (gx#datum->syntax '#f 'tab)
                                                    '()))
                                        '())))
                      (cons (cons _%$%hd123457123536%_
                                  (cons (gx#datum->syntax '#f 'tab)
                                        (cons (gx#datum->syntax '#f 'key)
                                              (cons (gx#datum->syntax
                                                     '#f
                                                     'value)
                                                    '()))))
                            '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'def)
                                                        (cons (cons _%$%hd123463123556%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons (gx#datum->syntax '#f 'tab)
                                  (cons (gx#datum->syntax '#f 'key)
                                        (cons (gx#datum->syntax '#f 'value)
                                              '()))))
                      (cons (cons (gx#datum->syntax '#f 'do-raw-table-lock)
                                  (cons (gx#datum->syntax '#f 'tab)
                                        (cons (cons _%$%hd123460123546%_
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'tab)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'key)
                        (cons (gx#datum->syntax '#f 'value) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'def)
                                                              (cons (cons _%$%hd123466123566%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (cons (gx#datum->syntax '#f 'tab)
                                        (cons (gx#datum->syntax '#f 'key)
                                              (cons _%$%hd123469123576%_
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'default)
                                                          '())))))
                            (cons (cons (gx#datum->syntax '#f 'let)
                                        (cons (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'table)
                                                          (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               '&raw-table-table)
                              (cons (gx#datum->syntax '#f 'tab) '()))
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'seed)
                        (cons (cons (gx#datum->syntax '#f '&raw-table-seed)
                                    (cons (gx#datum->syntax '#f 'tab) '()))
                              '()))
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           '__table-update!)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'table)
                        (cons (gx#datum->syntax '#f 'seed)
                              (cons _%$%hd123351123392%_
                                    (cons _%$%hd123354123402%_
                                          (cons (gx#datum->syntax '#f 'key)
                                                (cons _%$%hd123469123576%_
                                                      (cons (gx#datum->syntax
                                                             '#f
                                                             'default)
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'lambda)
                                (cons '()
                                      (cons (cons (gx#datum->syntax '#f 'set!)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               '&raw-table-free)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'tab)
                            '()))
                (cons (cons (gx#datum->syntax '#f 'fx-)
                            (cons (cons (gx#datum->syntax '#f '&raw-table-free)
                                        (cons (gx#datum->syntax '#f 'tab) '()))
                                  (cons '1 '())))
                      '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'set!)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             '&raw-table-count)
                            (cons (gx#datum->syntax '#f 'tab) '()))
                      (cons (cons (gx#datum->syntax '#f 'fx+)
                                  (cons (cons (gx#datum->syntax
                                               '#f
                                               '&raw-table-count)
                                              (cons (gx#datum->syntax '#f 'tab)
                                                    '()))
                                        (cons '1 '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '()))))
                          (cons (cons (gx#datum->syntax '#f 'lambda)
                                      (cons '()
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'set!)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             '&raw-table-count)
                            (cons (gx#datum->syntax '#f 'tab) '()))
                      (cons (cons (gx#datum->syntax '#f 'fx+)
                                  (cons (cons (gx#datum->syntax
                                               '#f
                                               '&raw-table-count)
                                              (cons (gx#datum->syntax '#f 'tab)
                                                    '()))
                                        (cons '1 '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '())))
                                '()))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  '())))
                (cons (cons (gx#datum->syntax '#f 'def)
                            (cons (cons _%$%hd123469123576%_
                                        (cons (gx#datum->syntax '#f 'tab)
                                              (cons (gx#datum->syntax '#f 'key)
                                                    (cons _%$%hd123469123576%_
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'default)
                        '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  (cons (cons (gx#datum->syntax '#f 'when)
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'fx<)
                                                          (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               '&raw-table-free)
                              (cons (gx#datum->syntax '#f 'tab) '()))
                        (cons (cons (gx#datum->syntax '#f 'fxquotient)
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'vector-length)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             '&raw-table-table)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'tab)
                          '()))
              '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (cons '4 '())))
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         '__raw-table-rehash!)
                        (cons (gx#datum->syntax '#f 'tab) '()))
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons _%$%hd123466123566%_
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'tab)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'key)
                        (cons _%$%hd123469123576%_
                              (cons (gx#datum->syntax '#f 'default) '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))))
                      (cons (cons (gx#datum->syntax '#f 'def)
                                  (cons (cons _%$%hd123472123586%_
                                              (cons (gx#datum->syntax '#f 'tab)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'key)
                                                          (cons _%$%hd123469123576%_
                                                                (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'default)
                              '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'do-raw-table-lock)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'tab)
                                                          (cons (cons _%$%hd123469123576%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (gx#datum->syntax '#f 'tab)
                                    (cons (gx#datum->syntax '#f 'key)
                                          (cons _%$%hd123469123576%_
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'default)
                                                      '())))))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))
                            (cons (cons (gx#datum->syntax '#f 'def)
                                        (cons (cons _%$%hd123475123596%_
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'tab)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'key)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'let)
                                                          (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                     '#f
                                     'table)
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 '&raw-table-table)
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'tab)
                                                      '()))
                                          '()))
                              (cons (cons (gx#datum->syntax '#f 'seed)
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       '&raw-table-seed)
                                                      (cons (gx#datum->syntax
                                                             '#f
                                                             'tab)
                                                            '()))
                                                '()))
                                    '()))
                        (cons (cons (gx#datum->syntax '#f '__table-del!)
                                    (cons (gx#datum->syntax '#f 'table)
                                          (cons (gx#datum->syntax '#f 'seed)
                                                (cons _%$%hd123351123392%_
                                                      (cons _%$%hd123354123402%_
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'key)
                          (cons (cons (gx#datum->syntax '#f 'lambda)
                                      (cons '()
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'set!)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             '&raw-table-count)
                            (cons (gx#datum->syntax '#f 'tab) '()))
                      (cons (cons (gx#datum->syntax '#f 'fx-)
                                  (cons (cons (gx#datum->syntax
                                               '#f
                                               '&raw-table-count)
                                              (cons (gx#datum->syntax '#f 'tab)
                                                    '()))
                                        (cons '1 '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '())))
                                '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  (cons (cons (gx#datum->syntax '#f 'def)
                                              (cons (cons _%$%hd123478123606%_
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'tab)
                        (cons (gx#datum->syntax '#f 'key) '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'do-raw-table-lock)
                        (cons (gx#datum->syntax '#f 'tab)
                              (cons (cons _%$%hd123475123596%_
                                          (cons (gx#datum->syntax '#f 'tab)
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'key)
                                                      '())))
                                    '())))
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        '())))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%g123430123485%_
                                           _%$%g123431123489%_))))
                                  (_%$%g123430123485%_ _%$%g123431123489%_))))
                          (_%$%g123430123485%_ _%$%g123431123489%_))))
                  (_%$%g123430123485%_ _%$%g123431123489%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g123430123485%_
                                                   _%$%g123431123489%_))))
                                          (_%$%g123430123485%_
                                           _%$%g123431123489%_))))
                                  (_%$%g123430123485%_ _%$%g123431123489%_))))
                          (_%$%g123430123485%_ _%$%g123431123489%_))))
                  (_%$%g123430123485%_ _%$%g123431123489%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g123430123485%_
                                                   _%$%g123431123489%_))))
                                          (_%$%g123430123485%_
                                           _%$%g123431123489%_))))
                                  (_%$%g123430123485%_ _%$%g123431123489%_))))
                          (_%$%g123430123485%_ _%$%g123431123489%_)))))
              (_%$%g123429123670%_
               (list (gx#stx-identifier
                      _%$%hd123348123382%_
                      '"make-"
                      _%$%hd123348123382%_)
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      '"make-"
                      _%$%hd123348123382%_
                      '"/lock")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-ref")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-ref/lock")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      '"__"
                      _%$%hd123348123382%_
                      '"-set!")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-set!")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-set!/lock")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      '"__"
                      _%$%hd123348123382%_
                      '"-update!")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-update!")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-update!/lock")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-delete!")
                     (gx#stx-identifier
                      _%$%hd123348123382%_
                      _%$%hd123348123382%_
                      '"-delete!/lock"))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g123339123361%_
                                                     _%$%g123340123365%_))))
                                            (_%$%g123339123361%_
                                             _%$%g123340123365%_))))
                                    (_%$%g123339123361%_
                                     _%$%g123340123365%_))))
                            (_%$%g123339123361%_ _%$%g123340123365%_))))
                    (_%$%g123339123361%_ _%$%g123340123365%_)))))
        (_%$%g123338123674%_ _%stx123336%_))))
  (define |[:0:]#probe-step|
    (lambda (_%$stx123678%_)
      (let* ((_%$%g123682123704%_
              (lambda (_%$%g123683123700%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g123683123700%_)))
             (_%$%g123681123773%_
              (lambda (_%$%g123683123708%_)
                (if (gx#stx-pair? _%$%g123683123708%_)
                    (let ((_%$%e123687123711%_
                           (gx#syntax-e _%$%g123683123708%_)))
                      (let ((_%$%hd123688123715%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123687123711%_)))
                            (_%$%tl123689123718%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123687123711%_))))
                        (if (gx#stx-pair? _%$%tl123689123718%_)
                            (let ((_%$%e123690123721%_
                                   (gx#syntax-e _%$%tl123689123718%_)))
                              (let ((_%$%hd123691123725%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123690123721%_)))
                                    (_%$%tl123692123728%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123690123721%_))))
                                (if (gx#stx-pair? _%$%tl123692123728%_)
                                    (let ((_%$%e123693123731%_
                                           (gx#syntax-e _%$%tl123692123728%_)))
                                      (let ((_%$%hd123694123735%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e123693123731%_)))
                                            (_%$%tl123695123738%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e123693123731%_))))
                                        (if (gx#stx-pair? _%$%tl123695123738%_)
                                            (let ((_%$%e123696123741%_
                                                   (gx#syntax-e
                                                    _%$%tl123695123738%_)))
                                              (let ((_%$%hd123697123745%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e123696123741%_)))
                                                    (_%$%tl123698123748%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e123696123741%_))))
                                                (if (gx#stx-null?
                                                     _%$%tl123698123748%_)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'let)
                                                          (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'next-probe)
                              (cons (cons (gx#datum->syntax '#f 'fx+)
                                          (cons _%$%hd123691123725%_
                                                (cons _%$%hd123694123735%_
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'fx*)
                          (cons _%$%hd123694123735%_
                                (cons _%$%hd123694123735%_ '())))
                    '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '()))
                        (cons (cons (gx#datum->syntax '#f 'fxmodulo)
                                    (cons (gx#datum->syntax '#f 'next-probe)
                                          (cons _%$%hd123697123745%_ '())))
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g123682123704%_
                                                     _%$%g123683123708%_))))
                                            (_%$%g123682123704%_
                                             _%$%g123683123708%_))))
                                    (_%$%g123682123704%_
                                     _%$%g123683123708%_))))
                            (_%$%g123682123704%_ _%$%g123683123708%_))))
                    (_%$%g123682123704%_ _%$%g123683123708%_)))))
        (_%$%g123681123773%_ _%$stx123678%_))))
  (define |[:0:]#__table-ref|
    (lambda (_%$stx123777%_)
      (let* ((_%$%g123781123815%_
              (lambda (_%$%g123782123811%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g123782123811%_)))
             (_%$%g123780123926%_
              (lambda (_%$%g123782123819%_)
                (if (gx#stx-pair? _%$%g123782123819%_)
                    (let ((_%$%e123789123822%_
                           (gx#syntax-e _%$%g123782123819%_)))
                      (let ((_%$%hd123790123826%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123789123822%_)))
                            (_%$%tl123791123829%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123789123822%_))))
                        (if (gx#stx-pair? _%$%tl123791123829%_)
                            (let ((_%$%e123792123832%_
                                   (gx#syntax-e _%$%tl123791123829%_)))
                              (let ((_%$%hd123793123836%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123792123832%_)))
                                    (_%$%tl123794123839%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123792123832%_))))
                                (if (gx#stx-pair? _%$%tl123794123839%_)
                                    (let ((_%$%e123795123842%_
                                           (gx#syntax-e _%$%tl123794123839%_)))
                                      (let ((_%$%hd123796123846%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e123795123842%_)))
                                            (_%$%tl123797123849%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e123795123842%_))))
                                        (if (gx#stx-pair? _%$%tl123797123849%_)
                                            (let ((_%$%e123798123852%_
                                                   (gx#syntax-e
                                                    _%$%tl123797123849%_)))
                                              (let ((_%$%hd123799123856%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e123798123852%_)))
                                                    (_%$%tl123800123859%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e123798123852%_))))
                                                (if (gx#stx-pair?
                                                     _%$%tl123800123859%_)
                                                    (let ((_%$%e123801123862%_
                                                           (gx#syntax-e
                                                            _%$%tl123800123859%_)))
                                                      (let ((_%$%hd123802123866%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e123801123862%_)))
                    (_%$%tl123803123869%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e123801123862%_))))
                (if (gx#stx-pair? _%$%tl123803123869%_)
                    (let ((_%$%e123804123872%_
                           (gx#syntax-e _%$%tl123803123869%_)))
                      (let ((_%$%hd123805123876%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123804123872%_)))
                            (_%$%tl123806123879%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123804123872%_))))
                        (if (gx#stx-pair? _%$%tl123806123879%_)
                            (let ((_%$%e123807123882%_
                                   (gx#syntax-e _%$%tl123806123879%_)))
                              (let ((_%$%hd123808123886%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123807123882%_)))
                                    (_%$%tl123809123889%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123807123882%_))))
                                (if (gx#stx-null? _%$%tl123809123889%_)
                                    (cons (gx#datum->syntax '#f 'let*)
                                          (cons (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'h)
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'fxxor)
                                (cons (cons _%$%hd123799123856%_
                                            (cons _%$%hd123805123876%_ '()))
                                      (cons _%$%hd123796123846%_ '())))
                          '()))
              (cons (cons (gx#datum->syntax '#f 'size)
                          (cons (cons (gx#datum->syntax '#f 'vector-length)
                                      (cons _%$%hd123793123836%_ '()))
                                '()))
                    (cons (cons (gx#datum->syntax '#f 'entries)
                                (cons (cons (gx#datum->syntax '#f 'fxquotient)
                                            (cons (gx#datum->syntax '#f 'size)
                                                  (cons '2 '())))
                                      '()))
                          (cons (cons (gx#datum->syntax '#f 'start)
                                      (cons (cons (gx#datum->syntax
                                                   '#f
                                                   'fxarithmetic-shift-left)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'fxmodulo)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'h)
                            (cons (gx#datum->syntax '#f 'entries) '())))
                (cons '1 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '()))
                                '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'let)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'loop)
                          (cons (cons (cons (gx#datum->syntax '#f 'probe)
                                            (cons (gx#datum->syntax '#f 'start)
                                                  '()))
                                      (cons (cons (gx#datum->syntax '#f 'i)
                                                  (cons '1 '()))
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'deleted)
                                                        (cons '#f '()))
                                                  '())))
                                (cons (cons (gx#datum->syntax '#f 'let)
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'k)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'vector-ref)
                            (cons _%$%hd123793123836%_
                                  (cons (gx#datum->syntax '#f 'probe) '())))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'cond)
                                                              (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                         '#f
                                         'eq?)
                                        (cons (gx#datum->syntax '#f 'k)
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'macro-unused-obj)
                                                          '())
                                                    '())))
                                  (cons _%$%hd123808123886%_ '()))
                            (cons (cons (cons (gx#datum->syntax '#f 'eq?)
                                              (cons (gx#datum->syntax '#f 'k)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'macro-deleted-obj)
                        '())
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'loop)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'probe-step)
                        (cons (gx#datum->syntax '#f 'start)
                              (cons (gx#datum->syntax '#f 'i)
                                    (cons (gx#datum->syntax '#f 'size) '()))))
                  (cons (cons (gx#datum->syntax '#f 'fx+)
                              (cons (gx#datum->syntax '#f 'i) (cons '1 '())))
                        (cons (cons (gx#datum->syntax '#f 'or)
                                    (cons (gx#datum->syntax '#f 'deleted)
                                          (cons (gx#datum->syntax '#f 'probe)
                                                '())))
                              '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))
                                  (cons (cons (cons _%$%hd123802123866%_
                                                    (cons _%$%hd123805123876%_
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'k)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'vector-ref)
                                                          (cons _%$%hd123793123836%_
                                                                (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                     '#f
                                     'fx+)
                                    (cons (gx#datum->syntax '#f 'probe)
                                          (cons '1 '())))
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '()))
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'else)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'loop)
                        (cons (cons (gx#datum->syntax '#f 'probe-step)
                                    (cons (gx#datum->syntax '#f 'start)
                                          (cons (gx#datum->syntax '#f 'i)
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'size)
                                                      '()))))
                              (cons (cons (gx#datum->syntax '#f 'fx+)
                                          (cons (gx#datum->syntax '#f 'i)
                                                (cons '1 '())))
                                    (cons (gx#datum->syntax '#f 'deleted)
                                          '()))))
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '()))))
              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%g123781123815%_
                                     _%$%g123782123819%_))))
                            (_%$%g123781123815%_ _%$%g123782123819%_))))
                    (_%$%g123781123815%_ _%$%g123782123819%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g123781123815%_
                                                     _%$%g123782123819%_))))
                                            (_%$%g123781123815%_
                                             _%$%g123782123819%_))))
                                    (_%$%g123781123815%_
                                     _%$%g123782123819%_))))
                            (_%$%g123781123815%_ _%$%g123782123819%_))))
                    (_%$%g123781123815%_ _%$%g123782123819%_)))))
        (_%$%g123780123926%_ _%$stx123777%_))))
  (define |[:0:]#__table-set!|
    (lambda (_%$stx123930%_)
      (let* ((_%$%g123934123976%_
              (lambda (_%$%g123935123972%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g123935123972%_)))
             (_%$%g123933124115%_
              (lambda (_%$%g123935123980%_)
                (if (gx#stx-pair? _%$%g123935123980%_)
                    (let ((_%$%e123944123983%_
                           (gx#syntax-e _%$%g123935123980%_)))
                      (let ((_%$%hd123945123987%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123944123983%_)))
                            (_%$%tl123946123990%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123944123983%_))))
                        (if (gx#stx-pair? _%$%tl123946123990%_)
                            (let ((_%$%e123947123993%_
                                   (gx#syntax-e _%$%tl123946123990%_)))
                              (let ((_%$%hd123948123997%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123947123993%_)))
                                    (_%$%tl123949124000%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123947123993%_))))
                                (if (gx#stx-pair? _%$%tl123949124000%_)
                                    (let ((_%$%e123950124003%_
                                           (gx#syntax-e _%$%tl123949124000%_)))
                                      (let ((_%$%hd123951124007%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e123950124003%_)))
                                            (_%$%tl123952124010%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e123950124003%_))))
                                        (if (gx#stx-pair? _%$%tl123952124010%_)
                                            (let ((_%$%e123953124013%_
                                                   (gx#syntax-e
                                                    _%$%tl123952124010%_)))
                                              (let ((_%$%hd123954124017%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e123953124013%_)))
                                                    (_%$%tl123955124020%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e123953124013%_))))
                                                (if (gx#stx-pair?
                                                     _%$%tl123955124020%_)
                                                    (let ((_%$%e123956124023%_
                                                           (gx#syntax-e
                                                            _%$%tl123955124020%_)))
                                                      (let ((_%$%hd123957124027%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e123956124023%_)))
                    (_%$%tl123958124030%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e123956124023%_))))
                (if (gx#stx-pair? _%$%tl123958124030%_)
                    (let ((_%$%e123959124033%_
                           (gx#syntax-e _%$%tl123958124030%_)))
                      (let ((_%$%hd123960124037%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e123959124033%_)))
                            (_%$%tl123961124040%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e123959124033%_))))
                        (if (gx#stx-pair? _%$%tl123961124040%_)
                            (let ((_%$%e123962124043%_
                                   (gx#syntax-e _%$%tl123961124040%_)))
                              (let ((_%$%hd123963124047%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e123962124043%_)))
                                    (_%$%tl123964124050%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e123962124043%_))))
                                (if (gx#stx-pair? _%$%tl123964124050%_)
                                    (let ((_%$%e123965124053%_
                                           (gx#syntax-e _%$%tl123964124050%_)))
                                      (let ((_%$%hd123966124057%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e123965124053%_)))
                                            (_%$%tl123967124060%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e123965124053%_))))
                                        (if (gx#stx-pair? _%$%tl123967124060%_)
                                            (let ((_%$%e123968124063%_
                                                   (gx#syntax-e
                                                    _%$%tl123967124060%_)))
                                              (let ((_%$%hd123969124067%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e123968124063%_)))
                                                    (_%$%tl123970124070%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e123968124063%_))))
                                                (if (gx#stx-null?
                                                     _%$%tl123970124070%_)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'let*)
                                                          (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                     '#f
                                     'h)
                                    (cons (cons (gx#datum->syntax '#f 'fxxor)
                                                (cons (cons _%$%hd123954124017%_
                                                            (cons _%$%hd123960124037%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              (cons _%$%hd123951124007%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          '()))
                              (cons (cons (gx#datum->syntax '#f 'size)
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       'vector-length)
                                                      (cons _%$%hd123948123997%_
                                                            '()))
                                                '()))
                                    (cons (cons (gx#datum->syntax '#f 'entries)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'fxquotient)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'size)
                          (cons '2 '())))
              '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       'start)
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'fxarithmetic-shift-left)
                          (cons (cons (gx#datum->syntax '#f 'fxmodulo)
                                      (cons (gx#datum->syntax '#f 'h)
                                            (cons (gx#datum->syntax
                                                   '#f
                                                   'entries)
                                                  '())))
                                (cons '1 '())))
                    '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '()))))
                        (cons (cons (gx#datum->syntax '#f 'let)
                                    (cons (gx#datum->syntax '#f 'loop)
                                          (cons (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'probe)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'start)
                          '()))
              (cons (cons (gx#datum->syntax '#f 'i) (cons '1 '()))
                    (cons (cons (gx#datum->syntax '#f 'deleted) (cons '#f '()))
                          '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'let)
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'k)
                                (cons (cons (gx#datum->syntax '#f 'vector-ref)
                                            (cons _%$%hd123948123997%_
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'probe)
                                                        '())))
                                      '()))
                          (cons (cons (gx#datum->syntax '#f 'cond)
                                      (cons (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'eq?)
                                                        (cons (gx#datum->syntax
                                                               '#f
                                                               'k)
                                                              (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '#f
                                   'macro-unused-obj)
                                  '())
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'if)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'deleted)
                            (cons (cons (gx#datum->syntax '#f 'begin)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'vector-set!)
                                                    (cons _%$%hd123948123997%_
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'deleted)
                        (cons _%$%hd123960124037%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'vector-set!)
                                                          (cons _%$%hd123948123997%_
                                                                (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                     '#f
                                     'fx+)
                                    (cons (gx#datum->syntax '#f 'deleted)
                                          (cons '1 '())))
                              (cons _%$%hd123963124047%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons _%$%hd123969124067%_
                                                                '())
                                                          '()))))
                                  (cons (cons (gx#datum->syntax '#f 'begin)
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'vector-set!)
                                                          (cons _%$%hd123948123997%_
                                                                (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'probe)
                              (cons _%$%hd123960124037%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'vector-set!)
                        (cons _%$%hd123948123997%_
                              (cons (cons (gx#datum->syntax '#f 'fx+)
                                          (cons (gx#datum->syntax '#f 'probe)
                                                (cons '1 '())))
                                    (cons _%$%hd123963124047%_ '()))))
                  (cons (cons _%$%hd123966124057%_ '()) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        '()))))
                '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (cons (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'eq?)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'k)
                            (cons (cons (gx#datum->syntax
                                         '#f
                                         'macro-deleted-obj)
                                        '())
                                  '())))
                (cons (cons (gx#datum->syntax '#f 'loop)
                            (cons (cons (gx#datum->syntax '#f 'probe-step)
                                        (cons (gx#datum->syntax '#f 'start)
                                              (cons (gx#datum->syntax '#f 'i)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'size)
                                                          '()))))
                                  (cons (cons (gx#datum->syntax '#f 'fx+)
                                              (cons (gx#datum->syntax '#f 'i)
                                                    (cons '1 '())))
                                        (cons (cons (gx#datum->syntax '#f 'or)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'deleted)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'probe)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (cons _%$%hd123957124027%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%$%hd123960124037%_
                                  (cons (gx#datum->syntax '#f 'k) '())))
                      (cons (cons (gx#datum->syntax '#f 'vector-set!)
                                  (cons _%$%hd123948123997%_
                                        (cons (gx#datum->syntax '#f 'probe)
                                              (cons _%$%hd123960124037%_
                                                    '()))))
                            (cons (cons (gx#datum->syntax '#f 'vector-set!)
                                        (cons _%$%hd123948123997%_
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'fx+)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'probe)
                        (cons '1 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons _%$%hd123963124047%_
                                                          '()))))
                                  '())))
                (cons (cons (gx#datum->syntax '#f 'else)
                            (cons (cons (gx#datum->syntax '#f 'loop)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'probe-step)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'start)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'i)
                        (cons (gx#datum->syntax '#f 'size) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'fx+)
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'i)
                        (cons '1 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'deleted)
                                                          '()))))
                                  '()))
                      '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                '())))
              '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g123934123976%_
                                                     _%$%g123935123980%_))))
                                            (_%$%g123934123976%_
                                             _%$%g123935123980%_))))
                                    (_%$%g123934123976%_
                                     _%$%g123935123980%_))))
                            (_%$%g123934123976%_ _%$%g123935123980%_))))
                    (_%$%g123934123976%_ _%$%g123935123980%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g123934123976%_
                                                     _%$%g123935123980%_))))
                                            (_%$%g123934123976%_
                                             _%$%g123935123980%_))))
                                    (_%$%g123934123976%_
                                     _%$%g123935123980%_))))
                            (_%$%g123934123976%_ _%$%g123935123980%_))))
                    (_%$%g123934123976%_ _%$%g123935123980%_)))))
        (_%$%g123933124115%_ _%$stx123930%_))))
  (define |[:0:]#__table-update!|
    (lambda (_%$stx124119%_)
      (let* ((_%$%g124123124169%_
              (lambda (_%$%g124124124165%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g124124124165%_)))
             (_%$%g124122124322%_
              (lambda (_%$%g124124124173%_)
                (if (gx#stx-pair? _%$%g124124124173%_)
                    (let ((_%$%e124134124176%_
                           (gx#syntax-e _%$%g124124124173%_)))
                      (let ((_%$%hd124135124180%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e124134124176%_)))
                            (_%$%tl124136124183%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e124134124176%_))))
                        (if (gx#stx-pair? _%$%tl124136124183%_)
                            (let ((_%$%e124137124186%_
                                   (gx#syntax-e _%$%tl124136124183%_)))
                              (let ((_%$%hd124138124190%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e124137124186%_)))
                                    (_%$%tl124139124193%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e124137124186%_))))
                                (if (gx#stx-pair? _%$%tl124139124193%_)
                                    (let ((_%$%e124140124196%_
                                           (gx#syntax-e _%$%tl124139124193%_)))
                                      (let ((_%$%hd124141124200%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e124140124196%_)))
                                            (_%$%tl124142124203%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e124140124196%_))))
                                        (if (gx#stx-pair? _%$%tl124142124203%_)
                                            (let ((_%$%e124143124206%_
                                                   (gx#syntax-e
                                                    _%$%tl124142124203%_)))
                                              (let ((_%$%hd124144124210%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e124143124206%_)))
                                                    (_%$%tl124145124213%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e124143124206%_))))
                                                (if (gx#stx-pair?
                                                     _%$%tl124145124213%_)
                                                    (let ((_%$%e124146124216%_
                                                           (gx#syntax-e
                                                            _%$%tl124145124213%_)))
                                                      (let ((_%$%hd124147124220%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e124146124216%_)))
                    (_%$%tl124148124223%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e124146124216%_))))
                (if (gx#stx-pair? _%$%tl124148124223%_)
                    (let ((_%$%e124149124226%_
                           (gx#syntax-e _%$%tl124148124223%_)))
                      (let ((_%$%hd124150124230%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e124149124226%_)))
                            (_%$%tl124151124233%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e124149124226%_))))
                        (if (gx#stx-pair? _%$%tl124151124233%_)
                            (let ((_%$%e124152124236%_
                                   (gx#syntax-e _%$%tl124151124233%_)))
                              (let ((_%$%hd124153124240%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e124152124236%_)))
                                    (_%$%tl124154124243%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e124152124236%_))))
                                (if (gx#stx-pair? _%$%tl124154124243%_)
                                    (let ((_%$%e124155124246%_
                                           (gx#syntax-e _%$%tl124154124243%_)))
                                      (let ((_%$%hd124156124250%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e124155124246%_)))
                                            (_%$%tl124157124253%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e124155124246%_))))
                                        (if (gx#stx-pair? _%$%tl124157124253%_)
                                            (let ((_%$%e124158124256%_
                                                   (gx#syntax-e
                                                    _%$%tl124157124253%_)))
                                              (let ((_%$%hd124159124260%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e124158124256%_)))
                                                    (_%$%tl124160124263%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e124158124256%_))))
                                                (if (gx#stx-pair?
                                                     _%$%tl124160124263%_)
                                                    (let ((_%$%e124161124266%_
                                                           (gx#syntax-e
                                                            _%$%tl124160124263%_)))
                                                      (let ((_%$%hd124162124270%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e124161124266%_)))
                    (_%$%tl124163124273%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e124161124266%_))))
                (if (gx#stx-null? _%$%tl124163124273%_)
                    (cons (gx#datum->syntax '#f 'let*)
                          (cons (cons (cons (gx#datum->syntax '#f 'h)
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'fxxor)
                                                        (cons (cons _%$%hd124144124210%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%$%hd124150124230%_ '()))
                      (cons _%$%hd124141124200%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '()))
                                      (cons (cons (gx#datum->syntax '#f 'size)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'vector-length)
                                                              (cons _%$%hd124138124190%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'entries)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'fxquotient)
                            (cons (gx#datum->syntax '#f 'size) (cons '2 '())))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'start)
                                                              (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '#f
                                   'fxarithmetic-shift-left)
                                  (cons (cons (gx#datum->syntax '#f 'fxmodulo)
                                              (cons (gx#datum->syntax '#f 'h)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'entries)
                                                          '())))
                                        (cons '1 '())))
                            '()))
                '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                (cons (cons (gx#datum->syntax '#f 'let)
                                            (cons (gx#datum->syntax '#f 'loop)
                                                  (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'probe)
                            (cons (gx#datum->syntax '#f 'start) '()))
                      (cons (cons (gx#datum->syntax '#f 'i) (cons '1 '()))
                            (cons (cons (gx#datum->syntax '#f 'deleted)
                                        (cons '#f '()))
                                  '())))
                (cons (cons (gx#datum->syntax '#f 'let)
                            (cons (cons (gx#datum->syntax '#f 'k)
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'vector-ref)
                                                    (cons _%$%hd124138124190%_
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'probe)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))
                                  (cons (cons (gx#datum->syntax '#f 'cond)
                                              (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'eq?)
                        (cons (gx#datum->syntax '#f 'k)
                              (cons (cons (gx#datum->syntax
                                           '#f
                                           'macro-unused-obj)
                                          '())
                                    '())))
                  (cons (cons (gx#datum->syntax '#f 'if)
                              (cons (gx#datum->syntax '#f 'deleted)
                                    (cons (cons (gx#datum->syntax '#f 'begin)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'vector-set!)
                                                            (cons _%$%hd124138124190%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons (gx#datum->syntax '#f 'deleted)
                                (cons _%$%hd124150124230%_ '()))))
              (cons (cons (gx#datum->syntax '#f 'vector-set!)
                          (cons _%$%hd124138124190%_
                                (cons (cons (gx#datum->syntax '#f 'fx+)
                                            (cons (gx#datum->syntax
                                                   '#f
                                                   'deleted)
                                                  (cons '1 '())))
                                      (cons (cons _%$%hd124153124240%_
                                                  (cons _%$%hd124156124250%_
                                                        '()))
                                            '()))))
                    (cons (cons _%$%hd124162124270%_ '()) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       'begin)
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'vector-set!)
                          (cons _%$%hd124138124190%_
                                (cons (gx#datum->syntax '#f 'probe)
                                      (cons _%$%hd124150124230%_ '()))))
                    (cons (cons (gx#datum->syntax '#f 'vector-set!)
                                (cons _%$%hd124138124190%_
                                      (cons (cons (gx#datum->syntax '#f 'fx+)
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'probe)
                                                        (cons '1 '())))
                                            (cons (cons _%$%hd124153124240%_
                                                        (cons _%$%hd124156124250%_
                                                              '()))
                                                  '()))))
                          (cons (cons _%$%hd124159124260%_ '()) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '()))))
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'eq?)
                              (cons (gx#datum->syntax '#f 'k)
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'macro-deleted-obj)
                                                '())
                                          '())))
                        (cons (cons (gx#datum->syntax '#f 'loop)
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'probe-step)
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'start)
                                                      (cons (gx#datum->syntax
                                                             '#f
                                                             'i)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'size)
                          '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       'fx+)
                                                      (cons (gx#datum->syntax
                                                             '#f
                                                             'i)
                                                            (cons '1 '())))
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'or)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'deleted)
                          (cons (gx#datum->syntax '#f 'probe) '())))
              '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                              '()))
                  (cons (cons (cons _%$%hd124147124220%_
                                    (cons _%$%hd124150124230%_
                                          (cons (gx#datum->syntax '#f 'k)
                                                '())))
                              (cons (cons (gx#datum->syntax '#f 'vector-set!)
                                          (cons _%$%hd124138124190%_
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'probe)
                                                      (cons _%$%hd124150124230%_
                                                            '()))))
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'vector-set!)
                                                (cons _%$%hd124138124190%_
                                                      (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'fx+)
                          (cons (gx#datum->syntax '#f 'probe) (cons '1 '())))
                    (cons (cons _%$%hd124153124240%_
                                (cons (cons (gx#datum->syntax '#f 'vector-ref)
                                            (cons _%$%hd124138124190%_
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'fx+)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'probe)
                            (cons '1 '())))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '()))
                          '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          '())))
                        (cons (cons (gx#datum->syntax '#f 'else)
                                    (cons (cons (gx#datum->syntax '#f 'loop)
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'probe-step)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'start)
                          (cons (gx#datum->syntax '#f 'i)
                                (cons (gx#datum->syntax '#f 'size) '()))))
              (cons (cons (gx#datum->syntax '#f 'fx+)
                          (cons (gx#datum->syntax '#f 'i) (cons '1 '())))
                    (cons (gx#datum->syntax '#f 'deleted) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          '()))
                              '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        '())))
                      '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '())))
                    (_%$%g124123124169%_ _%$%g124124124173%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g124123124169%_
                                                     _%$%g124124124173%_))))
                                            (_%$%g124123124169%_
                                             _%$%g124124124173%_))))
                                    (_%$%g124123124169%_
                                     _%$%g124124124173%_))))
                            (_%$%g124123124169%_ _%$%g124124124173%_))))
                    (_%$%g124123124169%_ _%$%g124124124173%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g124123124169%_
                                                     _%$%g124124124173%_))))
                                            (_%$%g124123124169%_
                                             _%$%g124124124173%_))))
                                    (_%$%g124123124169%_
                                     _%$%g124124124173%_))))
                            (_%$%g124123124169%_ _%$%g124124124173%_))))
                    (_%$%g124123124169%_ _%$%g124124124173%_)))))
        (_%$%g124122124322%_ _%$stx124119%_))))
  (define |[:0:]#__table-del!|
    (lambda (_%$stx124326%_)
      (let* ((_%$%g124330124364%_
              (lambda (_%$%g124331124360%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g124331124360%_)))
             (_%$%g124329124475%_
              (lambda (_%$%g124331124368%_)
                (if (gx#stx-pair? _%$%g124331124368%_)
                    (let ((_%$%e124338124371%_
                           (gx#syntax-e _%$%g124331124368%_)))
                      (let ((_%$%hd124339124375%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e124338124371%_)))
                            (_%$%tl124340124378%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e124338124371%_))))
                        (if (gx#stx-pair? _%$%tl124340124378%_)
                            (let ((_%$%e124341124381%_
                                   (gx#syntax-e _%$%tl124340124378%_)))
                              (let ((_%$%hd124342124385%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e124341124381%_)))
                                    (_%$%tl124343124388%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e124341124381%_))))
                                (if (gx#stx-pair? _%$%tl124343124388%_)
                                    (let ((_%$%e124344124391%_
                                           (gx#syntax-e _%$%tl124343124388%_)))
                                      (let ((_%$%hd124345124395%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e124344124391%_)))
                                            (_%$%tl124346124398%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e124344124391%_))))
                                        (if (gx#stx-pair? _%$%tl124346124398%_)
                                            (let ((_%$%e124347124401%_
                                                   (gx#syntax-e
                                                    _%$%tl124346124398%_)))
                                              (let ((_%$%hd124348124405%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e124347124401%_)))
                                                    (_%$%tl124349124408%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e124347124401%_))))
                                                (if (gx#stx-pair?
                                                     _%$%tl124349124408%_)
                                                    (let ((_%$%e124350124411%_
                                                           (gx#syntax-e
                                                            _%$%tl124349124408%_)))
                                                      (let ((_%$%hd124351124415%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e124350124411%_)))
                    (_%$%tl124352124418%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e124350124411%_))))
                (if (gx#stx-pair? _%$%tl124352124418%_)
                    (let ((_%$%e124353124421%_
                           (gx#syntax-e _%$%tl124352124418%_)))
                      (let ((_%$%hd124354124425%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e124353124421%_)))
                            (_%$%tl124355124428%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e124353124421%_))))
                        (if (gx#stx-pair? _%$%tl124355124428%_)
                            (let ((_%$%e124356124431%_
                                   (gx#syntax-e _%$%tl124355124428%_)))
                              (let ((_%$%hd124357124435%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e124356124431%_)))
                                    (_%$%tl124358124438%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e124356124431%_))))
                                (if (gx#stx-null? _%$%tl124358124438%_)
                                    (cons (gx#datum->syntax '#f 'let*)
                                          (cons (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'h)
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'fxxor)
                                (cons (cons _%$%hd124348124405%_
                                            (cons _%$%hd124354124425%_ '()))
                                      (cons _%$%hd124345124395%_ '())))
                          '()))
              (cons (cons (gx#datum->syntax '#f 'size)
                          (cons (cons (gx#datum->syntax '#f 'vector-length)
                                      (cons _%$%hd124342124385%_ '()))
                                '()))
                    (cons (cons (gx#datum->syntax '#f 'entries)
                                (cons (cons (gx#datum->syntax '#f 'fxquotient)
                                            (cons (gx#datum->syntax '#f 'size)
                                                  (cons '2 '())))
                                      '()))
                          (cons (cons (gx#datum->syntax '#f 'start)
                                      (cons (cons (gx#datum->syntax
                                                   '#f
                                                   'fxarithmetic-shift-left)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'fxmodulo)
                                                              (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'h)
                            (cons (gx#datum->syntax '#f 'entries) '())))
                (cons '1 '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '()))
                                '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'let)
                                                            (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '#f
                           'loop)
                          (cons (cons (cons (gx#datum->syntax '#f 'probe)
                                            (cons (gx#datum->syntax '#f 'start)
                                                  '()))
                                      (cons (cons (gx#datum->syntax '#f 'i)
                                                  (cons '1 '()))
                                            '()))
                                (cons (cons (gx#datum->syntax '#f 'let)
                                            (cons (cons (gx#datum->syntax
                                                         '#f
                                                         'k)
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'vector-ref)
                            (cons _%$%hd124342124385%_
                                  (cons (gx#datum->syntax '#f 'probe) '())))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'cond)
                                                              (cons (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                         '#f
                                         'eq?)
                                        (cons (gx#datum->syntax '#f 'k)
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'macro-unused-obj)
                                                          '())
                                                    '())))
                                  (cons (cons (gx#datum->syntax '#f 'void) '())
                                        '()))
                            (cons (cons (cons (gx#datum->syntax '#f 'eq?)
                                              (cons (gx#datum->syntax '#f 'k)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'macro-deleted-obj)
                        '())
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'loop)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'probe-step)
                        (cons (gx#datum->syntax '#f 'start)
                              (cons (gx#datum->syntax '#f 'i)
                                    (cons (gx#datum->syntax '#f 'size) '()))))
                  (cons (cons (gx#datum->syntax '#f 'fx+)
                              (cons (gx#datum->syntax '#f 'i) (cons '1 '())))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))
                                  (cons (cons (cons _%$%hd124351124415%_
                                                    (cons _%$%hd124354124425%_
                                                          (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'k)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (cons (cons (gx#datum->syntax
                                                           '#f
                                                           'vector-set!)
                                                          (cons _%$%hd124342124385%_
                                                                (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '#f
                               'probe)
                              (cons (cons (gx#datum->syntax
                                           '#f
                                           'macro-deleted-obj)
                                          '())
                                    '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'vector-set!)
                        (cons _%$%hd124342124385%_
                              (cons (cons (gx#datum->syntax '#f 'fx+)
                                          (cons (gx#datum->syntax '#f 'probe)
                                                (cons '1 '())))
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'macro-absent-obj)
                                                '())
                                          '()))))
                  (cons (cons _%$%hd124357124435%_ '()) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'else)
                                                    (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         'loop)
                        (cons (cons (gx#datum->syntax '#f 'probe-step)
                                    (cons (gx#datum->syntax '#f 'start)
                                          (cons (gx#datum->syntax '#f 'i)
                                                (cons (gx#datum->syntax
                                                       '#f
                                                       'size)
                                                      '()))))
                              (cons (cons (gx#datum->syntax '#f 'fx+)
                                          (cons (gx#datum->syntax '#f 'i)
                                                (cons '1 '())))
                                    '())))
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '()))))
              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%g124330124364%_
                                     _%$%g124331124368%_))))
                            (_%$%g124330124364%_ _%$%g124331124368%_))))
                    (_%$%g124330124364%_ _%$%g124331124368%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g124330124364%_
                                                     _%$%g124331124368%_))))
                                            (_%$%g124330124364%_
                                             _%$%g124331124368%_))))
                                    (_%$%g124330124364%_
                                     _%$%g124331124368%_))))
                            (_%$%g124330124364%_ _%$%g124331124368%_))))
                    (_%$%g124330124364%_ _%$%g124331124368%_)))))
        (_%$%g124329124475%_ _%$stx124326%_))))
  (define |[:0:]#do-gc-table-lock|
    (lambda (_%$stx124479%_)
      (let* ((_%$%g124483124501%_
              (lambda (_%$%g124484124497%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g124484124497%_)))
             (_%$%g124482124556%_
              (lambda (_%$%g124484124505%_)
                (if (gx#stx-pair? _%$%g124484124505%_)
                    (let ((_%$%e124487124508%_
                           (gx#syntax-e _%$%g124484124505%_)))
                      (let ((_%$%hd124488124512%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e124487124508%_)))
                            (_%$%tl124489124515%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e124487124508%_))))
                        (if (gx#stx-pair? _%$%tl124489124515%_)
                            (let ((_%$%e124490124518%_
                                   (gx#syntax-e _%$%tl124489124515%_)))
                              (let ((_%$%hd124491124522%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e124490124518%_)))
                                    (_%$%tl124492124525%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e124490124518%_))))
                                (if (gx#stx-pair? _%$%tl124492124525%_)
                                    (let ((_%$%e124493124528%_
                                           (gx#syntax-e _%$%tl124492124525%_)))
                                      (let ((_%$%hd124494124532%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e124493124528%_)))
                                            (_%$%tl124495124535%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e124493124528%_))))
                                        (if (gx#stx-null? _%$%tl124495124535%_)
                                            (cons (gx#datum->syntax
                                                   '#f
                                                   '__do-inline-lock!)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               '&gc-table-lock)
                                                              (cons _%$%hd124491124522%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                (cons _%$%hd124494124532%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g124483124501%_
                                             _%$%g124484124505%_))))
                                    (_%$%g124483124501%_
                                     _%$%g124484124505%_))))
                            (_%$%g124483124501%_ _%$%g124484124505%_))))
                    (_%$%g124483124501%_ _%$%g124484124505%_)))))
        (_%$%g124482124556%_ _%$stx124479%_)))))
