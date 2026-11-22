(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gerbil/core/contract~ContractRules[:0:]#maybe|
    (lambda (_%$stx62962%_)
      (let* ((_%$%g6296662980%_
              (lambda (_%$%g6296762976%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6296762976%_)))
             (_%$%g6296563022%_
              (lambda (_%$%g6296762984%_)
                (if (gx#stx-pair? _%$%g6296762984%_)
                    (let ((_%$%e6296962987%_ (gx#syntax-e _%$%g6296762984%_)))
                      (let ((_%$%hd6297062991%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6296962987%_)))
                            (_%$%tl6297162994%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6296962987%_))))
                        (if (gx#stx-pair? _%$%tl6297162994%_)
                            (let ((_%$%e6297262997%_
                                   (gx#syntax-e _%$%tl6297162994%_)))
                              (let ((_%$%hd6297363001%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6297262997%_)))
                                    (_%$%tl6297463004%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6297262997%_))))
                                (if (gx#stx-null? _%$%tl6297463004%_)
                                    (cons (gx#datum->syntax '#f '?)
                                          (cons (cons (gx#datum->syntax
                                                       '#f
                                                       'or)
                                                      (cons (gx#datum->syntax
                                                             '#f
                                                             'not)
                                                            (cons _%$%hd6297363001%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '()))
                                    (_%$%g6296662980%_ _%$%g6296762984%_))))
                            (_%$%g6296662980%_ _%$%g6296762984%_))))
                    (_%$%g6296662980%_ _%$%g6296762984%_)))))
        (_%$%g6296563022%_ _%$stx62962%_))))
  (define |gerbil/core/contract~ContractRules[:0:]#in-range?|
    (lambda (_%$stx63026%_)
      (let* ((_%$%g6303063048%_
              (lambda (_%$%g6303163044%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6303163044%_)))
             (_%$%g6302963103%_
              (lambda (_%$%g6303163052%_)
                (if (gx#stx-pair? _%$%g6303163052%_)
                    (let ((_%$%e6303463055%_ (gx#syntax-e _%$%g6303163052%_)))
                      (let ((_%$%hd6303563059%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6303463055%_)))
                            (_%$%tl6303663062%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6303463055%_))))
                        (if (gx#stx-pair? _%$%tl6303663062%_)
                            (let ((_%$%e6303763065%_
                                   (gx#syntax-e _%$%tl6303663062%_)))
                              (let ((_%$%hd6303863069%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6303763065%_)))
                                    (_%$%tl6303963072%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6303763065%_))))
                                (if (gx#stx-pair? _%$%tl6303963072%_)
                                    (let ((_%$%e6304063075%_
                                           (gx#syntax-e _%$%tl6303963072%_)))
                                      (let ((_%$%hd6304163079%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e6304063075%_)))
                                            (_%$%tl6304263082%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e6304063075%_))))
                                        (if (gx#stx-null? _%$%tl6304263082%_)
                                            (cons (gx#datum->syntax
                                                   '#f
                                                   'lambda)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'o)
                                                              '())
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'and)
                            (cons (cons (gx#datum->syntax '#f 'fixnum?)
                                        (cons (gx#datum->syntax '#f 'o) '()))
                                  (cons (cons (gx#datum->syntax '#f 'fx>=)
                                              (cons (gx#datum->syntax '#f 'o)
                                                    (cons _%$%hd6303863069%_
                                                          '())))
                                        (cons (cons (gx#datum->syntax '#f 'fx<)
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'o)
                                                          (cons _%$%hd6304163079%_
                                                                '())))
                                              '()))))
                      '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g6303063048%_
                                             _%$%g6303163052%_))))
                                    (_%$%g6303063048%_ _%$%g6303163052%_))))
                            (_%$%g6303063048%_ _%$%g6303163052%_))))
                    (_%$%g6303063048%_ _%$%g6303163052%_)))))
        (_%$%g6302963103%_ _%$stx63026%_))))
  (define |gerbil/core/contract~ContractRules[:0:]#in-range-inclusive?|
    (lambda (_%$stx63107%_)
      (let* ((_%$%g6311163129%_
              (lambda (_%$%g6311263125%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6311263125%_)))
             (_%$%g6311063184%_
              (lambda (_%$%g6311263133%_)
                (if (gx#stx-pair? _%$%g6311263133%_)
                    (let ((_%$%e6311563136%_ (gx#syntax-e _%$%g6311263133%_)))
                      (let ((_%$%hd6311663140%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6311563136%_)))
                            (_%$%tl6311763143%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6311563136%_))))
                        (if (gx#stx-pair? _%$%tl6311763143%_)
                            (let ((_%$%e6311863146%_
                                   (gx#syntax-e _%$%tl6311763143%_)))
                              (let ((_%$%hd6311963150%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6311863146%_)))
                                    (_%$%tl6312063153%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6311863146%_))))
                                (if (gx#stx-pair? _%$%tl6312063153%_)
                                    (let ((_%$%e6312163156%_
                                           (gx#syntax-e _%$%tl6312063153%_)))
                                      (let ((_%$%hd6312263160%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e6312163156%_)))
                                            (_%$%tl6312363163%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e6312163156%_))))
                                        (if (gx#stx-null? _%$%tl6312363163%_)
                                            (cons (gx#datum->syntax
                                                   '#f
                                                   'lambda)
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'o)
                                                              '())
                                                        (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '#f
                             'and)
                            (cons (cons (gx#datum->syntax '#f 'fixnum?)
                                        (cons (gx#datum->syntax '#f 'o) '()))
                                  (cons (cons (gx#datum->syntax '#f 'fx<=)
                                              (cons _%$%hd6311963150%_
                                                    (cons (gx#datum->syntax
                                                           '#f
                                                           'o)
                                                          (cons _%$%hd6312263160%_
                                                                '()))))
                                        '())))
                      '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g6311163129%_
                                             _%$%g6311263133%_))))
                                    (_%$%g6311163129%_ _%$%g6311263133%_))))
                            (_%$%g6311163129%_ _%$%g6311263133%_))))
                    (_%$%g6311163129%_ _%$%g6311263133%_)))))
        (_%$%g6311063184%_ _%$stx63107%_))))
  (define |gerbil/core/contract~ContractRules[:0:]#list-of?|
    (lambda (_%$stx63188%_)
      (let* ((_%$%g6319263206%_
              (lambda (_%$%g6319363202%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6319363202%_)))
             (_%$%g6319163247%_
              (lambda (_%$%g6319363210%_)
                (if (gx#stx-pair? _%$%g6319363210%_)
                    (let ((_%$%e6319563213%_ (gx#syntax-e _%$%g6319363210%_)))
                      (let ((_%$%hd6319663217%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6319563213%_)))
                            (_%$%tl6319763220%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6319563213%_))))
                        (if (gx#stx-pair? _%$%tl6319763220%_)
                            (let ((_%$%e6319863223%_
                                   (gx#syntax-e _%$%tl6319763220%_)))
                              (let ((_%$%hd6319963227%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e6319863223%_)))
                                    (_%$%tl6320063230%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e6319863223%_))))
                                (if (gx#stx-null? _%$%tl6320063230%_)
                                    (cons (gx#datum->syntax '#f 'lambda)
                                          (cons (cons (gx#datum->syntax '#f 'o)
                                                      '())
                                                (cons (cons (gx#datum->syntax
                                                             '#f
                                                             'and)
                                                            (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '#f
                                 'list?)
                                (cons (gx#datum->syntax '#f 'o) '()))
                          (cons (cons (gx#datum->syntax '#f 'andmap)
                                      (cons _%$%hd6319963227%_
                                            (cons (gx#datum->syntax '#f 'o)
                                                  '())))
                                '())))
              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%g6319263206%_ _%$%g6319363210%_))))
                            (_%$%g6319263206%_ _%$%g6319363210%_))))
                    (_%$%g6319263206%_ _%$%g6319363210%_)))))
        (_%$%g6319163247%_ _%$stx63188%_))))
  (define |gerbil/core/contract~ContractRules[:0:]#one-of|
    (lambda (_%$stx63251%_)
      (let* ((_%$%g6325563275%_
              (lambda (_%$%g6325663271%_)
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g6325663271%_)))
             (_%$%g6325463344%_
              (lambda (_%$%g6325663279%_)
                (if (gx#stx-pair? _%$%g6325663279%_)
                    (let ((_%$%e6325863282%_ (gx#syntax-e _%$%g6325663279%_)))
                      (let ((_%$%hd6325963286%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e6325863282%_)))
                            (_%$%tl6326063289%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e6325863282%_))))
                        (if (gx#stx-pair/null? _%$%tl6326063289%_)
                            (let ((_g107462_
                                   (gx#syntax-split-splice
                                    _%$%tl6326063289%_
                                    '0)))
                              (begin
                                (let ((_g107463_
                                       (let ()
                                         (declare (not safe))
                                         (if (##values? _g107462_)
                                             (##values-length _g107462_)
                                             1))))
                                  (if (not (let ()
                                             (declare (not safe))
                                             (##fx= _g107463_ 2)))
                                      (error "Context expects 2 values"
                                             _g107463_)))
                                (let ((_%$%target6326163292%_
                                       (let ()
                                         (declare (not safe))
                                         (##values-ref _g107462_ 0)))
                                      (_%$%tl6326363295%_
                                       (let ()
                                         (declare (not safe))
                                         (##values-ref _g107462_ 1))))
                                  (if (gx#stx-null? _%$%tl6326363295%_)
                                      (letrec ((_%$%loop6326463298%_
                                                (lambda (_%$%hd6326263302%_
                                                         _%$%val6326863305%_)
                                                  (if (gx#stx-pair?
                                                       _%$%hd6326263302%_)
                                                      (let ((_%$%e6326563307%_
                                                             (gx#syntax-e
                                                              _%$%hd6326263302%_)))
                                                        (let ((_%$%lp-hd6326663311%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##car _%$%e6326563307%_)))
                      (_%$%lp-tl6326763314%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e6326563307%_))))
                  (_%$%loop6326463298%_
                   _%$%lp-tl6326763314%_
                   (cons _%$%lp-hd6326663311%_ _%$%val6326863305%_))))
              (let ((_%$%val6326963317%_ (reverse _%$%val6326863305%_)))
                (cons (gx#datum->syntax '#f 'lambda)
                      (cons (cons (gx#datum->syntax '#f 'o) '())
                            (cons (cons (gx#datum->syntax '#f 'or)
                                        (foldr (lambda (_%$%g6333563338%_
                                                        _%$%g6333663341%_)
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'eq?)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'o)
                           (cons (cons (gx#datum->syntax '#f 'quasiquote)
                                       (cons _%$%g6333563338%_ '()))
                                 '())))
               _%$%g6333663341%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               '()
                                               _%$%val6326963317%_))
                                  '()))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (_%$%loop6326463298%_
                                         _%$%target6326163292%_
                                         '()))
                                      (_%$%g6325563275%_ _%$%g6325663279%_)))))
                            (_%$%g6325563275%_ _%$%g6325663279%_))))
                    (_%$%g6325563275%_ _%$%g6325663279%_)))))
        (_%$%g6325463344%_ _%$stx63251%_)))))
