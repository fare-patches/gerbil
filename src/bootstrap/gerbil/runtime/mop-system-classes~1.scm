(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |[1]#_g149504_|
    (##structure gx#syntax-quote::t ':- #f (gx#current-expander-context) '()))
  (begin
    (define |[:0:]#defpred|
      (lambda (_%stx148987%_)
        (let* ((_%$%g148990149028%_
                (lambda (_%$%g148991149024%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g148991149024%_)))
               (_%$%g148989149195%_
                (lambda (_%$%g148991149032%_)
                  (if (gx#stx-pair? _%$%g148991149032%_)
                      (let ((_%$%e148996149035%_
                             (gx#syntax-e _%$%g148991149032%_)))
                        (let ((_%$%hd148997149039%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e148996149035%_)))
                              (_%$%tl148998149042%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e148996149035%_))))
                          (if (gx#stx-pair? _%$%tl148998149042%_)
                              (let ((_%$%e148999149045%_
                                     (gx#syntax-e _%$%tl148998149042%_)))
                                (let ((_%$%hd149000149049%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e148999149045%_)))
                                      (_%$%tl149001149052%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e148999149045%_))))
                                  (if (gx#stx-pair? _%$%hd149000149049%_)
                                      (let ((_%$%e149002149055%_
                                             (gx#syntax-e
                                              _%$%hd149000149049%_)))
                                        (let ((_%$%hd149003149059%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e149002149055%_)))
                                              (_%$%tl149004149062%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e149002149055%_))))
                                          (if (gx#stx-pair?
                                               _%$%tl149004149062%_)
                                              (let ((_%$%e149005149065%_
                                                     (gx#syntax-e
                                                      _%$%tl149004149062%_)))
                                                (let ((_%$%hd149006149069%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e149005149065%_)))
                                                      (_%$%tl149007149072%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e149005149065%_))))
                                                  (if (gx#stx-null?
                                                       _%$%tl149007149072%_)
                                                      (if (gx#stx-pair?
                                                           _%$%tl149001149052%_)
                                                          (let ((_%$%e149008149075%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl149001149052%_)))
                    (let ((_%$%hd149009149079%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e149008149075%_)))
                          (_%$%tl149010149082%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e149008149075%_))))
                      (if (gx#identifier? _%$%hd149009149079%_)
                          (if (gx#free-identifier=?
                               |[1]#_g149504_|
                               _%$%hd149009149079%_)
                              (if (gx#stx-pair? _%$%tl149010149082%_)
                                  (let ((_%$%e149011149085%_
                                         (gx#syntax-e _%$%tl149010149082%_)))
                                    (let ((_%$%hd149012149089%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e149011149085%_)))
                                          (_%$%tl149013149092%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e149011149085%_))))
                                      (if (gx#stx-pair/null?
                                           _%$%tl149013149092%_)
                                          (let ((_g149505_
                                                 (gx#syntax-split-splice
                                                  _%$%tl149013149092%_
                                                  '0)))
                                            (begin
                                              (let ((_g149506_
                                                     (let ()
                                                       (declare (not safe))
                                                       (if (##values?
                                                            _g149505_)
                                                           (##values-length
                                                            _g149505_)
                                                           1))))
                                                (if (not (let ()
                                                           (declare (not safe))
                                                           (##fx= _g149506_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          2)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (error "Context expects 2 values"
                                                           _g149506_)))
                                              (let ((_%$%target149014149095%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##values-ref
                                                        _g149505_
                                                        0)))
                                                    (_%$%tl149016149098%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##values-ref
                                                        _g149505_
                                                        1))))
                                                (if (gx#stx-null?
                                                     _%$%tl149016149098%_)
                                                    (letrec ((_%$%loop149017149101%_
                                                              (lambda (_%$%hd149015149105%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               _%$%body149021149108%_)
                        (if (gx#stx-pair? _%$%hd149015149105%_)
                            (let ((_%$%e149018149110%_
                                   (gx#syntax-e _%$%hd149015149105%_)))
                              (let ((_%$%lp-hd149019149114%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e149018149110%_)))
                                    (_%$%lp-tl149020149117%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e149018149110%_))))
                                (_%$%loop149017149101%_
                                 _%$%lp-tl149020149117%_
                                 (cons _%$%lp-hd149019149114%_
                                       _%$%body149021149108%_))))
                            (let* ((_%$%body149022149120%_
                                    (reverse _%$%body149021149108%_))
                                   (_%$%g149156149164%_
                                    (lambda (_%$%g149157149160%_)
                                      (gx#raise-syntax-error
                                       '#f
                                       '"Bad syntax; invalid match target"
                                       _%$%g149157149160%_)))
                                   (_%$%g149155149191%_
                                    (lambda (_%$%g149157149168%_)
                                      (cons (gx#datum->syntax '#f 'def)
                                            (cons _%$%hd149003149059%_
                                                  (cons (cons (gx#datum->syntax
                                                               '#f
                                                               'begin-annotation)
                                                              (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '#f
                                   '@predicate)
                                  (cons _%$%g149157149168%_ '()))
                            (cons (cons (gx#datum->syntax '#f 'lambda)
                                        (cons (cons _%$%hd149006149069%_ '())
                                              (let ((__tmp149507
                                                     (lambda (_%$%g149182149185%_
                                                              _%$%g149183149188%_)
                                                       (cons _%$%g149182149185%_
                                                             _%$%g149183149188%_))))
                                                (declare (not safe))
                                                (foldr__0
                                                 __tmp149507
                                                 '()
                                                 _%$%body149022149120%_))))
                                  '())))
                '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                              (_%$%g149155149191%_
                               (let ()
                                 (declare (not safe))
                                 (|gerbil/core/contract~TypeReference[1]#resolve-type->type-descriptor|
                                  _%stx148987%_
                                  _%$%hd149012149089%_))))))))
              (_%$%loop149017149101%_ _%$%target149014149095%_ '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g148990149028%_
                                                     _%$%g148991149032%_)))))
                                          (_%$%g148990149028%_
                                           _%$%g148991149032%_))))
                                  (_%$%g148990149028%_ _%$%g148991149032%_))
                              (_%$%g148990149028%_ _%$%g148991149032%_))
                          (_%$%g148990149028%_ _%$%g148991149032%_))))
                  (_%$%g148990149028%_ _%$%g148991149032%_))
              (_%$%g148990149028%_ _%$%g148991149032%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g148990149028%_
                                               _%$%g148991149032%_))))
                                      (_%$%g148990149028%_
                                       _%$%g148991149032%_))))
                              (_%$%g148990149028%_ _%$%g148991149032%_))))
                      (_%$%g148990149028%_ _%$%g148991149032%_)))))
          (_%$%g148989149195%_ _%stx148987%_))))
    (define |[:0:]#subtype-property-vector|
      (lambda (_%$stx149200%_)
        (let* ((_%$%g149204149224%_
                (lambda (_%$%g149205149220%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g149205149220%_)))
               (_%$%g149203149293%_
                (lambda (_%$%g149205149228%_)
                  (if (gx#stx-pair? _%$%g149205149228%_)
                      (let ((_%$%e149207149231%_
                             (gx#syntax-e _%$%g149205149228%_)))
                        (let ((_%$%hd149208149235%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e149207149231%_)))
                              (_%$%tl149209149238%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e149207149231%_))))
                          (if (gx#stx-pair/null? _%$%tl149209149238%_)
                              (let ((_g149508_
                                     (gx#syntax-split-splice
                                      _%$%tl149209149238%_
                                      '0)))
                                (begin
                                  (let ((_g149509_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g149508_)
                                               (##values-length _g149508_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g149509_ 2)))
                                        (error "Context expects 2 values"
                                               _g149509_)))
                                  (let ((_%$%target149210149241%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g149508_ 0)))
                                        (_%$%tl149212149244%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g149508_ 1))))
                                    (if (gx#stx-null? _%$%tl149212149244%_)
                                        (letrec ((_%$%loop149213149247%_
                                                  (lambda (_%$%hd149211149251%_
                                                           _%$%t149217149254%_)
                                                    (if (gx#stx-pair?
                                                         _%$%hd149211149251%_)
                                                        (let ((_%$%e149214149256%_
                                                               (gx#syntax-e
                                                                _%$%hd149211149251%_)))
                                                          (let ((_%$%lp-hd149215149260%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##car _%$%e149214149256%_)))
                        (_%$%lp-tl149216149263%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e149214149256%_))))
                    (_%$%loop149213149247%_
                     _%$%lp-tl149216149263%_
                     (cons _%$%lp-hd149215149260%_ _%$%t149217149254%_))))
                (let ((_%$%t149218149266%_ (reverse _%$%t149217149254%_)))
                  (cons (gx#datum->syntax '#f 'let)
                        (cons (cons (gx#datum->syntax '#f 'vec)
                                    (cons (cons (gx#datum->syntax
                                                 '#f
                                                 'make-vector)
                                                (cons '32 (cons '#f '())))
                                          '()))
                              (let ((__tmp149511
                                     (lambda (_%$%g149284149287%_
                                              _%$%g149285149290%_)
                                       (cons (cons (gx#datum->syntax
                                                    '#f
                                                    'vector-set!)
                                                   (cons (gx#datum->syntax
                                                          '#f
                                                          'vec)
                                                         (cons _%$%g149284149287%_
                                                               (cons '#t
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             _%$%g149285149290%_)))
                                    (__tmp149510
                                     (cons (gx#datum->syntax '#f 'vec) '())))
                                (declare (not safe))
                                (foldr__0
                                 __tmp149511
                                 __tmp149510
                                 _%$%t149218149266%_)))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop149213149247%_
                                           _%$%target149210149241%_
                                           '()))
                                        (_%$%g149204149224%_
                                         _%$%g149205149228%_)))))
                              (_%$%g149204149224%_ _%$%g149205149228%_))))
                      (_%$%g149204149224%_ _%$%g149205149228%_)))))
          (_%$%g149203149293%_ _%$stx149200%_))))))
