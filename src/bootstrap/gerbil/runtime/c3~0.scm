(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/c3::timestamp 1795039813)
  (begin
    (define c4-linearize__%
      (lambda (_%@@keywords130157%_
               _%$%get-precedence-list130151130158%_
               _%$%struct?130152130159%_
               _%$%eq130153130160%_
               _%$%get-name130154130161%_
               _%rhead130162%_
               _%supers130163%_)
        (let* ((_%get-precedence-list130165%_
                (if (eq? _%$%get-precedence-list130151130158%_ absent-value)
                    (error '"Missing required keyword argument"
                           'get-precedence-list:)
                    _%$%get-precedence-list130151130158%_))
               (_%struct?130169%_
                (if (eq? _%$%struct?130152130159%_ absent-value)
                    (lambda (_%_130167%_) '#f)
                    _%$%struct?130152130159%_))
               (_%eq130171%_
                (if (eq? _%$%eq130153130160%_ absent-value)
                    eq?
                    _%$%eq130153130160%_))
               (_%get-name130173%_
                (if (eq? _%$%get-name130154130161%_ absent-value)
                    identity
                    _%$%get-name130154130161%_)))
          (c4-linearize*__%
           '#f
           _%get-precedence-list130165%_
           _%struct?130169%_
           absent-value
           _%eq130171%_
           _%get-name130173%_
           (reverse _%rhead130162%_)
           (list _%supers130163%_)))))
    (define c4-linearize__@
      (lambda (_%@@keywords130179%_ . _%args130180%_)
        (apply c4-linearize__%
               _%@@keywords130179%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130179%_
                  'get-precedence-list:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130179%_
                  'struct:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords130179%_ 'eq: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130179%_
                  'get-name:
                  absent-value))
               _%args130180%_)))
    (define c4-linearize
      (lambda _%$%args130155130186%_
        (apply keyword-dispatch
               '#(#f get-name: struct: get-precedence-list: #f eq:)
               c4-linearize__@
               _%$%args130155130186%_)))
    (define c4-linearize*__%
      (lambda (_%@@keywords129411%_
               _%$%get-precedence-list129404129412%_
               _%$%suffix?129405129413%_
               _%$%super-suffix129406129414%_
               _%$%eq129407129415%_
               _%$%get-name129408129416%_
               _%head129417%_
               _%parents129418%_)
        (let* ((_%get-precedence-list129420%_
                (if (eq? _%$%get-precedence-list129404129412%_ absent-value)
                    (error '"Missing required keyword argument"
                           'get-precedence-list:)
                    _%$%get-precedence-list129404129412%_))
               (_%suffix?129422%_
                (if (eq? _%$%suffix?129405129413%_ absent-value)
                    (error '"Missing required keyword argument" 'suffix:)
                    _%$%suffix?129405129413%_))
               (_%super-suffix129449%_
                (if (eq? _%$%super-suffix129406129414%_ absent-value)
                    (lambda (_%x129424%_)
                      (let* ((_%pred129426%_ _%suffix?129422%_)
                             (_%lst129429%_
                              (cdr (_%get-precedence-list129420%_
                                    _%x129424%_))))
                        (if (procedure? _%pred129426%_)
                            (let ((_%pred129434%_ _%pred129426%_))
                              (declare (not safe))
                              (__find _%pred129434%_ _%lst129429%_))
                            (begin
                              (raise-contract-violation-error
                               '"contract violation"
                               'context:
                               'gerbil/runtime/c3
                               'contract:
                               'procedure?
                               'value:
                               _%pred129426%_)
                              '#!void))))
                    _%$%super-suffix129406129414%_))
               (_%eq129451%_
                (if (eq? _%$%eq129407129415%_ absent-value)
                    eq?
                    _%$%eq129407129415%_))
               (_%get-name129453%_
                (if (eq? _%$%get-name129408129416%_ absent-value)
                    identity
                    _%$%get-name129408129416%_)))
          (set! _%parents129418%_
                (let ()
                  (declare (not safe))
                  (remove-nulls! _%parents129418%_)))
          (if (null? _%parents129418%_)
              (values _%head129417%_ '#f)
              (if (and (null? (cdr _%parents129418%_))
                       (null? (cdar _%parents129418%_)))
                  (let* ((_%parent129458%_ (caar _%parents129418%_))
                         (_%pl129460%_
                          (_%get-precedence-list129420%_ _%parent129458%_)))
                    (values (append _%head129417%_ _%pl129460%_)
                            (if (_%suffix?129422%_ _%parent129458%_)
                                _%parent129458%_
                                (_%super-suffix129449%_ _%parent129458%_))))
                  (let ((_%rcandidates129464%_ '())
                        (_%suffix129465%_ '#f)
                        (_%suffix-tail129466%_ '()))
                    (letrec* ((_g130262_
                               (let ((_g130263_
                                      (if (eq? _%eq129451%_ eq?)
                                          (values (lambda ()
                                                    (make-table 'test: eq?))
                                                  table-ref
                                                  table-set!
                                                  table-set!
                                                  table->list)
                                          (if (eq? _%eq129451%_ eqv?)
                                              (values (lambda ()
                                                        (make-table
                                                         'test:
                                                         eqv?))
                                                      table-ref
                                                      table-set!
                                                      table-set!
                                                      table->list)
                                              (if (eq? _%eq129451%_ equal?)
                                                  (values (lambda ()
                                                            (make-table
                                                             'test:
                                                             equal?))
                                                          table-ref
                                                          table-set!
                                                          table-set!
                                                          table->list)
                                                  (values (lambda ()
                                                            (letrec* ((_%this130069%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (cons '#f '())))
                      (let ()
                        (declare (not safe))
                        (##set-car! _%this130069%_ _%this130069%_))
                      _%this130069%_))
                  (lambda (_%tab130071%_ _%key130072%_ _%default130073%_)
                    (let ((_%$e130075%_
                           (assoc _%key130072%_
                                  (cdr _%tab130071%_)
                                  _%eq129451%_)))
                      (if _%$e130075%_ (cdr _%$e130075%_) _%default130073%_)))
                  (lambda (_%tab130079%_ _%key130080%_ _%value130081%_)
                    (let ((_%$e130083%_
                           (assoc _%key130080%_
                                  (cdr _%tab130079%_)
                                  _%eq129451%_)))
                      (if _%$e130083%_
                          (set-cdr! _%$e130083%_ _%value130081%_)
                          (let ((_%tail130089%_
                                 (cons (cons _%key130080%_ _%value130081%_)
                                       '())))
                            (set-cdr! (car _%tab130079%_) _%tail130089%_)
                            (set-car! _%tab130079%_ _%tail130089%_)))))
                  (lambda (_%tab130091%_ _%key130092%_)
                    (let _%lp130094%_ ((_%prev130096%_ _%tab130091%_)
                                       (_%rest130097%_ (cdr _%tab130091%_)))
                      (let* ((_%$%rest130098130107%_ _%rest130097%_)
                             (_%$%E130101130111%_
                              (lambda ()
                                (error '"No clause matching"
                                       _%$%rest130098130107%_
                                       '([])
                                       '([entry . tail]))
                                '#!void)))
                        (let ((_%$%K130105130134%_ (lambda () '#!void))
                              (_%$%K130102130118%_
                               (lambda (_%tail130115%_ _%entry130116%_)
                                 (if (_%eq129451%_
                                      _%key130092%_
                                      (car _%entry130116%_))
                                     (begin
                                       (set-cdr! _%prev130096%_ _%tail130115%_)
                                       (if (null? _%tail130115%_)
                                           (set-car!
                                            _%tab130091%_
                                            _%prev130096%_)
                                           '#!void))
                                     (_%lp130094%_
                                      _%rest130097%_
                                      _%tail130115%_)))))
                          (let ((_%$%try-match130100130130%_
                                 (lambda ()
                                   (if (pair? _%$%rest130098130107%_)
                                       (let ((_%$%tl130104130123%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%rest130098130107%_)))
                                             (_%$%hd130103130121%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%rest130098130107%_))))
                                         (let ((_%entry130126%_
                                                _%$%hd130103130121%_)
                                               (_%tail130128%_
                                                _%$%tl130104130123%_))
                                           (_%$%K130102130118%_
                                            _%tail130128%_
                                            _%entry130126%_)))
                                       (_%$%E130101130111%_)))))
                            (if (null? _%$%rest130098130107%_)
                                '#!void
                                (_%$%try-match130100130130%_)))))))
                  cdr))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                 #!void
                                 _g130263_))
                              (_%make-tab129468%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g130262_ 0)))
                              (_%tab-ref129469%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g130262_ 1)))
                              (_%tab-set!129470%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g130262_ 2)))
                              (_%tab-remove!129471%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g130262_ 3)))
                              (_%tab->list129472%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g130262_ 4)))
                              (_%get-names129473%_
                               (lambda (_%lst130059%_)
                                 (map _%get-name129453%_ _%lst130059%_)))
                              (_%err129474%_
                               (lambda _%a130057%_
                                 (apply error
                                        '"Inconsistent precedence graph"
                                        'head:
                                        (_%get-names129473%_ _%head129417%_)
                                        'parents:
                                        (map _%get-names129473%_
                                             _%parents129418%_)
                                        'precedence-lists:
                                        (let ((__tmp130264
                                               (map _%get-precedence-list129420%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (foldl__0
                                                       append
                                                       '()
                                                       _%parents129418%_)))))
                                          (declare (not safe))
                                          (##map _%get-names129473%_
                                                 __tmp130264))
                                        'common-suffix-tail:
                                        (_%get-names129473%_
                                         _%suffix-tail129466%_)
                                        'rcandidates:
                                        (let ()
                                          (declare (not safe))
                                          (##map _%get-names129473%_
                                                 _%rcandidates129464%_))
                                        _%a130057%_)))
                              (_%super-suffix?129475%_
                               (lambda (_%s1130044%_ _%s2130045%_)
                                 (let ((_%$e130047%_ (not _%s2130045%_)))
                                   (if _%$e130047%_
                                       _%$e130047%_
                                       (let _%loop130050%_ ((_%s130052%_
                                                             _%s1130044%_))
                                         (if _%s130052%_
                                             (let ((_%$e130054%_
                                                    (_%eq129451%_
                                                     _%s130052%_
                                                     _%s2130045%_)))
                                               (if _%$e130054%_
                                                   _%$e130054%_
                                                   (_%loop130050%_
                                                    (_%super-suffix129449%_
                                                     _%s130052%_))))
                                             '#f))))))
                              (_%merge-suffix129476%_
                               (lambda (_%s1130028%_ _%s2130029%_)
                                 (if _%s2130029%_
                                     (if _%s1130028%_
                                         (let _%loop130034%_ ((_%t1130036%_
                                                               _%s1130028%_)
                                                              (_%t2130037%_
                                                               _%s2130029%_))
                                           (if _%t1130036%_
                                               (if _%t2130037%_
                                                   (if (_%eq129451%_
                                                        _%t1130036%_
                                                        _%s2130029%_)
                                                       _%s1130028%_
                                                       (if (_%eq129451%_
                                                            _%t2130037%_
                                                            _%s1130028%_)
                                                           _%s2130029%_
                                                           (_%loop130034%_
                                                            (_%super-suffix129449%_
                                                             _%t1130036%_)
                                                            (_%super-suffix129449%_
                                                             _%t2130037%_))))
                                                   (if (_%super-suffix?129475%_
                                                        _%t1130036%_
                                                        _%s2130029%_)
                                                       _%s1130028%_
                                                       (_%err129474%_
                                                        'suffix-incompatibility:
                                                        (cons (_%get-name129453%_
                                                               _%s1130028%_)
                                                              (cons (_%get-name129453%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%s2130029%_)
                            '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (if (_%super-suffix?129475%_
                                                    _%t2130037%_
                                                    _%s1130028%_)
                                                   _%s2130029%_
                                                   (_%err129474%_
                                                    'suffix-incompatibility:
                                                    (cons (_%get-name129453%_
                                                           _%s1130028%_)
                                                          (cons (_%get-name129453%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%s2130029%_)
                        '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         _%s2130029%_)
                                     _%s1130028%_)))
                              (_%ancestor-counts129477%_ (_%make-tab129468%_))
                              (_%get-ancestor-count129478%_
                               (lambda (_%c130026%_)
                                 (_%tab-ref129469%_
                                  _%ancestor-counts129477%_
                                  _%c130026%_
                                  '0)))
                              (_%increment-ancestor-count129479%_
                               (lambda (_%c130008%_)
                                 (_%tab-set!129470%_
                                  _%ancestor-counts129477%_
                                  _%c130008%_
                                  (let ((_%x130010%_
                                         (_%get-ancestor-count129478%_
                                          _%c130008%_)))
                                    (if (number? _%x130010%_)
                                        (let ((_%x130015%_ _%x130010%_))
                                          (declare (not safe))
                                          (__1+ _%x130015%_))
                                        (begin
                                          (raise-contract-violation-error
                                           '"contract violation"
                                           'context:
                                           'gerbil/runtime/c3
                                           'contract:
                                           'number?
                                           'value:
                                           _%x130010%_)
                                          '#!void))))))
                              (_%decrement-ancestor-count129480%_
                               (lambda (_%c129988%_)
                                 (let ((_%count130006%_
                                        (let ((_%x129990%_
                                               (_%get-ancestor-count129478%_
                                                _%c129988%_)))
                                          (if (number? _%x129990%_)
                                              (let ((_%x129995%_ _%x129990%_))
                                                (declare (not safe))
                                                (__1- _%x129995%_))
                                              (begin
                                                (raise-contract-violation-error
                                                 '"contract violation"
                                                 'context:
                                                 'gerbil/runtime/c3
                                                 'contract:
                                                 'number?
                                                 'value:
                                                 _%x129990%_)
                                                '#!void)))))
                                   (if (= '0 _%count130006%_)
                                       (_%tab-remove!129471%_
                                        _%ancestor-counts129477%_
                                        _%c129988%_)
                                       (_%tab-set!129470%_
                                        _%ancestor-counts129477%_
                                        _%c129988%_
                                        _%count130006%_)))))
                              (_g130265_
                               (let ((_g130266_
                                      (for-each
                                       (lambda (_%parent-list129482%_)
                                         (for-each
                                          (lambda (_%parent129484%_)
                                            (if (zero? (_%get-ancestor-count129478%_
                                                        _%parent129484%_))
                                                (let _%loop129486%_ ((_%al129488%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (_%get-precedence-list129420%_ _%parent129484%_))
                             (_%r129489%_ '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (letrec ((_%done129491%_
                                                            (lambda ()
                                                              (if (null? _%r129489%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#!void
                          (set! _%rcandidates129464%_
                                (cons _%r129489%_ _%rcandidates129464%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let* ((_%$%al129492129501%_
                                                            _%al129488%_)
                                                           (_%$%E129495129505%_
                                                            (lambda ()
                                                              (error '"No clause matching"
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%al129492129501%_
                             '([])
                             '([a . ar]))
                      '#!void)))
              (let ((_%$%K129499129572%_ (lambda () (_%done129491%_)))
                    (_%$%K129496129556%_
                     (lambda (_%ar129509%_ _%a129510%_)
                       (if (_%suffix?129422%_ _%a129510%_)
                           (let ((_%ms129512%_
                                  (_%merge-suffix129476%_
                                   _%a129510%_
                                   _%suffix129465%_)))
                             (if (and _%suffix129465%_
                                      (_%eq129451%_
                                       _%ms129512%_
                                       _%suffix129465%_))
                                 '#!void
                                 (begin
                                   (let _%loop2129514%_ ((_%tl129516%_
                                                          _%al129488%_))
                                     (let* ((_%$%tl129517129526%_ _%tl129516%_)
                                            (_%$%E129520129530%_
                                             (lambda ()
                                               (error '"No clause matching"
                                                      _%$%tl129517129526%_
                                                      '([])
                                                      '([t . tr]))
                                               '#!void)))
                                       (let ((_%$%K129524129553%_
                                              (lambda () '#!void))
                                             (_%$%K129521129537%_
                                              (lambda (_%tr129534%_
                                                       _%t129535%_)
                                                (if (and _%suffix129465%_
                                                         (_%eq129451%_
                                                          _%t129535%_
                                                          _%suffix129465%_))
                                                    '#!void
                                                    (begin
                                                      (_%increment-ancestor-count129479%_
                                                       _%t129535%_)
                                                      (_%loop2129514%_
                                                       _%tr129534%_))))))
                                         (let ((_%$%try-match129519129549%_
                                                (lambda ()
                                                  (if (pair? _%$%tl129517129526%_)
                                                      (let ((_%$%tl129523129542%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%tl129517129526%_)))
                    (_%$%hd129522129540%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%tl129517129526%_))))
                (let ((_%t129545%_ _%$%hd129522129540%_)
                      (_%tr129547%_ _%$%tl129523129542%_))
                  (_%$%K129521129537%_ _%tr129547%_ _%t129545%_)))
              (_%$%E129520129530%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (if (null? _%$%tl129517129526%_)
                                               '#!void
                                               (_%$%try-match129519129549%_))))))
                                   (set! _%suffix129465%_ _%a129510%_)
                                   (set! _%suffix-tail129466%_ _%al129488%_)))
                             (_%done129491%_))
                           (begin
                             (_%increment-ancestor-count129479%_ _%a129510%_)
                             (_%loop129486%_
                              _%ar129509%_
                              (cons _%a129510%_ _%r129489%_)))))))
                (let ((_%$%try-match129494129568%_
                       (lambda ()
                         (if (pair? _%$%al129492129501%_)
                             (let ((_%$%tl129498129561%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%al129492129501%_)))
                                   (_%$%hd129497129559%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%al129492129501%_))))
                               (let ((_%a129564%_ _%$%hd129497129559%_)
                                     (_%ar129566%_ _%$%tl129498129561%_))
                                 (_%$%K129496129556%_
                                  _%ar129566%_
                                  _%a129564%_)))
                             (_%$%E129495129505%_)))))
                  (if (null? _%$%al129492129501%_)
                      (_%done129491%_)
                      (_%$%try-match129494129568%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '#!void))
                                          _%parent-list129482%_))
                                       _%parents129418%_)))
                                 #!void
                                 _g130266_))
                              (_%suffix-tail-index129575%_
                               (_%make-tab129468%_))
                              (_g130268_
                               (let ((_g130269_
                                      (let _%loop129577%_ ((_%i129579%_
                                                            (length _%suffix-tail129466%_))
                                                           (_%t129580%_
                                                            _%suffix-tail129466%_))
                                        (let* ((_%$%t129581129590%_
                                                _%t129580%_)
                                               (_%$%E129584129594%_
                                                (lambda ()
                                                  (error '"No clause matching"
                                                         _%$%t129581129590%_
                                                         '([])
                                                         '([a . r]))
                                                  '#!void)))
                                          (let ((_%$%K129588129645%_
                                                 (lambda () '#!void))
                                                (_%$%K129585129629%_
                                                 (lambda (_%r129598%_
                                                          _%a129599%_)
                                                   (_%tab-set!129470%_
                                                    _%suffix-tail-index129575%_
                                                    _%a129599%_
                                                    _%i129579%_)
                                                   (_%loop129577%_
                                                    (let ((_%x129601%_
                                                           _%i129579%_))
                                                      (if (number? _%x129601%_)
                                                          (let ((_%x129606%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%x129601%_))
                    (declare (not safe))
                    (__1- _%x129606%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/runtime/c3
                     'contract:
                     'number?
                     'value:
                     _%x129601%_)
                    '#!void)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    _%r129598%_))))
                                            (let ((_%$%try-match129583129641%_
                                                   (lambda ()
                                                     (if (pair? _%$%t129581129590%_)
                                                         (let ((_%$%tl129587129634%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (##cdr _%$%t129581129590%_)))
                       (_%$%hd129586129632%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%t129581129590%_))))
                   (let ((_%a129637%_ _%$%hd129586129632%_)
                         (_%r129639%_ _%$%tl129587129634%_))
                     (_%$%K129585129629%_ _%r129639%_ _%a129637%_)))
                 (_%$%E129584129594%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (null? _%$%t129581129590%_)
                                                  '#!void
                                                  (_%$%try-match129583129641%_))))))))
                                 #!void
                                 _g130269_))
                              (_%r-local-order129647%_
                               (let ((__tmp130271
                                      (lambda (_%parent-list129986%_)
                                        (if (null? (cdr _%parent-list129986%_))
                                            '#f
                                            (reverse _%parent-list129986%_)))))
                                 (declare (not safe))
                                 (filter-map__0
                                  __tmp130271
                                  _%parents129418%_)))
                              (_g130272_
                               (let ((_g130273_
                                      (let ((__tmp130275
                                             (lambda (_%cl129649%_)
                                               (for-each
                                                _%increment-ancestor-count129479%_
                                                _%cl129649%_))))
                                        (declare (not safe))
                                        (##for-each
                                         __tmp130275
                                         _%r-local-order129647%_))))
                                 #!void
                                 _g130273_))
                              (_g130276_
                               (let ((_g130277_
                                      (set! _%rcandidates129464%_
                                            (let ()
                                              (declare (not safe))
                                              (##append
                                               _%r-local-order129647%_
                                               _%rcandidates129464%_)))))
                                 #!void
                                 _g130277_))
                              (_%remove-suffix-tail-and-reverse129650%_
                               (lambda (_%rcl129860%_)
                                 (let _%u129862%_ ((_%cl-rhead129864%_
                                                    _%rcl129860%_)
                                                   (_%suffix-pos129865%_ '-1))
                                   (let* ((_%$%cl-rhead129866129875%_
                                           _%cl-rhead129864%_)
                                          (_%$%E129869129879%_
                                           (lambda ()
                                             (error '"No clause matching"
                                                    _%$%cl-rhead129866129875%_
                                                    '([])
                                                    '([c . clrh]))
                                             '#!void)))
                                     (let ((_%$%K129873129983%_
                                            (lambda () '()))
                                           (_%$%K129870129967%_
                                            (lambda (_%clrh129883%_
                                                     _%c129884%_)
                                              (let ((_%p129886%_
                                                     (_%tab-ref129469%_
                                                      _%suffix-tail-index129575%_
                                                      _%c129884%_
                                                      '#f)))
                                                (letrec ((_%err2129888%_
                                                          (lambda _%a129933%_
                                                            (apply _%err129474%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           'reverse-candidate-list:
                           (_%get-names129473%_ _%rcl129860%_)
                           'suffix-tail-index:
                           (map (lambda (_%$%e129934129936%_)
                                  (let* ((_%$%$%e129934129938129945%_
                                          _%$%e129934129936%_)
                                         (_%$%E129940129949%_
                                          (lambda ()
                                            (error '"No clause matching"
                                                   _%$%$%e129934129938129945%_
                                                   '([a . i]))
                                            '#!void))
                                         (_%$%K129941129955%_
                                          (lambda (_%i129952%_ _%a129953%_)
                                            (cons (_%get-name129453%_
                                                   _%a129953%_)
                                                  _%i129952%_))))
                                    (if (pair? _%$%$%e129934129938129945%_)
                                        (let ((_%$%hd129942129958%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%$%e129934129938129945%_)))
                                              (_%$%tl129943129960%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%$%e129934129938129945%_))))
                                          (let* ((_%a129963%_
                                                  _%$%hd129942129958%_)
                                                 (_%i129965%_
                                                  _%$%tl129943129960%_))
                                            (_%$%K129941129955%_
                                             _%i129965%_
                                             _%a129963%_)))
                                        (_%$%E129940129949%_))))
                                (_%tab->list129472%_
                                 _%suffix-tail-index129575%_))
                           'c:
                           (_%get-name129453%_ _%c129884%_)
                           'p:
                           _%p129886%_
                           'suffix-pos:
                           _%suffix-pos129865%_
                           _%a129933%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if _%p129886%_
                                                      (if (> _%p129886%_
                                                             _%suffix-pos129865%_)
                                                          (_%u129862%_
                                                           _%clrh129883%_
                                                           _%p129886%_)
                                                          (_%err2129888%_
                                                           'ancestor-out-of-order-vs-suffix-tail:
                                                           (_%get-name129453%_
                                                            _%c129884%_)))
                                                      (let ((_g130279_
                                                             (let* ((_%pred129895%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (lambda (_%$%g129890129892%_)
                               (_%tab-ref129469%_
                                _%suffix-tail-index129575%_
                                _%$%g129890129892%_
                                '#f)))
                            (_%rhead129898%_ _%clrh129883%_)
                            (_%tail129901%_ (cons _%c129884%_ '()))
                            (_%pred129906%_ _%pred129895%_))
                       (declare (not safe))
                       (__append-reverse-until
                        _%pred129906%_
                        _%rhead129898%_
                        _%tail129901%_))))
                (begin
                  (let ((_g130280_
                         (let ()
                           (declare (not safe))
                           (if (##values? _g130279_)
                               (##values-length _g130279_)
                               1))))
                    (if (not (let () (declare (not safe)) (##fx= _g130280_ 2)))
                        (error "Context expects 2 values" _g130280_)))
                  (let ((_%clrh2129928%_
                         (let ()
                           (declare (not safe))
                           (##values-ref _g130279_ 0)))
                        (_%h129929%_
                         (let ()
                           (declare (not safe))
                           (##values-ref _g130279_ 1))))
                    (if (null? _%clrh2129928%_)
                        _%h129929%_
                        (_%err2129888%_
                         'precedence-list-tail:
                         (_%get-names129473%_ _%h129929%_)
                         'ancestor-out-of-order-vs-suffix-tail:
                         (_%get-name129453%_ (car _%clrh2129928%_))
                         'precedence-list-head:
                         (_%get-names129473%_
                          (reverse _%clrh2129928%_)))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (let ((_%$%try-match129868129979%_
                                              (lambda ()
                                                (if (pair? _%$%cl-rhead129866129875%_)
                                                    (let ((_%$%tl129872129972%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%cl-rhead129866129875%_)))
                                                          (_%$%hd129871129970%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%cl-rhead129866129875%_))))
                                                      (let ((_%c129975%_
                                                             _%$%hd129871129970%_)
                                                            (_%clrh129977%_
                                                             _%$%tl129872129972%_))
                                                        (_%$%K129870129967%_
                                                         _%clrh129977%_
                                                         _%c129975%_)))
                                                    (_%$%E129869129879%_)))))
                                         (if (null? _%$%cl-rhead129866129875%_)
                                             (_%$%K129873129983%_)
                                             (_%$%try-match129868129979%_))))))))
                              (_%candidates129651%_
                               (reverse (let ((__tmp130281
                                               (let ()
                                                 (declare (not safe))
                                                 (##map _%remove-suffix-tail-and-reverse129650%_
                                                        _%rcandidates129464%_))))
                                          (declare (not safe))
                                          (remove-nulls! __tmp130281))))
                              (_g130282_
                               (let ((_g130283_
                                      (let ((__tmp130285
                                             (lambda (_%cl129653%_)
                                               (_%decrement-ancestor-count129480%_
                                                (car _%cl129653%_)))))
                                        (declare (not safe))
                                        (##for-each
                                         __tmp130285
                                         _%candidates129651%_))))
                                 #!void
                                 _g130283_))
                              (_%c3-select-next129654%_
                               (lambda (_%tails129816%_)
                                 (let _%loop129818%_ ((_%ts129820%_
                                                       _%tails129816%_))
                                   (let* ((_%$%ts129821129831%_ _%ts129820%_)
                                          (_%$%else129823129839%_
                                           (lambda ()
                                             (_%err129474%_
                                              'c3-select-next:
                                              'fail)))
                                          (_%$%K129825129845%_
                                           (lambda (_%rts129842%_ _%c129843%_)
                                             (if (zero? (_%get-ancestor-count129478%_
                                                         _%c129843%_))
                                                 _%c129843%_
                                                 (_%loop129818%_
                                                  _%rts129842%_)))))
                                     (if (pair? _%$%ts129821129831%_)
                                         (let ((_%$%hd129826129848%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%ts129821129831%_)))
                                               (_%$%tl129827129850%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%ts129821129831%_))))
                                           (if (pair? _%$%hd129826129848%_)
                                               (let* ((_%$%hd129828129853%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%hd129826129848%_)))
                                                      (_%c129856%_
                                                       _%$%hd129828129853%_)
                                                      (_%rts129858%_
                                                       _%$%tl129827129850%_))
                                                 (_%$%K129825129845%_
                                                  _%rts129858%_
                                                  _%c129856%_))
                                               (_%$%else129823129839%_)))
                                         (_%$%else129823129839%_))))))
                              (_%remove-next!129655%_
                               (lambda (_%next129706%_ _%tails129707%_)
                                 (let _%loop129709%_ ((_%t129711%_
                                                       _%tails129707%_))
                                   (let* ((_%$%t129712129727%_ _%t129711%_)
                                          (_%$%E129716129731%_
                                           (lambda ()
                                             (error '"No clause matching"
                                                    _%$%t129712129727%_
                                                    '([(and hd
                                                            [(? (cut eq
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             next
                             <>))
                     .
                     tl])
               .
               rr])
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '([_ . rr])
                                                    '(_))
                                             '#!void)))
                                     (let ((_%$%K129721129793%_
                                            (lambda (_%rr129756%_
                                                     _%tl129757%_
                                                     _%hd129758%_)
                                              (let* ((_%$%tl129759129768%_
                                                      _%tl129757%_)
                                                     (_%$%E129762129772%_
                                                      (lambda ()
                                                        (error '"No clause matching"
                                                               _%$%tl129759129768%_
                                                               '([c . _])
                                                               '(_))
                                                        '#!void)))
                                                (let ((_%$%K129764129785%_
                                                       (lambda (_%c129783%_)
                                                         (_%decrement-ancestor-count129480%_
                                                          _%c129783%_)))
                                                      (_%$%K129763129777%_
                                                       (lambda () '#!void)))
                                                  (if (pair? _%$%tl129759129768%_)
                                                      (let* ((_%$%hd129765129788%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%tl129759129768%_)))
                     (_%c129791%_ _%$%hd129765129788%_))
                (_%decrement-ancestor-count129480%_ _%c129791%_))
              '#!void)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (set-car!
                                               _%t129711%_
                                               _%tl129757%_)
                                              (_%loop129709%_ _%rr129756%_)))
                                           (_%$%K129718129745%_
                                            (lambda (_%rr129743%_)
                                              (_%loop129709%_ _%rr129743%_)))
                                           (_%$%K129717129736%_
                                            (lambda () _%tails129707%_)))
                                       (if (pair? _%$%t129712129727%_)
                                           (let ((_%$%tl129723129798%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%t129712129727%_)))
                                                 (_%$%hd129722129796%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%t129712129727%_))))
                                             (if (pair? _%$%hd129722129796%_)
                                                 (let ((_%$%tl129725129805%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%hd129722129796%_)))
                                                       (_%$%hd129724129803%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%hd129722129796%_))))
                                                   (if (_%eq129451%_
                                                        _%next129706%_
                                                        _%$%hd129724129803%_)
                                                       (let ((_%hd129801%_
                                                              _%$%hd129722129796%_)
                                                             (_%tl129812%_
                                                              _%$%tl129725129805%_)
                                                             (_%rr129814%_
                                                              _%$%tl129723129798%_))
                                                         (_%$%K129721129793%_
                                                          _%rr129814%_
                                                          _%tl129812%_
                                                          _%hd129801%_))
                                                       (let ((_%rr129751%_
                                                              _%$%tl129723129798%_))
                                                         (_%loop129709%_
                                                          _%rr129751%_))))
                                                 (let ((_%rr129751%_
                                                        _%$%tl129723129798%_))
                                                   (_%loop129709%_
                                                    _%rr129751%_))))
                                           (_%$%K129717129736%_)))))))
                              (_%precedence-list129656%_
                               (let _%c3loop129658%_ ((_%rhead129660%_
                                                       (reverse _%head129417%_))
                                                      (_%tails129661%_
                                                       _%candidates129651%_))
                                 (let* ((_%$%tails129662129672%_
                                         _%tails129661%_)
                                        (_%$%else129665129683%_
                                         (lambda ()
                                           (let ((_%next129680%_
                                                  (_%c3-select-next129654%_
                                                   _%tails129661%_)))
                                             (_%c3loop129658%_
                                              (cons _%next129680%_
                                                    _%rhead129660%_)
                                              (let ((__tmp130286
                                                     (_%remove-next!129655%_
                                                      _%next129680%_
                                                      _%tails129661%_)))
                                                (declare (not safe))
                                                (remove-nulls!
                                                 __tmp130286)))))))
                                   (let ((_%$%K129670129703%_
                                          (lambda ()
                                            (append-reverse
                                             _%rhead129660%_
                                             _%suffix-tail129466%_)))
                                         (_%$%K129667129689%_
                                          (lambda (_%tail129687%_)
                                            (append-reverse
                                             _%rhead129660%_
                                             (append _%tail129687%_
                                                     _%suffix-tail129466%_)))))
                                     (let ((_%$%try-match129664129699%_
                                            (lambda ()
                                              (if (pair? _%$%tails129662129672%_)
                                                  (let ((_%$%tl129669129694%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%tails129662129672%_)))
                                                        (_%$%hd129668129692%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%tails129662129672%_))))
                                                    (if (null? _%$%tl129669129694%_)
                                                        (let ((_%tail129697%_
                                                               _%$%hd129668129692%_))
                                                          (_%$%K129667129689%_
                                                           _%tail129697%_))
                                                        (_%$%else129665129683%_)))
                                                  (_%$%else129665129683%_)))))
                                       (if (null? _%$%tails129662129672%_)
                                           (_%$%K129670129703%_)
                                           (_%$%try-match129664129699%_))))))))
                      (values _%precedence-list129656%_
                              _%suffix129465%_))))))))
    (define c4-linearize*__@
      (lambda (_%@@keywords130140%_ . _%args130141%_)
        (apply c4-linearize*__%
               _%@@keywords130140%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130140%_
                  'get-precedence-list:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130140%_
                  'suffix:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130140%_
                  'super-suffix:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords130140%_ 'eq: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords130140%_
                  'get-name:
                  absent-value))
               _%args130141%_)))
    (define c4-linearize*
      (lambda _%$%args129409130147%_
        (apply keyword-dispatch
               '#(#f
                  #f
                  super-suffix:
                  eq:
                  suffix:
                  #f
                  #f
                  get-precedence-list:
                  #f
                  get-name:)
               c4-linearize*__@
               _%$%args129409130147%_)))
    (define c4-compute-class-slots
      (lambda (_%precedence-list129358%_
               _%direct-slot-list129359%_
               _%mixin-slot-names129360%_
               _%result129361%_)
        (let* ((_%next-slot129363%_ '1)
               (_%slot-table129365%_
                (let () (declare (not safe)) (make-symbolic-table__% '#f '0)))
               (_%r-slots129367%_ (cons 'class '()))
               (_%process-slot129392%_
                (lambda (_%slot129369%_)
                  (if (symbol? _%slot129369%_)
                      '#!void
                      (error '"invalid slot name" _%slot129369%_))
                  (if (eq? (let ()
                             (declare (not safe))
                             (symbolic-table-ref
                              _%slot-table129365%_
                              _%slot129369%_
                              absent-value))
                           absent-value)
                      (begin
                        (let ()
                          (declare (not safe))
                          (symbolic-table-set!
                           _%slot-table129365%_
                           _%slot129369%_
                           _%next-slot129363%_))
                        (let ((__tmp130287
                               (let ((_%sym129371%_ _%slot129369%_))
                                 (if (symbol? _%sym129371%_)
                                     (let ((_%sym129376%_ _%sym129371%_))
                                       (declare (not safe))
                                       (__symbol->keyword _%sym129376%_))
                                     (begin
                                       (raise-contract-violation-error
                                        '"contract violation"
                                        'context:
                                        'gerbil/runtime/c3
                                        'contract:
                                        'symbol?
                                        'value:
                                        _%sym129371%_)
                                       '#!void)))))
                          (declare (not safe))
                          (symbolic-table-set!
                           _%slot-table129365%_
                           __tmp130287
                           _%next-slot129363%_))
                        (set! _%r-slots129367%_
                              (cons _%slot129369%_ _%r-slots129367%_))
                        (set! _%next-slot129363%_
                              (let ()
                                (declare (not safe))
                                (##fx+ _%next-slot129363%_ '1))))
                      '#!void)))
               (_%process-slots129398%_
                (lambda (_%$%g129393129395%_)
                  (for-each _%process-slot129392%_ _%$%g129393129395%_))))
          (let ((__tmp130289
                 (lambda (_%mixin129401%_)
                   (_%process-slots129398%_
                    (_%mixin-slot-names129360%_ _%mixin129401%_))))
                (__tmp130288 (reverse _%precedence-list129358%_)))
            (declare (not safe))
            (##for-each __tmp130289 __tmp130288))
          (_%process-slots129398%_ _%direct-slot-list129359%_)
          (_%result129361%_
           (reverse! _%r-slots129367%_)
           _%slot-table129365%_))))))
