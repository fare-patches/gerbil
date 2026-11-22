(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/stxcase::timestamp 1795039817)
  (begin
    (define gx#syntax-pattern::t
      (let ((__tmp201954 (list gx#expander::t))
            (__tmp201953 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gx#syntax-pattern::t
         'syntax-pattern
         __tmp201954
         '(id depth)
         __tmp201953
         '#f)))
    (define gx#syntax-pattern?
      (let ()
        (declare (not safe))
        (__make-class-predicate gx#syntax-pattern::t)))
    (define gx#make-syntax-pattern
      (lambda _%$args201950%_
        (apply make-instance gx#syntax-pattern::t _%$args201950%_)))
    (define gx#syntax-pattern-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gx#syntax-pattern::t 'id)))
    (define gx#syntax-pattern-depth
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gx#syntax-pattern::t 'depth)))
    (define gx#syntax-pattern-e
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gx#syntax-pattern::t 'e)))
    (define gx#syntax-pattern-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gx#syntax-pattern::t 'id)))
    (define gx#syntax-pattern-depth-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gx#syntax-pattern::t 'depth)))
    (define gx#syntax-pattern-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gx#syntax-pattern::t 'e)))
    (define gx#&syntax-pattern-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gx#syntax-pattern::t 'id)))
    (define gx#&syntax-pattern-depth
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gx#syntax-pattern::t 'depth)))
    (define gx#&syntax-pattern-e
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gx#syntax-pattern::t 'e)))
    (define gx#&syntax-pattern-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gx#syntax-pattern::t 'id)))
    (define gx#&syntax-pattern-depth-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gx#syntax-pattern::t 'depth)))
    (define gx#&syntax-pattern-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gx#syntax-pattern::t 'e)))
    (define gx#syntax-pattern::apply-macro-expander
      (lambda (_%self201936%_ _%stx201937%_)
        (let ((_%self201940%_ _%self201936%_))
          (declare (not safe))
          (gx#raise-syntax-error
           '#f
           '"Identifier used out of context"
           _%stx201937%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gx#syntax-pattern::t
       'apply-macro-expander
       gx#syntax-pattern::apply-macro-expander
       '#f))
    (define gx#macro-expand-syntax
      (lambda (_%stx201403%_)
        (letrec ((_%generate201405%_
                  (lambda (_%e201645%_)
                    (letrec ((_%BUG201647%_
                              (lambda (_%q201812%_)
                                (let ()
                                  (declare (not safe))
                                  (error '"BUG: syntax; generate"
                                         _%stx201403%_
                                         _%e201645%_
                                         _%q201812%_))))
                             (_%local-pattern-e201648%_
                              (lambda (_%pat201810%_)
                                (let ((__tmp201955
                                       (##structure-ref
                                        _%pat201810%_
                                        '2
                                        gx#syntax-pattern::t
                                        '#f)))
                                  (declare (not safe))
                                  (gx#syntax-local-rewrap __tmp201955))))
                             (_%getvar201649%_
                              (lambda (_%q201807%_ _%vars201808%_)
                                (let ()
                                  (declare (not safe))
                                  (agetq__%
                                   _%q201807%_
                                   _%vars201808%_
                                   _%BUG201647%_))))
                             (_%getarg201650%_
                              (lambda (_%arg201773%_ _%vars201774%_)
                                (let* ((_%$%arg201775201782%_ _%arg201773%_)
                                       (_%$%E201777201786%_
                                        (lambda ()
                                          (let ()
                                            (declare (not safe))
                                            (error '"No clause matching"
                                                   _%$%arg201775201782%_
                                                   '([tag . e])))
                                          '#!void))
                                       (_%$%K201778201795%_
                                        (lambda (_%e201789%_ _%tag201790%_)
                                          (let ((_%$e201792%_ _%tag201790%_))
                                            (if (eq? 'ref _%$e201792%_)
                                                (_%getvar201649%_
                                                 _%e201789%_
                                                 _%vars201774%_)
                                                (if (eq? 'pattern _%$e201792%_)
                                                    (_%local-pattern-e201648%_
                                                     _%e201789%_)
                                                    (_%BUG201647%_
                                                     _%arg201773%_)))))))
                                  (if (pair? _%$%arg201775201782%_)
                                      (let ((_%$%hd201779201798%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%arg201775201782%_)))
                                            (_%$%tl201780201800%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%arg201775201782%_))))
                                        (let* ((_%tag201803%_
                                                _%$%hd201779201798%_)
                                               (_%e201805%_
                                                _%$%tl201780201800%_))
                                          (_%$%K201778201795%_
                                           _%e201805%_
                                           _%tag201803%_)))
                                      (_%$%E201777201786%_))))))
                      (let _%recur201652%_ ((_%e201654%_ _%e201645%_)
                                            (_%vars201655%_ '()))
                        (let* ((_%$%e201656201663%_ _%e201654%_)
                               (_%$%E201658201667%_
                                (lambda ()
                                  (let ()
                                    (declare (not safe))
                                    (error '"No clause matching"
                                           _%$%e201656201663%_
                                           '([tag . body])))
                                  '#!void))
                               (_%$%K201659201761%_
                                (lambda (_%body201670%_ _%tag201671%_)
                                  (let ((_%$e201673%_ _%tag201671%_))
                                    (if (eq? 'datum _%$e201673%_)
                                        (let ()
                                          (declare (not safe))
                                          (gx#core-list 'quote _%body201670%_))
                                        (if (eq? 'term _%$e201673%_)
                                            (let ((_%id201676%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-local-unwrap
                                                      _%body201670%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (##structure-direct-instance-of?
                                                     _%id201676%_
                                                     'gx#identifier-wrap::t))
                                                  (let ((_%marks201679%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##unchecked-structure-ref
                                                            _%id201676%_
                                                            '3
                                                            '#f
                                                            '#f))))
                                                    (if (null? _%marks201679%_)
                                                        (let ((__tmp201956
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#core-list 'quote _%body201670%_))))
                  (declare (not safe))
                  (gx#core-list 'datum->syntax '#f __tmp201956))
                (let ((__tmp201958
                       (let ()
                         (declare (not safe))
                         (gx#core-list 'quote-syntax _%body201670%_)))
                      (__tmp201957
                       (let ()
                         (declare (not safe))
                         (gx#core-list 'quote _%body201670%_))))
                  (declare (not safe))
                  (gx#core-list
                   'datum->syntax
                   __tmp201958
                   __tmp201957
                   '#f
                   '#f))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (##structure-direct-instance-of?
                                                         _%id201676%_
                                                         'gx#syntax-quote::t))
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#core-list
                                                         'quote-syntax
                                                         _%body201670%_))
                                                      (_%BUG201647%_
                                                       _%e201654%_))))
                                            (if (eq? 'pattern _%$e201673%_)
                                                (_%local-pattern-e201648%_
                                                 _%body201670%_)
                                                (if (eq? 'ref _%$e201673%_)
                                                    (_%getvar201649%_
                                                     _%body201670%_
                                                     _%vars201655%_)
                                                    (if (eq? 'cons
                                                             _%$e201673%_)
                                                        (let ((__tmp201960
                                                               (_%recur201652%_
                                                                (car _%body201670%_)
                                                                _%vars201655%_))
                                                              (__tmp201959
                                                               (_%recur201652%_
                                                                (cdr _%body201670%_)
                                                                _%vars201655%_)))
                                                          (declare (not safe))
                                                          (gx#core-list
                                                           'cons
                                                           __tmp201960
                                                           __tmp201959))
                                                        (if (eq? 'vector
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$e201673%_)
                    (let ((__tmp201961
                           (_%recur201652%_ _%body201670%_ _%vars201655%_)))
                      (declare (not safe))
                      (gx#core-list 'list->vector __tmp201961))
                    (if (eq? 'box _%$e201673%_)
                        (let ((__tmp201962
                               (_%recur201652%_
                                _%body201670%_
                                _%vars201655%_)))
                          (declare (not safe))
                          (gx#core-list 'box __tmp201962))
                        (if (eq? 'splice _%$e201673%_)
                            (let* ((_%$%body201682201693%_ _%body201670%_)
                                   (_%$%E201684201697%_
                                    (lambda ()
                                      (let ()
                                        (declare (not safe))
                                        (error '"No clause matching"
                                               _%$%body201682201693%_
                                               '([depth hd iv . args])))
                                      '#!void))
                                   (_%$%K201685201735%_
                                    (lambda (_%args201700%_
                                             _%iv201701%_
                                             _%hd201702%_
                                             _%depth201703%_)
                                      (let* ((_%targets201709%_
                                              (map (lambda (_%$%g201704201706%_)
                                                     (_%getarg201650%_
                                                      _%$%g201704201706%_
                                                      _%vars201655%_))
                                                   _%args201700%_))
                                             (_%fold-in201711%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#gentemps _%args201700%_)))
                                             (_%fold-out201713%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#genident__0)))
                                             (_%lambda-args201715%_
                                              (let ((__tmp201963
                                                     (cons _%fold-out201713%_
                                                           '())))
                                                (declare (not safe))
                                                (##append
                                                 _%fold-in201711%_
                                                 __tmp201963)))
                                             (_%lambda-body201732%_
                                              (if (let ()
                                                    (declare (not safe))
                                                    (##fx> _%depth201703%_ '1))
                                                  (let ((_%r-args201723%_
                                                         (map (lambda (_%arg201717%_)
                                                                (cons 'ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cdr _%arg201717%_)))
                      _%args201700%_))
                (_%r-vars201724%_
                 (let ((__tmp201964
                        (lambda (_%arg201719%_ _%var201720%_ _%r201721%_)
                          (cons (cons (cdr _%arg201719%_) _%var201720%_)
                                _%r201721%_))))
                   (declare (not safe))
                   (foldr__1
                    __tmp201964
                    _%vars201655%_
                    _%args201700%_
                    _%fold-in201711%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%recur201652%_
                                                     (cons 'splice
                                                           (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (declare (not safe))
                           (##fx- _%depth201703%_ '1))
                         (cons _%hd201702%_
                               (cons (cons 'var _%fold-out201713%_)
                                     _%r-args201723%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%r-vars201724%_))
                                                  (let* ((_%hd-vars201730%_
                                                          (let ((__tmp201965
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (lambda (_%arg201726%_ _%var201727%_ _%r201728%_)
                           (cons (cons (cdr _%arg201726%_) _%var201727%_)
                                 _%r201728%_))))
                    (declare (not safe))
                    (foldr__1
                     __tmp201965
                     _%vars201655%_
                     _%args201700%_
                     _%fold-in201711%_)))
                 (__tmp201966
                  (_%recur201652%_ _%hd201702%_ _%hd-vars201730%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (gx#core-list
                                                     'cons
                                                     __tmp201966
                                                     _%fold-out201713%_)))))
                                        (let ((__tmp201970
                                               (if (let ((__tmp201971
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##length
                                                             _%targets201709%_))))
                                                     (declare (not safe))
                                                     (##fx> __tmp201971 '1))
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#core-cons*
                                                      'syntax-check-splice-targets
                                                      _%targets201709%_))
                                                   '#!void))
                                              (__tmp201967
                                               (let ((__tmp201969
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#core-list
                                                         'lambda%
                                                         _%lambda-args201715%_
                                                         _%lambda-body201732%_)))
                                                     (__tmp201968
                                                      (_%recur201652%_
                                                       _%iv201701%_
                                                       _%vars201655%_)))
                                                 (declare (not safe))
                                                 (gx#core-cons*
                                                  'foldr
                                                  __tmp201969
                                                  __tmp201968
                                                  _%targets201709%_))))
                                          (declare (not safe))
                                          (gx#core-list
                                           'begin
                                           __tmp201970
                                           __tmp201967))))))
                              (if (pair? _%$%body201682201693%_)
                                  (let ((_%$%hd201686201738%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%body201682201693%_)))
                                        (_%$%tl201687201740%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%body201682201693%_))))
                                    (let ((_%depth201743%_
                                           _%$%hd201686201738%_))
                                      (if (pair? _%$%tl201687201740%_)
                                          (let ((_%$%hd201688201745%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%tl201687201740%_)))
                                                (_%$%tl201689201747%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%tl201687201740%_))))
                                            (let ((_%hd201750%_
                                                   _%$%hd201688201745%_))
                                              (if (pair? _%$%tl201689201747%_)
                                                  (let ((_%$%hd201690201752%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%tl201689201747%_)))
                                                        (_%$%tl201691201754%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%tl201689201747%_))))
                                                    (let* ((_%iv201757%_
                                                            _%$%hd201690201752%_)
                                                           (_%args201759%_
                                                            _%$%tl201691201754%_))
                                                      (_%$%K201685201735%_
                                                       _%args201759%_
                                                       _%iv201757%_
                                                       _%hd201750%_
                                                       _%depth201743%_)))
                                                  (_%$%E201684201697%_))))
                                          (_%$%E201684201697%_))))
                                  (_%$%E201684201697%_)))
                            (if (eq? 'var _%$e201673%_)
                                _%body201670%_
                                (_%BUG201647%_ _%e201654%_))))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                          (if (pair? _%$%e201656201663%_)
                              (let ((_%$%hd201660201764%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e201656201663%_)))
                                    (_%$%tl201661201766%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e201656201663%_))))
                                (let* ((_%tag201769%_ _%$%hd201660201764%_)
                                       (_%body201771%_ _%$%tl201661201766%_))
                                  (_%$%K201659201761%_
                                   _%body201771%_
                                   _%tag201769%_)))
                              (_%$%E201658201667%_)))))))
                 (_%parse201406%_
                  (lambda (_%e201447%_)
                    (letrec ((_%make-cons201449%_
                              (lambda (_%hd201637%_ _%tl201638%_)
                                (let ((_g201972_ _%hd201637%_)
                                      (_g201974_ _%tl201638%_))
                                  (begin
                                    (let ((_g201973_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g201972_)
                                                 (##values-length _g201972_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g201973_ 2)))
                                          (error "Context expects 2 values"
                                                 _g201973_)))
                                    (let ((_g201975_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g201974_)
                                                 (##values-length _g201974_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g201975_ 2)))
                                          (error "Context expects 2 values"
                                                 _g201975_)))
                                    (let ((_%hd-e201640%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g201972_ 0)))
                                          (_%hd-vars201641%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g201972_ 1))))
                                      (let ((_%tl-e201642%_
                                             (let ()
                                               (declare (not safe))
                                               (##values-ref _g201974_ 0)))
                                            (_%tl-vars201643%_
                                             (let ()
                                               (declare (not safe))
                                               (##values-ref _g201974_ 1))))
                                        (values (cons 'cons
                                                      (cons _%hd-e201640%_
                                                            _%tl-e201642%_))
                                                (append _%hd-vars201641%_
                                                        _%tl-vars201643%_))))))))
                             (_%make-splice201450%_
                              (lambda (_%where201573%_
                                       _%depth201574%_
                                       _%hd201575%_
                                       _%tl201576%_)
                                (let ((_g201976_ _%hd201575%_)
                                      (_g201978_ _%tl201576%_))
                                  (begin
                                    (let ((_g201977_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g201976_)
                                                 (##values-length _g201976_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g201977_ 2)))
                                          (error "Context expects 2 values"
                                                 _g201977_)))
                                    (let ((_g201979_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g201978_)
                                                 (##values-length _g201978_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g201979_ 2)))
                                          (error "Context expects 2 values"
                                                 _g201979_)))
                                    (let ((_%hd-e201578%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g201976_ 0)))
                                          (_%hd-vars201579%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g201976_ 1))))
                                      (let ((_%tl-e201580%_
                                             (let ()
                                               (declare (not safe))
                                               (##values-ref _g201978_ 0)))
                                            (_%tl-vars201581%_
                                             (let ()
                                               (declare (not safe))
                                               (##values-ref _g201978_ 1))))
                                        (let _%lp201583%_ ((_%rest201585%_
                                                            _%hd-vars201579%_)
                                                           (_%targets201586%_
                                                            '())
                                                           (_%vars201587%_
                                                            _%tl-vars201581%_))
                                          (let* ((_%$%rest201588201598%_
                                                  _%rest201585%_)
                                                 (_%$%else201590201606%_
                                                  (lambda ()
                                                    (if (null? _%targets201586%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#raise-syntax-error
                                                           '#f
                                                           '"Misplaced ellipsis"
                                                           _%stx201403%_
                                                           _%where201573%_))
                                                        (values (cons 'splice
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%depth201574%_
                                    (cons _%hd-e201578%_
                                          (cons _%tl-e201580%_
                                                _%targets201586%_))))
                        _%vars201587%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%K201592201618%_
                                                  (lambda (_%rest201609%_
                                                           _%hd-pat201610%_
                                                           _%hd-depth*201611%_)
                                                    (let ((_%hd-depth201613%_
                                                           (fx- _%hd-depth*201611%_
                                                                _%depth201574%_)))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (##fxpositive?
                                                             _%hd-depth201613%_))
                                                          (_%lp201583%_
                                                           _%rest201609%_
                                                           (cons (cons 'ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               _%hd-pat201610%_)
                         _%targets201586%_)
                   (cons (cons _%hd-depth201613%_ _%hd-pat201610%_)
                         _%vars201587%_))
                  (if (let ()
                        (declare (not safe))
                        (##fxzero? _%hd-depth201613%_))
                      (_%lp201583%_
                       _%rest201609%_
                       (cons (cons 'pattern _%hd-pat201610%_)
                             _%targets201586%_)
                       _%vars201587%_)
                      (let ()
                        (declare (not safe))
                        (gx#raise-syntax-error
                         '#f
                         '"Too many ellipses"
                         _%stx201403%_
                         _%where201573%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (if (pair? _%$%rest201588201598%_)
                                                (let ((_%$%hd201593201621%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%rest201588201598%_)))
                                                      (_%$%tl201594201623%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%rest201588201598%_))))
                                                  (if (pair? _%$%hd201593201621%_)
                                                      (let ((_%$%hd201595201626%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%hd201593201621%_)))
                    (_%$%tl201596201628%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%hd201593201621%_))))
                (let* ((_%hd-depth*201631%_ _%$%hd201595201626%_)
                       (_%hd-pat201633%_ _%$%tl201596201628%_)
                       (_%rest201635%_ _%$%tl201594201623%_))
                  (_%$%K201592201618%_
                   _%rest201635%_
                   _%hd-pat201633%_
                   _%hd-depth*201631%_)))
              (_%$%else201590201606%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%else201590201606%_))))))))))
                             (_%recur201451%_
                              (lambda (_%e201456%_ _%is-e?201457%_)
                                (if (_%is-e?201457%_ _%e201456%_)
                                    (let ()
                                      (declare (not safe))
                                      (gx#raise-syntax-error
                                       '#f
                                       '"Mislpaced ellipsis"
                                       _%stx201403%_))
                                    (if (gx#syntax-local-pattern? _%e201456%_)
                                        (let* ((_%pat201461%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#syntax-local-e__0
                                                   _%e201456%_)))
                                               (_%depth201463%_
                                                (##structure-ref
                                                 _%pat201461%_
                                                 '3
                                                 gx#syntax-pattern::t
                                                 '#f)))
                                          (if (fxpositive? _%depth201463%_)
                                              (values (cons 'ref _%pat201461%_)
                                                      (cons (cons _%depth201463%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%pat201461%_)
                    '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (values (cons 'pattern
                                                            _%pat201461%_)
                                                      '())))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#identifier? _%e201456%_))
                                            (values (cons 'term _%e201456%_)
                                                    '())
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair? _%e201456%_))
                                                (let* ((_%$%e201467201474%_
                                                        _%e201456%_)
                                                       (_%$%E201469201478%_
                                                        (lambda ()
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#raise-syntax-error
                                                             '#f
                                                             '"Bad syntax; invalid syntax-case clause"
                                                             _%$%e201467201474%_))))
                                                       (_%$%E201468201560%_
                                                        (lambda ()
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%e201467201474%_))
                      (let ((_%$%e201470201482%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%e201467201474%_))))
                        (let ((_%$%hd201471201485%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e201470201482%_)))
                              (_%$%tl201472201487%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e201470201482%_))))
                          (let* ((_%hd201490%_ _%$%hd201471201485%_)
                                 (_%rest201492%_ _%$%tl201472201487%_))
                            (if (_%is-e?201457%_ _%hd201490%_)
                                (let* ((_%$%e201493201500%_ _%rest201492%_)
                                       (_%$%E201495201504%_
                                        (lambda ()
                                          (let ()
                                            (declare (not safe))
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Bad ellipsis syntax"
                                             _%stx201403%_
                                             _%e201456%_))))
                                       (_%$%E201494201518%_
                                        (lambda ()
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%e201493201500%_))
                                              (let ((_%$%e201496201508%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%e201493201500%_))))
                                                (let ((_%$%hd201497201511%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e201496201508%_)))
                                                      (_%$%tl201498201513%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e201496201508%_))))
                                                  (let ((_%rest201516%_
                                                         _%$%hd201497201511%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl201498201513%_))
                                                        (_%recur201451%_
                                                         _%rest201516%_
                                                         false)
                                                        (_%$%E201495201504%_)))))
                                              (_%$%E201495201504%_)))))
                                  (_%$%E201494201518%_))
                                (let _%lp201522%_ ((_%rest201524%_
                                                    _%rest201492%_)
                                                   (_%depth201525%_ '0))
                                  (let* ((_%$%e201526201533%_ _%rest201524%_)
                                         (_%$%E201528201537%_
                                          (lambda ()
                                            (if (fxpositive? _%depth201525%_)
                                                (_%make-splice201450%_
                                                 _%e201456%_
                                                 _%depth201525%_
                                                 (_%recur201451%_
                                                  _%hd201490%_
                                                  _%is-e?201457%_)
                                                 (_%recur201451%_
                                                  _%rest201524%_
                                                  _%is-e?201457%_))
                                                (_%make-cons201449%_
                                                 (_%recur201451%_
                                                  _%hd201490%_
                                                  _%is-e?201457%_)
                                                 (_%recur201451%_
                                                  _%rest201524%_
                                                  _%is-e?201457%_)))))
                                         (_%$%E201527201556%_
                                          (lambda ()
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%e201526201533%_))
                                                (let ((_%$%e201529201541%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#syntax-e
                                                          _%$%e201526201533%_))))
                                                  (let ((_%$%hd201530201544%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e201529201541%_)))
                                                        (_%$%tl201531201546%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e201529201541%_))))
                                                    (let* ((_%rest-hd201549%_
                                                            _%$%hd201530201544%_)
                                                           (_%rest-tl201551%_
                                                            _%$%tl201531201546%_))
                                                      (if (_%is-e?201457%_
                                                           _%rest-hd201549%_)
                                                          (_%lp201522%_
                                                           _%rest-tl201551%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##fx+ _%depth201525%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '1)))
                  (if (fxpositive? _%depth201525%_)
                      (_%make-splice201450%_
                       _%e201456%_
                       _%depth201525%_
                       (_%recur201451%_ _%hd201490%_ _%is-e?201457%_)
                       (_%recur201451%_ _%rest201524%_ _%is-e?201457%_))
                      (_%make-cons201449%_
                       (_%recur201451%_ _%hd201490%_ _%is-e?201457%_)
                       (_%recur201451%_ _%rest201524%_ _%is-e?201457%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%E201528201537%_)))))
                                    (_%$%E201527201556%_)))))))
                      (_%$%E201469201478%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E201468201560%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-vector?
                                                       _%e201456%_))
                                                    (let ((_g201980_
                                                           (_%recur201451%_
                                                            (vector->list
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-unwrap__0 _%e201456%_)))
                    _%is-e?201457%_)))
              (begin
                (let ((_g201981_
                       (let ()
                         (declare (not safe))
                         (if (##values? _g201980_)
                             (##values-length _g201980_)
                             1))))
                  (if (not (let () (declare (not safe)) (##fx= _g201981_ 2)))
                      (error "Context expects 2 values" _g201981_)))
                (let ((_%e201565%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g201980_ 0)))
                      (_%vars201566%_
                       (let ()
                         (declare (not safe))
                         (##values-ref _g201980_ 1))))
                  (values (cons 'vector _%e201565%_) _%vars201566%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-box?
                                                           _%e201456%_))
                                                        (let ((_g201982_
                                                               (_%recur201451%_
                                                                (unbox (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (declare (not safe))
                                 (gx#stx-unwrap__0 _%e201456%_)))
                        _%is-e?201457%_)))
                  (begin
                    (let ((_g201983_
                           (let ()
                             (declare (not safe))
                             (if (##values? _g201982_)
                                 (##values-length _g201982_)
                                 1))))
                      (if (not (let ()
                                 (declare (not safe))
                                 (##fx= _g201983_ 2)))
                          (error "Context expects 2 values" _g201983_)))
                    (let ((_%e201569%_
                           (let ()
                             (declare (not safe))
                             (##values-ref _g201982_ 0)))
                          (_%vars201570%_
                           (let ()
                             (declare (not safe))
                             (##values-ref _g201982_ 1))))
                      (values (cons 'box _%e201569%_) _%vars201570%_))))
                (values (cons 'datum _%e201456%_) '()))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                      (let ((_g201984_
                             (_%recur201451%_ _%e201447%_ gx#ellipsis?)))
                        (begin
                          (let ((_g201985_
                                 (let ()
                                   (declare (not safe))
                                   (if (##values? _g201984_)
                                       (##values-length _g201984_)
                                       1))))
                            (if (not (let ()
                                       (declare (not safe))
                                       (##fx= _g201985_ 2)))
                                (error "Context expects 2 values" _g201985_)))
                          (let ((_%tree201453%_
                                 (let ()
                                   (declare (not safe))
                                   (##values-ref _g201984_ 0)))
                                (_%vars201454%_
                                 (let ()
                                   (declare (not safe))
                                   (##values-ref _g201984_ 1))))
                            (if (null? _%vars201454%_)
                                _%tree201453%_
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Missing ellipsis"
                                   _%stx201403%_
                                   _%vars201454%_))))))))))
          (let* ((_%$%e201407201417%_ _%stx201403%_)
                 (_%$%E201409201421%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; expand-syntax expects a single argument"
                       _%stx201403%_))))
                 (_%$%E201408201443%_
                  (lambda ()
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%e201407201417%_))
                        (let ((_%$%e201410201425%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%e201407201417%_))))
                          (let ((_%$%hd201411201428%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e201410201425%_)))
                                (_%$%tl201412201430%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e201410201425%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl201412201430%_))
                                (let ((_%$%e201413201433%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl201412201430%_))))
                                  (let ((_%$%hd201414201436%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e201413201433%_)))
                                        (_%$%tl201415201438%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e201413201433%_))))
                                    (let ((_%form201441%_
                                           _%$%hd201414201436%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl201415201438%_))
                                          (let ((__tmp201987
                                                 (_%generate201405%_
                                                  (_%parse201406%_
                                                   _%form201441%_)))
                                                (__tmp201986
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-source
                                                    _%stx201403%_))))
                                            (declare (not safe))
                                            (gx#stx-wrap-source
                                             __tmp201987
                                             __tmp201986))
                                          (_%$%E201409201421%_)))))
                                (_%$%E201409201421%_))))
                        (_%$%E201409201421%_)))))
            (_%$%E201408201443%_)))))
    (define gx#macro-expand-syntax-case__%
      (lambda (_%stx200652%_
               _%identifier=?200653%_
               _%unwrap-e200654%_
               _%wrap-e200655%_)
        (letrec ((_%generate-bindings200657%_
                  (lambda (_%target201267%_
                           _%ids201268%_
                           _%clauses201269%_
                           _%clause-ids201270%_
                           _%E201271%_)
                    (letrec ((_%generate1201273%_
                              (lambda (_%clause201370%_
                                       _%clause-id201371%_
                                       _%E201372%_)
                                (cons (cons _%clause-id201371%_ '())
                                      (cons (let ((__tmp201989
                                                   (cons _%target201267%_ '()))
                                                  (__tmp201988
                                                   (_%generate-clause200659%_
                                                    _%target201267%_
                                                    _%ids201268%_
                                                    _%clause201370%_
                                                    _%E201372%_)))
                                              (declare (not safe))
                                              (gx#core-list
                                               'lambda%
                                               __tmp201989
                                               __tmp201988))
                                            '())))))
                      (let _%lp201275%_ ((_%rest201277%_ _%clauses201269%_)
                                         (_%rest-ids201278%_
                                          _%clause-ids201270%_)
                                         (_%bindings201279%_ '()))
                        (let* ((_%$%rest201280201288%_ _%rest201277%_)
                               (_%$%else201282201296%_
                                (lambda () _%bindings201279%_))
                               (_%$%K201284201358%_
                                (lambda (_%rest201299%_ _%clause201300%_)
                                  (let* ((_%$%rest-ids201301201308%_
                                          _%rest-ids201278%_)
                                         (_%$%E201303201312%_
                                          (lambda ()
                                            (let ()
                                              (declare (not safe))
                                              (error '"No clause matching"
                                                     _%$%rest-ids201301201308%_
                                                     '([clause-id
                                                        .
                                                        rest-ids])))
                                            '#!void))
                                         (_%$%K201304201346%_
                                          (lambda (_%rest-ids201315%_
                                                   _%clause-id201316%_)
                                            (let* ((_%$%rest-ids201317201325%_
                                                    _%rest-ids201315%_)
                                                   (_%$%else201319201333%_
                                                    (lambda ()
                                                      (cons (_%generate1201273%_
                                                             _%clause201300%_
                                                             _%clause-id201316%_
                                                             _%E201271%_)
                                                            _%bindings201279%_)))
                                                   (_%$%K201321201338%_
                                                    (lambda (_%next-clause-id201336%_)
                                                      (_%lp201275%_
                                                       _%rest201299%_
                                                       _%rest-ids201315%_
                                                       (cons (_%generate1201273%_
                                                              _%clause201300%_
                                                              _%clause-id201316%_
                                                              _%next-clause-id201336%_)
                                                             _%bindings201279%_)))))
                                              (if (pair? _%$%rest-ids201317201325%_)
                                                  (let* ((_%$%hd201322201341%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%rest-ids201317201325%_)))
                                                         (_%next-clause-id201344%_
                                                          _%$%hd201322201341%_))
                                                    (_%$%K201321201338%_
                                                     _%next-clause-id201344%_))
                                                  (_%$%else201319201333%_))))))
                                    (if (pair? _%$%rest-ids201301201308%_)
                                        (let ((_%$%hd201305201349%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%rest-ids201301201308%_)))
                                              (_%$%tl201306201351%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%rest-ids201301201308%_))))
                                          (let* ((_%clause-id201354%_
                                                  _%$%hd201305201349%_)
                                                 (_%rest-ids201356%_
                                                  _%$%tl201306201351%_))
                                            (_%$%K201304201346%_
                                             _%rest-ids201356%_
                                             _%clause-id201354%_)))
                                        (_%$%E201303201312%_))))))
                          (if (pair? _%$%rest201280201288%_)
                              (let ((_%$%hd201285201361%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest201280201288%_)))
                                    (_%$%tl201286201363%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest201280201288%_))))
                                (let* ((_%clause201366%_ _%$%hd201285201361%_)
                                       (_%rest201368%_ _%$%tl201286201363%_))
                                  (_%$%K201284201358%_
                                   _%rest201368%_
                                   _%clause201366%_)))
                              (_%$%else201282201296%_)))))))
                 (_%generate-body200658%_
                  (lambda (_%bindings201227%_ _%body201228%_)
                    (let _%recur201230%_ ((_%rest201232%_ _%bindings201227%_))
                      (let* ((_%$%rest201233201241%_ _%rest201232%_)
                             (_%$%else201235201249%_
                              (lambda () _%body201228%_))
                             (_%$%K201237201255%_
                              (lambda (_%rest201252%_ _%hd201253%_)
                                (let ((__tmp201991 (cons _%hd201253%_ '()))
                                      (__tmp201990
                                       (_%recur201230%_ _%rest201252%_)))
                                  (declare (not safe))
                                  (gx#core-list
                                   'let-values
                                   __tmp201991
                                   __tmp201990)))))
                        (if (pair? _%$%rest201233201241%_)
                            (let ((_%$%hd201238201258%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest201233201241%_)))
                                  (_%$%tl201239201260%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest201233201241%_))))
                              (let* ((_%hd201263%_ _%$%hd201238201258%_)
                                     (_%rest201265%_ _%$%tl201239201260%_))
                                (_%$%K201237201255%_
                                 _%rest201265%_
                                 _%hd201263%_)))
                            (_%$%else201235201249%_))))))
                 (_%generate-clause200659%_
                  (lambda (_%target201090%_
                           _%ids201091%_
                           _%clause201092%_
                           _%E201093%_)
                    (letrec ((_%generate1201095%_
                              (lambda (_%hd201182%_
                                       _%fender201183%_
                                       _%body201184%_)
                                (let ((_g201992_
                                       (_%parse-clause200661%_
                                        _%hd201182%_
                                        _%ids201091%_)))
                                  (begin
                                    (let ((_g201993_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g201992_)
                                                 (##values-length _g201992_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g201993_ 2)))
                                          (error "Context expects 2 values"
                                                 _g201993_)))
                                    (let ((_%e201186%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g201992_ 0)))
                                          (_%mvars201187%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g201992_ 1))))
                                      (let* ((_%pvars201189%_
                                              (map gx#syntax-local-rewrap
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#gentemps
                                                      _%mvars201187%_))))
                                             (_%E201191%_
                                              (cons _%E201093%_
                                                    (cons _%target201090%_
                                                          '())))
                                             (_%K201224%_
                                              (let ((__tmp201994
                                                     (let ((__tmp201996
                                                            (map (lambda (_%mvar201193%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  _%pvar201194%_)
                           (let* ((_%$%mvar201195201202%_ _%mvar201193%_)
                                  (_%$%E201197201206%_
                                   (lambda ()
                                     (let ()
                                       (declare (not safe))
                                       (error '"No clause matching"
                                              _%$%mvar201195201202%_
                                              '([id . depth])))
                                     '#!void))
                                  (_%$%K201198201212%_
                                   (lambda (_%depth201209%_ _%id201210%_)
                                     (cons _%id201210%_
                                           (cons (let ((__tmp201998
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#core-list
                                                           'quote
                                                           _%id201210%_)))
                                                       (__tmp201997
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#core-list
                                                           'quote
                                                           _%pvar201194%_))))
                                                   (declare (not safe))
                                                   (gx#core-list
                                                    'make-syntax-pattern
                                                    __tmp201998
                                                    __tmp201997
                                                    _%depth201209%_))
                                                 '())))))
                             (if (pair? _%$%mvar201195201202%_)
                                 (let ((_%$%hd201199201215%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%mvar201195201202%_)))
                                       (_%$%tl201200201217%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%mvar201195201202%_))))
                                   (let* ((_%id201220%_ _%$%hd201199201215%_)
                                          (_%depth201222%_
                                           _%$%tl201200201217%_))
                                     (_%$%K201198201212%_
                                      _%depth201222%_
                                      _%id201220%_)))
                                 (_%$%E201197201206%_))))
                         _%mvars201187%_
                         _%pvars201189%_))
                   (__tmp201995
                    (if (eq? _%fender201183%_ '#t)
                        _%body201184%_
                        (let ()
                          (declare (not safe))
                          (gx#core-list
                           'if
                           _%fender201183%_
                           _%body201184%_
                           _%E201191%_)))))
               (declare (not safe))
               (gx#core-list 'let-syntax __tmp201996 __tmp201995))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (declare (not safe))
                                                (gx#core-list
                                                 'lambda%
                                                 _%pvars201189%_
                                                 __tmp201994))))
                                        (_%generate-match200660%_
                                         _%hd201182%_
                                         _%target201090%_
                                         _%e201186%_
                                         _%mvars201187%_
                                         _%K201224%_
                                         _%E201191%_))))))))
                      (let* ((_%$%e201096201116%_ _%clause201092%_)
                             (_%$%E201105201120%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid syntax-case clause"
                                   _%$%e201096201116%_))))
                             (_%$%E201098201154%_
                              (lambda ()
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%e201096201116%_))
                                    (let ((_%$%e201106201124%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-e
                                              _%$%e201096201116%_))))
                                      (let ((_%$%hd201107201127%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e201106201124%_)))
                                            (_%$%tl201108201129%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e201106201124%_))))
                                        (let ((_%hd201132%_
                                               _%$%hd201107201127%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl201108201129%_))
                                              (let ((_%$%e201109201134%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl201108201129%_))))
                                                (let ((_%$%hd201110201137%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e201109201134%_)))
                                                      (_%$%tl201111201139%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e201109201134%_))))
                                                  (let ((_%fender201142%_
                                                         _%$%hd201110201137%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl201111201139%_))
                                                        (let ((_%$%e201112201144%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%tl201111201139%_))))
                  (let ((_%$%hd201113201147%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e201112201144%_)))
                        (_%$%tl201114201149%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e201112201144%_))))
                    (let ((_%body201152%_ _%$%hd201113201147%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl201114201149%_))
                          (_%generate1201095%_
                           _%hd201132%_
                           _%fender201142%_
                           _%body201152%_)
                          (_%$%E201105201120%_)))))
                (_%$%E201105201120%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E201105201120%_)))))
                                    (_%$%E201105201120%_))))
                             (_%$%E201097201178%_
                              (lambda ()
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%e201096201116%_))
                                    (let ((_%$%e201099201158%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-e
                                              _%$%e201096201116%_))))
                                      (let ((_%$%hd201100201161%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e201099201158%_)))
                                            (_%$%tl201101201163%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e201099201158%_))))
                                        (let ((_%hd201166%_
                                               _%$%hd201100201161%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl201101201163%_))
                                              (let ((_%$%e201102201168%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl201101201163%_))))
                                                (let ((_%$%hd201103201171%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e201102201168%_)))
                                                      (_%$%tl201104201173%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e201102201168%_))))
                                                  (let ((_%body201176%_
                                                         _%$%hd201103201171%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl201104201173%_))
                                                        (_%generate1201095%_
                                                         _%hd201166%_
                                                         '#t
                                                         _%body201176%_)
                                                        (_%$%E201098201154%_)))))
                                              (_%$%E201098201154%_)))))
                                    (_%$%E201098201154%_)))))
                        (_%$%E201097201178%_)))))
                 (_%generate-match200660%_
                  (lambda (_%where200839%_
                           _%target200840%_
                           _%hd200841%_
                           _%mvars200842%_
                           _%K200843%_
                           _%E200844%_)
                    (letrec ((_%BUG200846%_
                              (lambda (_%q201088%_)
                                (let ()
                                  (declare (not safe))
                                  (error '"BUG: syntax-case; generate"
                                         _%stx200652%_
                                         _%hd200841%_
                                         _%q201088%_))))
                             (_%recur200847%_
                              (lambda (_%e200938%_
                                       _%vars200939%_
                                       _%target200940%_
                                       _%E200941%_
                                       _%k200942%_)
                                (let* ((_%$%e200943200950%_ _%e200938%_)
                                       (_%$%E200945200954%_
                                        (lambda ()
                                          (let ()
                                            (declare (not safe))
                                            (error '"No clause matching"
                                                   _%$%e200943200950%_
                                                   '([tag . body])))
                                          '#!void))
                                       (_%$%K200946201076%_
                                        (lambda (_%body200957%_ _%tag200958%_)
                                          (let ((_%$e200960%_ _%tag200958%_))
                                            (if (eq? 'any _%$e200960%_)
                                                (_%k200942%_ _%vars200939%_)
                                                (if (eq? 'id _%$e200960%_)
                                                    (let ((__tmp202003
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#core-list
                                                              'identifier?
                                                              _%target200940%_)))
                                                          (__tmp201999
                                                           (let ((__tmp202001
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ((__tmp202002
                                 (let ()
                                   (declare (not safe))
                                   (gx#core-list
                                    _%wrap-e200655%_
                                    _%body200957%_))))
                            (declare (not safe))
                            (gx#core-list
                             _%identifier=?200653%_
                             __tmp202002
                             _%target200940%_)))
                         (__tmp202000 (_%k200942%_ _%vars200939%_)))
                     (declare (not safe))
                     (gx#core-list 'if __tmp202001 __tmp202000 _%E200941%_))))
              (declare (not safe))
              (gx#core-list 'if __tmp202003 __tmp201999 _%E200941%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (eq? 'var _%$e200960%_)
                                                        (_%k200942%_
                                                         (cons (cons _%body200957%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%target200940%_)
                       _%vars200939%_))
                (if (eq? 'cons _%$e200960%_)
                    (let ((_%$e200963%_
                           (let () (declare (not safe)) (gx#genident__1 'e)))
                          (_%$hd200964%_
                           (let () (declare (not safe)) (gx#genident__1 'hd)))
                          (_%$tl200965%_
                           (let () (declare (not safe)) (gx#genident__1 'tl))))
                      (let ((__tmp202009
                             (let ()
                               (declare (not safe))
                               (gx#core-list 'stx-pair? _%target200940%_)))
                            (__tmp202004
                             (let ((__tmp202008
                                    (cons (cons (cons _%$e200963%_ '())
                                                (cons (let ()
                                                        (declare (not safe))
                                                        (gx#core-list
                                                         _%unwrap-e200654%_
                                                         _%target200940%_))
                                                      '()))
                                          '()))
                                   (__tmp202005
                                    (let ((__tmp202007
                                           (cons (cons (cons _%$hd200964%_ '())
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#core-list '##car _%$e200963%_))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (cons _%$tl200965%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())
                     (cons (let ()
                             (declare (not safe))
                             (gx#core-list '##cdr _%$e200963%_))
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (__tmp202006
                                           (let* ((_%$%body200966200973%_
                                                   _%body200957%_)
                                                  (_%$%E200968200977%_
                                                   (lambda ()
                                                     (let ()
                                                       (declare (not safe))
                                                       (error '"No clause matching"
                                                              _%$%body200966200973%_
                                                              '([hd . tl])))
                                                     '#!void))
                                                  (_%$%K200969200985%_
                                                   (lambda (_%tl200980%_
                                                            _%hd200981%_)
                                                     (_%recur200847%_
                                                      _%hd200981%_
                                                      _%vars200939%_
                                                      _%$hd200964%_
                                                      _%E200941%_
                                                      (lambda (_%vars200983%_)
                                                        (_%recur200847%_
                                                         _%tl200980%_
                                                         _%vars200983%_
                                                         _%$tl200965%_
                                                         _%E200941%_
                                                         _%k200942%_))))))
                                             (if (pair? _%$%body200966200973%_)
                                                 (let ((_%$%hd200970200988%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%body200966200973%_)))
                                                       (_%$%tl200971200990%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%body200966200973%_))))
                                                   (let* ((_%hd200993%_
                                                           _%$%hd200970200988%_)
                                                          (_%tl200995%_
                                                           _%$%tl200971200990%_))
                                                     (_%$%K200969200985%_
                                                      _%tl200995%_
                                                      _%hd200993%_)))
                                                 (_%$%E200968200977%_)))))
                                      (declare (not safe))
                                      (gx#core-list
                                       'let-values
                                       __tmp202007
                                       __tmp202006))))
                               (declare (not safe))
                               (gx#core-list
                                'let-values
                                __tmp202008
                                __tmp202005))))
                        (declare (not safe))
                        (gx#core-list
                         'if
                         __tmp202009
                         __tmp202004
                         _%E200941%_)))
                    (if (eq? 'splice _%$e200960%_)
                        (let* ((_%$%body200996201003%_ _%body200957%_)
                               (_%$%E200998201007%_
                                (lambda ()
                                  (let ()
                                    (declare (not safe))
                                    (error '"No clause matching"
                                           _%$%body200996201003%_
                                           '([hd . tl])))
                                  '#!void))
                               (_%$%K200999201058%_
                                (lambda (_%tl201010%_ _%hd201011%_)
                                  (let* ((_%rlen201013%_
                                          (_%splice-rlen200848%_ _%tl201010%_))
                                         (_%$target201015%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'target)))
                                         (_%$hd201017%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'hd)))
                                         (_%$tl201019%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'tl)))
                                         (_%$lp201021%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'loop)))
                                         (_%$lp-e201023%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'e)))
                                         (_%$lp-hd201025%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'lp-hd)))
                                         (_%$lp-tl201027%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#genident__1 'lp-tl)))
                                         (_%svars201029%_
                                          (_%splice-vars200849%_ _%hd201011%_))
                                         (_%lvars201031%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#gentemps _%svars201029%_)))
                                         (_%tlvars201033%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#gentemps _%svars201029%_)))
                                         (_%linit201037%_
                                          (map (lambda (_%var201035%_)
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#core-list 'quote '())))
                                               _%lvars201031%_)))
                                    (letrec ((_%make-loop201040%_
                                              (lambda (_%vars201044%_)
                                                (let ((__tmp202011
                                                       (cons (cons (cons _%$lp201021%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 '())
                           (cons (let ((__tmp202024
                                        (cons _%$hd201017%_ _%lvars201031%_))
                                       (__tmp202012
                                        (let ((__tmp202023
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#core-list
                                                  'stx-pair?
                                                  _%$hd201017%_)))
                                              (__tmp202017
                                               (let ((__tmp202022
                                                      (cons (cons (cons _%$lp-e201023%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                '())
                          (cons (let ()
                                  (declare (not safe))
                                  (gx#core-list
                                   _%unwrap-e200654%_
                                   _%$hd201017%_))
                                '()))
                    '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (__tmp202018
                                                      (let ((__tmp202021
                                                             (cons (cons (cons _%$lp-hd201025%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                       '())
                                 (cons (let ()
                                         (declare (not safe))
                                         (gx#core-list '##car _%$lp-e201023%_))
                                       '()))
                           (cons (cons (cons _%$lp-tl201027%_ '())
                                       (cons (let ()
                                               (declare (not safe))
                                               (gx#core-list
                                                '##cdr
                                                _%$lp-e201023%_))
                                             '()))
                                 '())))
                    (__tmp202019
                     (_%recur200847%_
                      _%hd201011%_
                      '()
                      _%$lp-hd201025%_
                      _%E200941%_
                      (lambda (_%hdvars201046%_)
                        (cons _%$lp201021%_
                              (cons _%$lp-tl201027%_
                                    (map (lambda (_%svar201048%_
                                                  _%lvar201049%_)
                                           (let ((__tmp202020
                                                  (let ()
                                                    (declare (not safe))
                                                    (agetq__%
                                                     _%svar201048%_
                                                     _%hdvars201046%_
                                                     _%BUG200846%_))))
                                             (declare (not safe))
                                             (gx#core-list
                                              'cons
                                              __tmp202020
                                              _%lvar201049%_)))
                                         _%svars201029%_
                                         _%lvars201031%_)))))))
                (declare (not safe))
                (gx#core-list 'let-values __tmp202021 __tmp202019))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (declare (not safe))
                                                 (gx#core-list
                                                  'let-values
                                                  __tmp202022
                                                  __tmp202018)))
                                              (__tmp202013
                                               (let ((__tmp202016
                                                      (map (lambda (_%lvar201051%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%tlvar201052%_)
                     (cons (cons _%tlvar201052%_ '())
                           (cons (let ()
                                   (declare (not safe))
                                   (gx#core-list 'reverse _%lvar201051%_))
                                 '())))
                   _%lvars201031%_
                   _%tlvars201033%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (__tmp202014
                                                      (_%k200942%_
                                                       (let ((__tmp202015
                                                              (lambda (_%svar201054%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               _%tlvar201055%_
                               _%r201056%_)
                        (cons (cons _%svar201054%_ _%tlvar201055%_)
                              _%r201056%_))))
                 (declare (not safe))
                 (foldl__1
                  __tmp202015
                  _%vars201044%_
                  _%svars201029%_
                  _%tlvars201033%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (declare (not safe))
                                                 (gx#core-list
                                                  'let-values
                                                  __tmp202016
                                                  __tmp202014))))
                                          (declare (not safe))
                                          (gx#core-list
                                           'if
                                           __tmp202023
                                           __tmp202017
                                           __tmp202013))))
                                   (declare (not safe))
                                   (gx#core-list
                                    'lambda%
                                    __tmp202024
                                    __tmp202012))
                                 '()))
                     '()))
              (__tmp202010
               (cons _%$lp201021%_ (cons _%$target201015%_ _%linit201037%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gx#core-list
                                                   'letrec-values
                                                   __tmp202011
                                                   __tmp202010)))))
                                      (let ((_%body201042%_
                                             (let ((__tmp202026
                                                    (cons (cons (cons _%$target201015%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%$tl201019%_ '()))
                        (cons (let ()
                                (declare (not safe))
                                (gx#core-list
                                 'syntax-split-splice
                                 _%target200940%_
                                 _%rlen201013%_))
                              '()))
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (__tmp202025
                                                    (_%recur200847%_
                                                     _%tl201010%_
                                                     _%vars200939%_
                                                     _%$tl201019%_
                                                     _%E200941%_
                                                     _%make-loop201040%_)))
                                               (declare (not safe))
                                               (gx#core-list
                                                'let-values
                                                __tmp202026
                                                __tmp202025))))
                                        (let ((__tmp202030
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#core-list
                                                  'stx-pair/null?
                                                  _%target200940%_)))
                                              (__tmp202027
                                               (if (zero? _%rlen201013%_)
                                                   _%body201042%_
                                                   (let ((__tmp202028
                                                          (let ((__tmp202029
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#core-list 'stx-length _%target200940%_))))
                    (declare (not safe))
                    (gx#core-list 'fx>= __tmp202029 _%rlen201013%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (gx#core-list
                                                      'if
                                                      __tmp202028
                                                      _%body201042%_
                                                      _%E200941%_)))))
                                          (declare (not safe))
                                          (gx#core-list
                                           'if
                                           __tmp202030
                                           __tmp202027
                                           _%E200941%_))))))))
                          (if (pair? _%$%body200996201003%_)
                              (let ((_%$%hd201000201061%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%body200996201003%_)))
                                    (_%$%tl201001201063%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%body200996201003%_))))
                                (let* ((_%hd201066%_ _%$%hd201000201061%_)
                                       (_%tl201068%_ _%$%tl201001201063%_))
                                  (_%$%K200999201058%_
                                   _%tl201068%_
                                   _%hd201066%_)))
                              (_%$%E200998201007%_)))
                        (if (eq? 'null _%$e200960%_)
                            (let ((__tmp202032
                                   (let ()
                                     (declare (not safe))
                                     (gx#core-list
                                      'stx-null?
                                      _%target200940%_)))
                                  (__tmp202031 (_%k200942%_ _%vars200939%_)))
                              (declare (not safe))
                              (gx#core-list
                               'if
                               __tmp202032
                               __tmp202031
                               _%E200941%_))
                            (if (eq? 'vector _%$e200960%_)
                                (let ((_%$e201070%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#genident__1 'e))))
                                  (let ((__tmp202037
                                         (let ()
                                           (declare (not safe))
                                           (gx#core-list
                                            'stx-vector?
                                            _%target200940%_)))
                                        (__tmp202033
                                         (let ((__tmp202035
                                                (cons (cons (cons _%$e201070%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '())
                    (cons (let ((__tmp202036
                                 (let ()
                                   (declare (not safe))
                                   (gx#core-list
                                    _%unwrap-e200654%_
                                    _%target200940%_))))
                            (declare (not safe))
                            (gx#core-list 'vector->list __tmp202036))
                          '()))
              '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (__tmp202034
                                                (_%recur200847%_
                                                 _%body200957%_
                                                 _%vars200939%_
                                                 _%$e201070%_
                                                 _%E200941%_
                                                 _%k200942%_)))
                                           (declare (not safe))
                                           (gx#core-list
                                            'let-values
                                            __tmp202035
                                            __tmp202034))))
                                    (declare (not safe))
                                    (gx#core-list
                                     'if
                                     __tmp202037
                                     __tmp202033
                                     _%E200941%_)))
                                (if (eq? 'box _%$e200960%_)
                                    (let ((_%$e201072%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#genident__1 'e))))
                                      (let ((__tmp202042
                                             (let ()
                                               (declare (not safe))
                                               (gx#core-list
                                                'stx-box?
                                                _%target200940%_)))
                                            (__tmp202038
                                             (let ((__tmp202040
                                                    (cons (cons (cons _%$e201072%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '())
                        (cons (let ((__tmp202041
                                     (let ()
                                       (declare (not safe))
                                       (gx#core-list
                                        _%unwrap-e200654%_
                                        _%target200940%_))))
                                (declare (not safe))
                                (gx#core-list 'unbox __tmp202041))
                              '()))
                  '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (__tmp202039
                                                    (_%recur200847%_
                                                     _%body200957%_
                                                     _%vars200939%_
                                                     _%$e201072%_
                                                     _%E200941%_
                                                     _%k200942%_)))
                                               (declare (not safe))
                                               (gx#core-list
                                                'let-values
                                                __tmp202040
                                                __tmp202039))))
                                        (declare (not safe))
                                        (gx#core-list
                                         'if
                                         __tmp202042
                                         __tmp202038
                                         _%E200941%_)))
                                    (if (eq? 'datum _%$e200960%_)
                                        (let ((_%$e201074%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#genident__1 'e))))
                                          (let ((__tmp202048
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#core-list
                                                    'stx-datum?
                                                    _%target200940%_)))
                                                (__tmp202043
                                                 (let ((__tmp202047
                                                        (cons (cons (cons _%$e201074%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  '())
                            (cons (let ()
                                    (declare (not safe))
                                    (gx#core-list 'stx-e _%target200940%_))
                                  '()))
                      '()))
               (__tmp202044
                (let ((__tmp202046
                       (let ()
                         (declare (not safe))
                         (gx#core-list 'equal? _%$e201074%_ _%body200957%_)))
                      (__tmp202045 (_%k200942%_ _%vars200939%_)))
                  (declare (not safe))
                  (gx#core-list 'if __tmp202046 __tmp202045 _%E200941%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (declare (not safe))
                                                   (gx#core-list
                                                    'let-values
                                                    __tmp202047
                                                    __tmp202044))))
                                            (declare (not safe))
                                            (gx#core-list
                                             'if
                                             __tmp202048
                                             __tmp202043
                                             _%E200941%_)))
                                        (_%BUG200846%_
                                         _%e200938%_))))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  (if (pair? _%$%e200943200950%_)
                                      (let ((_%$%hd200947201079%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e200943200950%_)))
                                            (_%$%tl200948201081%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e200943200950%_))))
                                        (let* ((_%tag201084%_
                                                _%$%hd200947201079%_)
                                               (_%body201086%_
                                                _%$%tl200948201081%_))
                                          (_%$%K200946201076%_
                                           _%body201086%_
                                           _%tag201084%_)))
                                      (_%$%E200945200954%_)))))
                             (_%splice-rlen200848%_
                              (lambda (_%e200900%_)
                                (let _%lp200902%_ ((_%e200904%_ _%e200900%_)
                                                   (_%n200905%_ '0))
                                  (let* ((_%$%e200906200913%_ _%e200904%_)
                                         (_%$%E200908200917%_
                                          (lambda ()
                                            (let ()
                                              (declare (not safe))
                                              (error '"No clause matching"
                                                     _%$%e200906200913%_
                                                     '([tag . body])))
                                            '#!void))
                                         (_%$%K200909200926%_
                                          (lambda (_%body200920%_
                                                   _%tag200921%_)
                                            (let ((_%$e200923%_ _%tag200921%_))
                                              (if (eq? 'splice _%$e200923%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#raise-syntax-error
                                                     '#f
                                                     '"Ambiguous pattern"
                                                     _%stx200652%_
                                                     _%where200839%_))
                                                  (if (eq? 'cons _%$e200923%_)
                                                      (_%lp200902%_
                                                       (cdr _%body200920%_)
                                                       (let ()
                                                         (declare (not safe))
                                                         (##fx+ _%n200905%_
                                                                '1)))
                                                      _%n200905%_))))))
                                    (if (pair? _%$%e200906200913%_)
                                        (let ((_%$%hd200910200929%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e200906200913%_)))
                                              (_%$%tl200911200931%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e200906200913%_))))
                                          (let* ((_%tag200934%_
                                                  _%$%hd200910200929%_)
                                                 (_%body200936%_
                                                  _%$%tl200911200931%_))
                                            (_%$%K200909200926%_
                                             _%body200936%_
                                             _%tag200934%_)))
                                        (_%$%E200908200917%_))))))
                             (_%splice-vars200849%_
                              (lambda (_%e200856%_)
                                (let _%recur200858%_ ((_%e200860%_ _%e200856%_)
                                                      (_%vars200861%_ '()))
                                  (let* ((_%$%e200862200869%_ _%e200860%_)
                                         (_%$%E200864200873%_
                                          (lambda ()
                                            (let ()
                                              (declare (not safe))
                                              (error '"No clause matching"
                                                     _%$%e200862200869%_
                                                     '([tag . body])))
                                            '#!void))
                                         (_%$%K200865200888%_
                                          (lambda (_%body200876%_
                                                   _%tag200877%_)
                                            (let ((_%$e200879%_ _%tag200877%_))
                                              (if (eq? 'var _%$e200879%_)
                                                  (cons _%body200876%_
                                                        _%vars200861%_)
                                                  (if (or (eq? 'cons
                                                               _%$e200879%_)
                                                          (eq? 'splice
                                                               _%$e200879%_))
                                                      (_%recur200858%_
                                                       (cdr _%body200876%_)
                                                       (_%recur200858%_
                                                        (car _%body200876%_)
                                                        _%vars200861%_))
                                                      (if (or (eq? 'vector
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$e200879%_)
                      (eq? 'box _%$e200879%_))
                  (_%recur200858%_ _%body200876%_ _%vars200861%_)
                  _%vars200861%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (if (pair? _%$%e200862200869%_)
                                        (let ((_%$%hd200866200891%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e200862200869%_)))
                                              (_%$%tl200867200893%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e200862200869%_))))
                                          (let* ((_%tag200896%_
                                                  _%$%hd200866200891%_)
                                                 (_%body200898%_
                                                  _%$%tl200867200893%_))
                                            (_%$%K200865200888%_
                                             _%body200898%_
                                             _%tag200896%_)))
                                        (_%$%E200864200873%_))))))
                             (_%make-body200850%_
                              (lambda (_%vars200852%_)
                                (cons _%K200843%_
                                      (map (lambda (_%mvar200854%_)
                                             (let ((__tmp202049
                                                    (car _%mvar200854%_)))
                                               (declare (not safe))
                                               (agetq__%
                                                __tmp202049
                                                _%vars200852%_
                                                _%BUG200846%_)))
                                           _%mvars200842%_)))))
                      (_%recur200847%_
                       _%hd200841%_
                       '()
                       _%target200840%_
                       _%E200844%_
                       _%make-body200850%_))))
                 (_%parse-clause200661%_
                  (lambda (_%hd200733%_ _%ids200734%_)
                    (let _%recur200736%_ ((_%e200738%_ _%hd200733%_)
                                          (_%vars200739%_ '())
                                          (_%depth200740%_ '0))
                      (if (let ()
                            (declare (not safe))
                            (gx#identifier? _%e200738%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#underscore? _%e200738%_))
                              (values '(any) _%vars200739%_)
                              (if (let ()
                                    (declare (not safe))
                                    (gx#ellipsis? _%e200738%_))
                                  (let ()
                                    (declare (not safe))
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Misplaced ellipsis"
                                     _%stx200652%_
                                     _%hd200733%_))
                                  (if (let ((__tmp202050
                                             (lambda (_%id200745%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#bound-identifier=?
                                                  _%e200738%_
                                                  _%id200745%_)))))
                                        (declare (not safe))
                                        (__find __tmp202050 _%ids200734%_))
                                      (values (cons 'id _%e200738%_)
                                              _%vars200739%_)
                                      (if (let ((__tmp202051
                                                 (lambda (_%var200748%_)
                                                   (let ((__tmp202052
                                                          (car _%var200748%_)))
                                                     (declare (not safe))
                                                     (gx#bound-identifier=?
                                                      _%e200738%_
                                                      __tmp202052)))))
                                            (declare (not safe))
                                            (__find __tmp202051
                                                    _%vars200739%_))
                                          (let ()
                                            (declare (not safe))
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Duplicate pattern variable"
                                             _%stx200652%_
                                             _%e200738%_))
                                          (values (cons 'var _%e200738%_)
                                                  (cons (cons _%e200738%_
                                                              _%depth200740%_)
                                                        _%vars200739%_))))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%e200738%_))
                              (let* ((_%$%e200752200759%_ _%e200738%_)
                                     (_%$%E200754200763%_
                                      (lambda ()
                                        (let ()
                                          (declare (not safe))
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid syntax-case clause"
                                           _%$%e200752200759%_))))
                                     (_%$%E200753200824%_
                                      (lambda ()
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%e200752200759%_))
                                            (let ((_%$%e200755200767%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-e
                                                      _%$%e200752200759%_))))
                                              (let ((_%$%hd200756200770%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e200755200767%_)))
                                                    (_%$%tl200757200772%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e200755200767%_))))
                                                (let* ((_%hd200775%_
                                                        _%$%hd200756200770%_)
                                                       (_%rest200777%_
                                                        _%$%tl200757200772%_)
                                                       (_%make-pair200792%_
                                                        (lambda (_%tag200779%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%hd200780%_
                         _%tl200781%_)
                  (let* ((_%hd-depth200783%_
                          (if (eq? _%tag200779%_ 'splice)
                              (let ()
                                (declare (not safe))
                                (##fx+ _%depth200740%_ '1))
                              _%depth200740%_))
                         (_g202053_
                          (_%recur200736%_
                           _%hd200780%_
                           _%vars200739%_
                           _%hd-depth200783%_)))
                    (begin
                      (let ((_g202054_
                             (let ()
                               (declare (not safe))
                               (if (##values? _g202053_)
                                   (##values-length _g202053_)
                                   1))))
                        (if (not (let ()
                                   (declare (not safe))
                                   (##fx= _g202054_ 2)))
                            (error "Context expects 2 values" _g202054_)))
                      (let ((_%hd200785%_
                             (let ()
                               (declare (not safe))
                               (##values-ref _g202053_ 0)))
                            (_%vars200786%_
                             (let ()
                               (declare (not safe))
                               (##values-ref _g202053_ 1))))
                        (let ((_g202055_
                               (_%recur200736%_
                                _%tl200781%_
                                _%vars200786%_
                                _%depth200740%_)))
                          (begin
                            (let ((_g202056_
                                   (let ()
                                     (declare (not safe))
                                     (if (##values? _g202055_)
                                         (##values-length _g202055_)
                                         1))))
                              (if (not (let ()
                                         (declare (not safe))
                                         (##fx= _g202056_ 2)))
                                  (error "Context expects 2 values"
                                         _g202056_)))
                            (let ((_%tl200788%_
                                   (let ()
                                     (declare (not safe))
                                     (##values-ref _g202055_ 0)))
                                  (_%vars200789%_
                                   (let ()
                                     (declare (not safe))
                                     (##values-ref _g202055_ 1))))
                              (values (cons _%tag200779%_
                                            (cons _%hd200785%_ _%tl200788%_))
                                      _%vars200789%_)))))))))
               (_%$%e200793200800%_ _%rest200777%_)
               (_%$%E200795200804%_
                (lambda ()
                  (_%make-pair200792%_ 'cons _%hd200775%_ _%rest200777%_)))
               (_%$%E200794200820%_
                (lambda ()
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%e200793200800%_))
                      (let ((_%$%e200796200808%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%e200793200800%_))))
                        (let ((_%$%hd200797200811%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e200796200808%_)))
                              (_%$%tl200798200813%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e200796200808%_))))
                          (let* ((_%rest-hd200816%_ _%$%hd200797200811%_)
                                 (_%rest-tl200818%_ _%$%tl200798200813%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#ellipsis? _%rest-hd200816%_))
                                (_%make-pair200792%_
                                 'splice
                                 _%hd200775%_
                                 _%rest-tl200818%_)
                                (_%make-pair200792%_
                                 'cons
                                 _%hd200775%_
                                 _%rest200777%_)))))
                      (_%$%E200795200804%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E200794200820%_))))
                                            (_%$%E200754200763%_)))))
                                (_%$%E200753200824%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%e200738%_))
                                  (values '(null) _%vars200739%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-vector? _%e200738%_))
                                      (let ((_g202057_
                                             (_%recur200736%_
                                              (vector->list
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-e _%e200738%_)))
                                              _%vars200739%_
                                              _%depth200740%_)))
                                        (begin
                                          (let ((_g202058_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g202057_)
                                                       (##values-length
                                                        _g202057_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g202058_ 2)))
                                                (error "Context expects 2 values"
                                                       _g202058_)))
                                          (let ((_%e200830%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g202057_ 0)))
                                                (_%vars200831%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g202057_
                                                    1))))
                                            (values (cons 'vector _%e200830%_)
                                                    _%vars200831%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-box? _%e200738%_))
                                          (let ((_g202059_
                                                 (_%recur200736%_
                                                  (unbox (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%e200738%_)))
                                                  _%vars200739%_
                                                  _%depth200740%_)))
                                            (begin
                                              (let ((_g202060_
                                                     (let ()
                                                       (declare (not safe))
                                                       (if (##values?
                                                            _g202059_)
                                                           (##values-length
                                                            _g202059_)
                                                           1))))
                                                (if (not (let ()
                                                           (declare (not safe))
                                                           (##fx= _g202060_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          2)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (error "Context expects 2 values"
                                                           _g202060_)))
                                              (let ((_%e200834%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##values-ref
                                                        _g202059_
                                                        0)))
                                                    (_%vars200835%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##values-ref
                                                        _g202059_
                                                        1))))
                                                (values (cons 'box _%e200834%_)
                                                        _%vars200835%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-datum? _%e200738%_))
                                              (values (cons 'datum
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%e200738%_)))
                                                      _%vars200739%_)
                                              (let ()
                                                (declare (not safe))
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Bad pattern"
                                                 _%stx200652%_
                                                 _%e200738%_))))))))))))
          (let* ((_%$%e200662200675%_ _%stx200652%_)
                 (_%$%E200664200679%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid syntax-case clause"
                       _%$%e200662200675%_))))
                 (_%$%E200663200729%_
                  (lambda ()
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%e200662200675%_))
                        (let ((_%$%e200665200683%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%e200662200675%_))))
                          (let ((_%$%hd200666200686%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e200665200683%_)))
                                (_%$%tl200667200688%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e200665200683%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl200667200688%_))
                                (let ((_%$%e200668200691%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl200667200688%_))))
                                  (let ((_%$%hd200669200694%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e200668200691%_)))
                                        (_%$%tl200670200696%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e200668200691%_))))
                                    (let ((_%expr200699%_
                                           _%$%hd200669200694%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl200670200696%_))
                                          (let ((_%$%e200671200701%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#syntax-e
                                                    _%$%tl200670200696%_))))
                                            (let ((_%$%hd200672200704%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e200671200701%_)))
                                                  (_%$%tl200673200706%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e200671200701%_))))
                                              (let* ((_%ids200709%_
                                                      _%$%hd200672200704%_)
                                                     (_%clauses200711%_
                                                      _%$%tl200673200706%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#identifier-list?
                                                       _%ids200709%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-list?
                                                           _%clauses200711%_))
                                                        (let* ((_%ids200716%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#syntax->list _%ids200709%_)))
                       (_%clauses200718%_
                        (let ()
                          (declare (not safe))
                          (gx#syntax->list _%clauses200711%_)))
                       (_%clause-ids200720%_
                        (let ()
                          (declare (not safe))
                          (gx#gentemps _%clauses200718%_)))
                       (_%E200722%_
                        (let () (declare (not safe)) (gx#genident__0)))
                       (_%target200724%_
                        (let () (declare (not safe)) (gx#genident__0)))
                       (_%first200726%_
                        (if (null? _%clauses200718%_)
                            _%E200722%_
                            (car _%clause-ids200720%_))))
                  (let ((__tmp202062
                         (let ((__tmp202063
                                (let ((__tmp202065
                                       (let ((__tmp202067
                                              (cons (cons (cons _%E200722%_
                                                                '())
                                                          (cons (let ((__tmp202069
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (cons _%target200724%_ '()))
                              (__tmp202068
                               (let ()
                                 (declare (not safe))
                                 (gx#core-list
                                  'raise-syntax-error
                                  '#f
                                  '"Bad syntax; invalid match target"
                                  _%target200724%_))))
                          (declare (not safe))
                          (gx#core-list 'lambda% __tmp202069 __tmp202068))
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '()))
                                             (__tmp202066
                                              (_%generate-body200658%_
                                               (_%generate-bindings200657%_
                                                _%target200724%_
                                                _%ids200716%_
                                                _%clauses200718%_
                                                _%clause-ids200720%_
                                                _%E200722%_)
                                               (cons _%first200726%_
                                                     (cons _%expr200699%_
                                                           '())))))
                                         (declare (not safe))
                                         (gx#core-list
                                          'let-values
                                          __tmp202067
                                          __tmp202066)))
                                      (__tmp202064
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-source _%stx200652%_))))
                                  (declare (not safe))
                                  (gx#stx-wrap-source
                                   __tmp202065
                                   __tmp202064))))
                           (declare (not safe))
                           (gx#core-list
                            'begin-annotation
                            '@syntax-case
                            __tmp202063)))
                        (__tmp202061
                         (let ()
                           (declare (not safe))
                           (gx#stx-source _%stx200652%_))))
                    (declare (not safe))
                    (gx#stx-wrap-source __tmp202062 __tmp202061)))
                (let ()
                  (declare (not safe))
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; clauses expected"
                   _%stx200652%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#raise-syntax-error
                                                       '#f
                                                       '"Bad template identifier list"
                                                       _%stx200652%_
                                                       _%ids200709%_))))))
                                          (_%$%E200664200679%_)))))
                                (_%$%E200664200679%_))))
                        (_%$%E200664200679%_)))))
            (_%$%E200663200729%_)))))
    (define gx#macro-expand-syntax-case__0
      (lambda (_%stx201377%_)
        (let* ((_%identifier=?201379%_ 'free-identifier=?)
               (_%unwrap-e201381%_ 'syntax-e)
               (_%wrap-e201383%_ 'quote-syntax))
          (gx#macro-expand-syntax-case__%
           _%stx201377%_
           _%identifier=?201379%_
           _%unwrap-e201381%_
           _%wrap-e201383%_))))
    (define gx#macro-expand-syntax-case__1
      (lambda (_%stx201385%_ _%identifier=?201386%_)
        (let* ((_%unwrap-e201388%_ 'syntax-e) (_%wrap-e201390%_ 'quote-syntax))
          (gx#macro-expand-syntax-case__%
           _%stx201385%_
           _%identifier=?201386%_
           _%unwrap-e201388%_
           _%wrap-e201390%_))))
    (define gx#macro-expand-syntax-case__2
      (lambda (_%stx201392%_ _%identifier=?201393%_ _%unwrap-e201394%_)
        (let ((_%wrap-e201396%_ 'quote-syntax))
          (gx#macro-expand-syntax-case__%
           _%stx201392%_
           _%identifier=?201393%_
           _%unwrap-e201394%_
           _%wrap-e201396%_))))
    (define gx#macro-expand-syntax-case
      (lambda _g202070_
        (let ((_g202071_ (let () (declare (not safe)) (##length _g202070_))))
          (cond ((let () (declare (not safe)) (##fx= _g202071_ 1))
                 (apply gx#macro-expand-syntax-case__0 _g202070_))
                ((let () (declare (not safe)) (##fx= _g202071_ 2))
                 (apply gx#macro-expand-syntax-case__1 _g202070_))
                ((let () (declare (not safe)) (##fx= _g202071_ 3))
                 (apply gx#macro-expand-syntax-case__2 _g202070_))
                ((let () (declare (not safe)) (##fx= _g202071_ 4))
                 (apply gx#macro-expand-syntax-case__% _g202070_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#macro-expand-syntax-case
                  _g202070_))))))
    (define gx#syntax-local-pattern?
      (lambda (_%stx200649%_)
        (if (let () (declare (not safe)) (gx#identifier? _%stx200649%_))
            (let ((__tmp202072
                   (let ()
                     (declare (not safe))
                     (gx#syntax-local-e__% _%stx200649%_ false))))
              (declare (not safe))
              (##structure-instance-of? __tmp202072 'gx#syntax-pattern::t))
            '#f)))
    (define gx#syntax-check-splice-targets
      (lambda (_%hd200607%_ . _%rest200608%_)
        (let ((_%len200610%_ (length _%hd200607%_)))
          (let _%lp200612%_ ((_%rest200614%_ _%rest200608%_))
            (let* ((_%$%rest200615200623%_ _%rest200614%_)
                   (_%$%else200617200631%_ (lambda () '#!void))
                   (_%$%K200619200637%_
                    (lambda (_%rest200634%_ _%hd200635%_)
                      (if (let ((__tmp202073 (length _%hd200635%_)))
                            (declare (not safe))
                            (##fx= _%len200610%_ __tmp202073))
                          (_%lp200612%_ _%rest200634%_)
                          (let ()
                            (declare (not safe))
                            (gx#raise-syntax-error
                             '#f
                             '"Splice length mismatch"
                             _%hd200635%_))))))
              (if (pair? _%$%rest200615200623%_)
                  (let ((_%$%hd200620200640%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest200615200623%_)))
                        (_%$%tl200621200642%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest200615200623%_))))
                    (let* ((_%hd200645%_ _%$%hd200620200640%_)
                           (_%rest200647%_ _%$%tl200621200642%_))
                      (_%$%K200619200637%_ _%rest200647%_ _%hd200645%_)))
                  '#!void))))))
    (define gx#syntax-split-splice
      (lambda (_%stx200557%_ _%n200558%_)
        (let _%lp200560%_ ((_%rest200563%_ _%stx200557%_) (_%r200565%_ '()))
          (if (let () (declare (not safe)) (gx#stx-pair? _%rest200563%_))
              (let* ((_%$%g200567200574%_
                      (let ()
                        (declare (not safe))
                        (gx#syntax-e _%rest200563%_)))
                     (_%$%E200569200578%_
                      (lambda ()
                        (let ()
                          (declare (not safe))
                          (error '"No clause matching"
                                 _%$%g200567200574%_
                                 '([hd . rest])))
                        '#!void))
                     (_%$%K200570200585%_
                      (lambda (_%rest200581%_ _%hd200582%_)
                        (_%lp200560%_
                         _%rest200581%_
                         (cons _%hd200582%_ _%r200565%_)))))
                (if (pair? _%$%g200567200574%_)
                    (let ((_%$%hd200571200588%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%g200567200574%_)))
                          (_%$%tl200572200590%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%g200567200574%_))))
                      (let* ((_%hd200593%_ _%$%hd200571200588%_)
                             (_%rest200595%_ _%$%tl200572200590%_))
                        (_%$%K200570200585%_ _%rest200595%_ _%hd200593%_)))
                    (_%$%E200569200578%_)))
              (let _%lp200597%_ ((_%n200599%_ _%n200558%_)
                                 (_%l200600%_ _%r200565%_)
                                 (_%r200602%_ _%rest200563%_))
                (if (null? _%l200600%_)
                    (values _%l200600%_ _%r200602%_)
                    (if (fxpositive? _%n200599%_)
                        (_%lp200597%_
                         (let () (declare (not safe)) (##fx- _%n200599%_ '1))
                         (cdr _%l200600%_)
                         (cons (car _%l200600%_) _%r200602%_))
                        (values (reverse! _%l200600%_) _%r200602%_))))))))
    (define gx#syntax-split-splice->vector
      (lambda (_%stx200507%_ _%n200508%_)
        (let _%lp200510%_ ((_%rest200513%_ _%stx200507%_) (_%r200515%_ '()))
          (if (let () (declare (not safe)) (gx#stx-pair? _%rest200513%_))
              (let* ((_%$%g200517200524%_
                      (let ()
                        (declare (not safe))
                        (gx#syntax-e _%rest200513%_)))
                     (_%$%E200519200528%_
                      (lambda ()
                        (let ()
                          (declare (not safe))
                          (error '"No clause matching"
                                 _%$%g200517200524%_
                                 '([hd . rest])))
                        '#!void))
                     (_%$%K200520200535%_
                      (lambda (_%rest200531%_ _%hd200532%_)
                        (_%lp200510%_
                         _%rest200531%_
                         (cons _%hd200532%_ _%r200515%_)))))
                (if (pair? _%$%g200517200524%_)
                    (let ((_%$%hd200521200538%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%g200517200524%_)))
                          (_%$%tl200522200540%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%g200517200524%_))))
                      (let* ((_%hd200543%_ _%$%hd200521200538%_)
                             (_%rest200545%_ _%$%tl200522200540%_))
                        (_%$%K200520200535%_ _%rest200545%_ _%hd200543%_)))
                    (_%$%E200519200528%_)))
              (let _%lp200547%_ ((_%n200549%_ _%n200508%_)
                                 (_%l200550%_ _%r200515%_)
                                 (_%r200552%_ _%rest200513%_))
                (if (null? _%l200550%_)
                    (vector _%l200550%_ _%r200552%_)
                    (if (fxpositive? _%n200549%_)
                        (_%lp200547%_
                         (let () (declare (not safe)) (##fx- _%n200549%_ '1))
                         (cdr _%l200550%_)
                         (cons (car _%l200550%_) _%r200552%_))
                        (vector (reverse! _%l200550%_) _%r200552%_))))))))))
