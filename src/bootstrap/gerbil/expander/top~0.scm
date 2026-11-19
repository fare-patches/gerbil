(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/top::timestamp 1795039816)
  (begin
    (declare (not safe))
    (define gx#core-expand-begin%
      (lambda (_%stx194077%_)
        (letrec ((_%expand-special194079%_
                  (lambda (_%hd194081%_ _%K194082%_ _%rest194083%_ _%r194084%_)
                    (_%K194082%_
                     _%rest194083%_
                     (cons (gx#core-expand-top _%hd194081%_) _%r194084%_)))))
          (gx#core-expand-block__0 _%stx194077%_ _%expand-special194079%_))))
    (define gx#core-expand-begin-syntax%
      (lambda (_%stx193731%_)
        (letrec ((_%expand-special193733%_
                  (lambda (_%hd193853%_ _%K193854%_ _%rest193855%_ _%r193856%_)
                    (let* ((_%K*193860%_
                            (lambda (_%e193858%_)
                              (_%K193854%_
                               _%rest193855%_
                               (cons _%e193858%_ _%r193856%_))))
                           (_%$%e193861193913%_ _%hd193853%_)
                           (_%$%E193899193917%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e193861193913%_)))
                           (_%$%E193895193959%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193900193921%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193901193924%_
                                           (##car _%$%e193900193921%_))
                                          (_%$%tl193902193926%_
                                           (##cdr _%$%e193900193921%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193901193924%_)
                                               (gx#core-identifier=?
                                                _%$%hd193901193924%_
                                                '%#bind-runtime-properties!))
                                          (if (gx#stx-pair?
                                               _%$%tl193902193926%_)
                                              (let ((_%$%e193903193929%_
                                                     (gx#syntax-e
                                                      _%$%tl193902193926%_)))
                                                (let ((_%$%hd193904193932%_
                                                       (##car _%$%e193903193929%_))
                                                      (_%$%tl193905193934%_
                                                       (##cdr _%$%e193903193929%_)))
                                                  (if (gx#stx-pair?
                                                       _%$%hd193904193932%_)
                                                      (let ((_%$%e193909193937%_
                                                             (gx#syntax-e
                                                              _%$%hd193904193932%_)))
                                                        (let ((_%$%hd193910193940%_
                                                               (##car _%$%e193909193937%_))
                                                              (_%$%tl193911193942%_
                                                               (##cdr _%$%e193909193937%_)))
                                                          (let ((_%id193945%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%hd193910193940%_))
                    (if (gx#stx-null? _%$%tl193911193942%_)
                        (if (gx#stx-pair? _%$%tl193905193934%_)
                            (let ((_%$%e193906193947%_
                                   (gx#syntax-e _%$%tl193905193934%_)))
                              (let ((_%$%hd193907193950%_
                                     (##car _%$%e193906193947%_))
                                    (_%$%tl193908193952%_
                                     (##cdr _%$%e193906193947%_)))
                                (let ((_%props193955%_ _%$%hd193907193950%_))
                                  (if (gx#stx-null? _%$%tl193908193952%_)
                                      (let ((_%bind193957%_
                                             (gx#resolve-identifier__0
                                              _%id193945%_)))
                                        (gx#core-bind-runtime-properties!
                                         _%bind193957%_
                                         _%props193955%_)
                                        (_%K193854%_
                                         _%rest193855%_
                                         _%r193856%_))
                                      (_%$%E193899193917%_)))))
                            (_%$%E193899193917%_))
                        (_%$%E193899193917%_)))))
              (_%$%E193899193917%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193899193917%_))
                                          (_%$%E193899193917%_))))
                                  (_%$%E193899193917%_))))
                           (_%$%E193891193971%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193896193963%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193897193966%_
                                           (##car _%$%e193896193963%_))
                                          (_%$%tl193898193968%_
                                           (##cdr _%$%e193896193963%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193897193966%_)
                                               (gx#core-identifier=?
                                                _%$%hd193897193966%_
                                                '%#define-runtime))
                                          (_%K*193860%_
                                           (gx#core-expand-define-runtime%
                                            _%hd193853%_))
                                          (_%$%E193895193959%_))))
                                  (_%$%E193895193959%_))))
                           (_%$%E193887193983%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193892193975%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193893193978%_
                                           (##car _%$%e193892193975%_))
                                          (_%$%tl193894193980%_
                                           (##cdr _%$%e193892193975%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193893193978%_)
                                               (gx#core-identifier=?
                                                _%$%hd193893193978%_
                                                '%#define-alias))
                                          (_%K*193860%_
                                           (gx#core-expand-define-alias%
                                            _%hd193853%_))
                                          (_%$%E193891193971%_))))
                                  (_%$%E193891193971%_))))
                           (_%$%E193877193995%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193888193987%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193889193990%_
                                           (##car _%$%e193888193987%_))
                                          (_%$%tl193890193992%_
                                           (##cdr _%$%e193888193987%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193889193990%_)
                                               (gx#core-identifier=?
                                                _%$%hd193889193990%_
                                                '%#define-syntax))
                                          (_%K*193860%_
                                           (gx#core-expand-define-syntax%
                                            _%hd193853%_))
                                          (_%$%E193887193983%_))))
                                  (_%$%E193887193983%_))))
                           (_%$%E193867194027%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193878193999%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193879194002%_
                                           (##car _%$%e193878193999%_))
                                          (_%$%tl193880194004%_
                                           (##cdr _%$%e193878193999%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193879194002%_)
                                               (gx#core-identifier=?
                                                _%$%hd193879194002%_
                                                '%#define-values))
                                          (if (gx#stx-pair?
                                               _%$%tl193880194004%_)
                                              (let ((_%$%e193881194007%_
                                                     (gx#syntax-e
                                                      _%$%tl193880194004%_)))
                                                (let ((_%$%hd193882194010%_
                                                       (##car _%$%e193881194007%_))
                                                      (_%$%tl193883194012%_
                                                       (##cdr _%$%e193881194007%_)))
                                                  (let ((_%hd-bind194015%_
                                                         _%$%hd193882194010%_))
                                                    (if (gx#stx-pair?
                                                         _%$%tl193883194012%_)
                                                        (let ((_%$%e193884194017%_
                                                               (gx#syntax-e
                                                                _%$%tl193883194012%_)))
                                                          (let ((_%$%hd193885194020%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e193884194017%_))
                        (_%$%tl193886194022%_ (##cdr _%$%e193884194017%_)))
                    (let ((_%expr194025%_ _%$%hd193885194020%_))
                      (if (gx#stx-null? _%$%tl193886194022%_)
                          (if (gx#core-bind-values? _%hd-bind194015%_)
                              (begin
                                (gx#core-bind-values!__0 _%hd-bind194015%_)
                                (_%K*193860%_ _%hd193853%_))
                              (_%$%E193877193995%_))
                          (_%$%E193877193995%_)))))
                (_%$%E193877193995%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193877193995%_))
                                          (_%$%E193877193995%_))))
                                  (_%$%E193877193995%_))))
                           (_%$%E193863194061%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193868194031%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193869194034%_
                                           (##car _%$%e193868194031%_))
                                          (_%$%tl193870194036%_
                                           (##cdr _%$%e193868194031%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193869194034%_)
                                               (gx#core-identifier=?
                                                _%$%hd193869194034%_
                                                '%#define-values))
                                          (if (gx#stx-pair?
                                               _%$%tl193870194036%_)
                                              (let ((_%$%e193871194039%_
                                                     (gx#syntax-e
                                                      _%$%tl193870194036%_)))
                                                (let ((_%$%hd193872194042%_
                                                       (##car _%$%e193871194039%_))
                                                      (_%$%tl193873194044%_
                                                       (##cdr _%$%e193871194039%_)))
                                                  (let ((_%hd-bind194047%_
                                                         _%$%hd193872194042%_))
                                                    (if (gx#stx-pair?
                                                         _%$%tl193873194044%_)
                                                        (let ((_%$%e193874194049%_
                                                               (gx#syntax-e
                                                                _%$%tl193873194044%_)))
                                                          (let ((_%$%hd193875194052%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e193874194049%_))
                        (_%$%tl193876194054%_ (##cdr _%$%e193874194049%_)))
                    (let* ((_%expr194057%_ _%$%hd193875194052%_)
                           (_%props194059%_ _%$%tl193876194054%_))
                      (if (and (gx#core-bind-values? _%hd-bind194047%_)
                               (gx#stx-list? _%props194059%_)
                               (not (gx#stx-null? _%props194059%_)))
                          (begin
                            (gx#core-bind-values!__0 _%hd-bind194047%_)
                            (_%K193854%_
                             (cons (gx#core-cons
                                    '%#bind-runtime-properties!
                                    (cons _%hd-bind194047%_
                                          (cons _%props194059%_ '())))
                                   _%rest193855%_)
                             (cons (gx#core-cons
                                    '%#define-values
                                    (cons _%hd-bind194047%_
                                          (cons _%expr194057%_ '())))
                                   _%r193856%_)))
                          (_%$%E193867194027%_)))))
                (_%$%E193867194027%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193867194027%_))
                                          (_%$%E193867194027%_))))
                                  (_%$%E193867194027%_))))
                           (_%$%E193862194073%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193861193913%_)
                                  (let ((_%$%e193864194065%_
                                         (gx#syntax-e _%$%e193861193913%_)))
                                    (let ((_%$%hd193865194068%_
                                           (##car _%$%e193864194065%_))
                                          (_%$%tl193866194070%_
                                           (##cdr _%$%e193864194065%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193865194068%_)
                                               (gx#core-identifier=?
                                                _%$%hd193865194068%_
                                                '%#begin-syntax))
                                          (_%K*193860%_
                                           (gx#core-expand-begin-syntax%
                                            _%hd193853%_))
                                          (_%$%E193863194061%_))))
                                  (_%$%E193863194061%_)))))
                      (_%$%E193862194073%_))))
                 (_%eval-body193734%_
                  (lambda (_%rbody193742%_)
                    (let _%lp193744%_ ((_%rest193746%_ _%rbody193742%_)
                                       (_%body193747%_ '())
                                       (_%ebody193748%_ '()))
                      (let* ((_%$%rest193749193757%_ _%rest193746%_)
                             (_%$%else193751193765%_
                              (lambda ()
                                (values _%body193747%_
                                        (gx#eval-syntax*
                                         (gx#core-quote-syntax__1
                                          (gx#core-cons
                                           '%#begin
                                           _%ebody193748%_)
                                          (gx#stx-source _%stx193731%_))))))
                             (_%$%K193753193841%_
                              (lambda (_%rest193768%_ _%hd193769%_)
                                (let* ((_%$%e193770193787%_ _%hd193769%_)
                                       (_%$%E193782193791%_
                                        (lambda ()
                                          (_%lp193744%_
                                           _%rest193768%_
                                           (cons _%hd193769%_ _%body193747%_)
                                           (cons _%hd193769%_
                                                 _%ebody193748%_))))
                                       (_%$%E193772193803%_
                                        (lambda ()
                                          (if (gx#stx-pair?
                                               _%$%e193770193787%_)
                                              (let ((_%$%e193783193795%_
                                                     (gx#syntax-e
                                                      _%$%e193770193787%_)))
                                                (let ((_%$%hd193784193798%_
                                                       (##car _%$%e193783193795%_))
                                                      (_%$%tl193785193800%_
                                                       (##cdr _%$%e193783193795%_)))
                                                  (if (and (gx#identifier?
                                                            _%$%hd193784193798%_)
                                                           (gx#core-identifier=?
                                                            _%$%hd193784193798%_
                                                            '%#begin-syntax))
                                                      (_%lp193744%_
                                                       _%rest193768%_
                                                       (cons _%hd193769%_
                                                             _%body193747%_)
                                                       _%ebody193748%_)
                                                      (_%$%E193782193791%_))))
                                              (_%$%E193782193791%_))))
                                       (_%$%E193771193837%_
                                        (lambda ()
                                          (if (gx#stx-pair?
                                               _%$%e193770193787%_)
                                              (let ((_%$%e193773193807%_
                                                     (gx#syntax-e
                                                      _%$%e193770193787%_)))
                                                (let ((_%$%hd193774193810%_
                                                       (##car _%$%e193773193807%_))
                                                      (_%$%tl193775193812%_
                                                       (##cdr _%$%e193773193807%_)))
                                                  (if (and (gx#identifier?
                                                            _%$%hd193774193810%_)
                                                           (gx#core-identifier=?
                                                            _%$%hd193774193810%_
                                                            '%#define-values))
                                                      (if (gx#stx-pair?
                                                           _%$%tl193775193812%_)
                                                          (let ((_%$%e193776193815%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl193775193812%_)))
                    (let ((_%$%hd193777193818%_ (##car _%$%e193776193815%_))
                          (_%$%tl193778193820%_ (##cdr _%$%e193776193815%_)))
                      (let ((_%hd-bind193823%_ _%$%hd193777193818%_))
                        (if (gx#stx-pair? _%$%tl193778193820%_)
                            (let ((_%$%e193779193825%_
                                   (gx#syntax-e _%$%tl193778193820%_)))
                              (let ((_%$%hd193780193828%_
                                     (##car _%$%e193779193825%_))
                                    (_%$%tl193781193830%_
                                     (##cdr _%$%e193779193825%_)))
                                (let ((_%expr193833%_ _%$%hd193780193828%_))
                                  (if (gx#stx-null? _%$%tl193781193830%_)
                                      (let ((_%ehd193835%_
                                             (gx#core-quote-syntax__1
                                              (cons (gx#core-quote-syntax__0
                                                     '%#define-values)
                                                    (cons (gx#core-quote-bind-values
                                                           _%hd-bind193823%_)
                                                          (cons (gx#core-expand-expression
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%expr193833%_)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (gx#stx-source _%hd193769%_))))
                                        (_%lp193744%_
                                         _%rest193768%_
                                         (cons _%ehd193835%_ _%body193747%_)
                                         (cons _%ehd193835%_ _%ebody193748%_)))
                                      (_%$%E193772193803%_)))))
                            (_%$%E193772193803%_)))))
                  (_%$%E193772193803%_))
              (_%$%E193772193803%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193772193803%_)))))
                                  (_%$%E193771193837%_)))))
                        (if (pair? _%$%rest193749193757%_)
                            (let ((_%$%hd193754193844%_
                                   (##car _%$%rest193749193757%_))
                                  (_%$%tl193755193846%_
                                   (##cdr _%$%rest193749193757%_)))
                              (let* ((_%hd193849%_ _%$%hd193754193844%_)
                                     (_%rest193851%_ _%$%tl193755193846%_))
                                (_%$%K193753193841%_
                                 _%rest193851%_
                                 _%hd193849%_)))
                            (_%$%else193751193765%_)))))))
          (call-with-parameters__1
           (lambda ()
             (let* ((_%rbody193737%_
                     (gx#core-expand-block__1
                      _%stx193731%_
                      _%expand-special193733%_
                      '#f))
                    (_g194110_ (_%eval-body193734%_ _%rbody193737%_)))
               (begin
                 (let ((_g194111_
                        (if (##values? _g194110_)
                            (##values-length _g194110_)
                            1)))
                   (if (not (##fx= _g194111_ 2))
                       (error "Context expects 2 values" _g194111_)))
                 (let ((_%expanded-body193739%_ (##values-ref _g194110_ 0))
                       (_%value193740%_ (##values-ref _g194110_ 1)))
                   (gx#core-quote-syntax__1
                    (if (##structure-instance-of?
                         (gx#current-expander-context)
                         'gx#module-context::t)
                        (gx#core-cons '%#begin-syntax _%expanded-body193739%_)
                        (cons (gx#core-quote-syntax__0 '%#quote)
                              (cons _%value193740%_ '())))
                    (gx#stx-source _%stx193731%_))))))
           gx#current-expander-phi
           (##fx+ (gx#current-expander-phi) '1)))))
    (define gx#core-expand-begin-foreign%
      (lambda (_%stx193701%_)
        (let* ((_%$%e193702193709%_ _%stx193701%_)
               (_%$%E193704193713%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e193702193709%_)))
               (_%$%E193703193727%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e193702193709%_)
                      (let ((_%$%e193705193717%_
                             (gx#syntax-e _%$%e193702193709%_)))
                        (let ((_%$%hd193706193720%_
                               (##car _%$%e193705193717%_))
                              (_%$%tl193707193722%_
                               (##cdr _%$%e193705193717%_)))
                          (let ((_%body193725%_ _%$%tl193707193722%_))
                            (if (gx#stx-list? _%body193725%_)
                                (gx#core-quote-syntax__1
                                 (gx#core-cons '%#begin-foreign _%body193725%_)
                                 (gx#stx-source _%stx193701%_))
                                (_%$%E193704193713%_)))))
                      (_%$%E193704193713%_)))))
          (_%$%E193703193727%_))))
    (define gx#core-expand-begin-module%
      (lambda (_%stx193699%_)
        (gx#raise-syntax-error '#f '"Illegal expansion" _%stx193699%_)))
    (define gx#core-expand-begin-annotation%
      (lambda (_%stx193645%_)
        (let* ((_%$%e193646193659%_ _%stx193645%_)
               (_%$%E193648193663%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e193646193659%_)))
               (_%$%E193647193695%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e193646193659%_)
                      (let ((_%$%e193649193667%_
                             (gx#syntax-e _%$%e193646193659%_)))
                        (let ((_%$%hd193650193670%_
                               (##car _%$%e193649193667%_))
                              (_%$%tl193651193672%_
                               (##cdr _%$%e193649193667%_)))
                          (if (gx#stx-pair? _%$%tl193651193672%_)
                              (let ((_%$%e193652193675%_
                                     (gx#syntax-e _%$%tl193651193672%_)))
                                (let ((_%$%hd193653193678%_
                                       (##car _%$%e193652193675%_))
                                      (_%$%tl193654193680%_
                                       (##cdr _%$%e193652193675%_)))
                                  (let ((_%ann193683%_ _%$%hd193653193678%_))
                                    (if (gx#stx-pair? _%$%tl193654193680%_)
                                        (let ((_%$%e193655193685%_
                                               (gx#syntax-e
                                                _%$%tl193654193680%_)))
                                          (let ((_%$%hd193656193688%_
                                                 (##car _%$%e193655193685%_))
                                                (_%$%tl193657193690%_
                                                 (##cdr _%$%e193655193685%_)))
                                            (let ((_%expr193693%_
                                                   _%$%hd193656193688%_))
                                              (if (gx#stx-null?
                                                   _%$%tl193657193690%_)
                                                  (gx#core-quote-syntax__1
                                                   (cons (gx#core-quote-syntax__0
                                                          '%#begin-annotation)
                                                         (cons _%ann193683%_
                                                               (cons (gx#core-expand-expression
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%expr193693%_)
                             '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (gx#stx-source
                                                    _%stx193645%_))
                                                  (_%$%E193648193663%_)))))
                                        (_%$%E193648193663%_)))))
                              (_%$%E193648193663%_))))
                      (_%$%E193648193663%_)))))
          (_%$%E193647193695%_))))
    (define gx#core-expand-local-block
      (lambda (_%stx193270%_ _%body193271%_)
        (letrec ((_%expand-special193273%_
                  (lambda (_%hd193640%_ _%K193641%_ _%rest193642%_ _%r193643%_)
                    (_%K193641%_
                     '()
                     (cons (_%expand-internal193274%_
                            _%hd193640%_
                            _%rest193642%_)
                           _%r193643%_))))
                 (_%expand-internal193274%_
                  (lambda (_%hd193636%_ _%rest193637%_)
                    (call-with-parameters__1
                     (lambda ()
                       (_%wrap-internal193276%_
                        (gx#core-expand-block__1
                         (gx#stx-wrap-source
                          (cons '%#begin (cons _%hd193636%_ _%rest193637%_))
                          (gx#stx-source _%stx193270%_))
                         _%expand-internal-special193275%_
                         '#f)))
                     gx#current-expander-context
                     (let ((__obj194094
                            (##structure
                             gx#local-context::t
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f)))
                       (gx#local-context:::init!__0 __obj194094)
                       __obj194094))))
                 (_%expand-internal-special193275%_
                  (lambda (_%hd193432%_ _%K193433%_ _%rest193434%_ _%r193435%_)
                    (let* ((_%$%e193436193484%_ _%hd193432%_)
                           (_%$%E193479193488%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e193436193484%_)))
                           (_%$%E193466193500%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193436193484%_)
                                  (let ((_%$%e193480193492%_
                                         (gx#syntax-e _%$%e193436193484%_)))
                                    (let ((_%$%hd193481193495%_
                                           (##car _%$%e193480193492%_))
                                          (_%$%tl193482193497%_
                                           (##cdr _%$%e193480193492%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193481193495%_)
                                               (gx#core-identifier=?
                                                _%$%hd193481193495%_
                                                '%#declare))
                                          (_%K193433%_
                                           _%rest193434%_
                                           (cons (gx#core-expand-declare%
                                                  _%hd193432%_)
                                                 _%r193435%_))
                                          (_%$%E193479193488%_))))
                                  (_%$%E193479193488%_))))
                           (_%$%E193462193542%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193436193484%_)
                                  (let ((_%$%e193467193504%_
                                         (gx#syntax-e _%$%e193436193484%_)))
                                    (let ((_%$%hd193468193507%_
                                           (##car _%$%e193467193504%_))
                                          (_%$%tl193469193509%_
                                           (##cdr _%$%e193467193504%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193468193507%_)
                                               (gx#core-identifier=?
                                                _%$%hd193468193507%_
                                                '%#bind-runtime-properties!))
                                          (if (gx#stx-pair?
                                               _%$%tl193469193509%_)
                                              (let ((_%$%e193470193512%_
                                                     (gx#syntax-e
                                                      _%$%tl193469193509%_)))
                                                (let ((_%$%hd193471193515%_
                                                       (##car _%$%e193470193512%_))
                                                      (_%$%tl193472193517%_
                                                       (##cdr _%$%e193470193512%_)))
                                                  (if (gx#stx-pair?
                                                       _%$%hd193471193515%_)
                                                      (let ((_%$%e193476193520%_
                                                             (gx#syntax-e
                                                              _%$%hd193471193515%_)))
                                                        (let ((_%$%hd193477193523%_
                                                               (##car _%$%e193476193520%_))
                                                              (_%$%tl193478193525%_
                                                               (##cdr _%$%e193476193520%_)))
                                                          (let ((_%id193528%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%hd193477193523%_))
                    (if (gx#stx-null? _%$%tl193478193525%_)
                        (if (gx#stx-pair? _%$%tl193472193517%_)
                            (let ((_%$%e193473193530%_
                                   (gx#syntax-e _%$%tl193472193517%_)))
                              (let ((_%$%hd193474193533%_
                                     (##car _%$%e193473193530%_))
                                    (_%$%tl193475193535%_
                                     (##cdr _%$%e193473193530%_)))
                                (let ((_%props193538%_ _%$%hd193474193533%_))
                                  (if (gx#stx-null? _%$%tl193475193535%_)
                                      (let ((_%bind193540%_
                                             (gx#resolve-identifier__0
                                              _%id193528%_)))
                                        (gx#core-bind-runtime-properties!
                                         _%bind193540%_
                                         _%props193538%_)
                                        (_%K193433%_
                                         _%rest193434%_
                                         _%r193435%_))
                                      (_%$%E193466193500%_)))))
                            (_%$%E193466193500%_))
                        (_%$%E193466193500%_)))))
              (_%$%E193466193500%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193466193500%_))
                                          (_%$%E193466193500%_))))
                                  (_%$%E193466193500%_))))
                           (_%$%E193458193554%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193436193484%_)
                                  (let ((_%$%e193463193546%_
                                         (gx#syntax-e _%$%e193436193484%_)))
                                    (let ((_%$%hd193464193549%_
                                           (##car _%$%e193463193546%_))
                                          (_%$%tl193465193551%_
                                           (##cdr _%$%e193463193546%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193464193549%_)
                                               (gx#core-identifier=?
                                                _%$%hd193464193549%_
                                                '%#define-alias))
                                          (begin
                                            (gx#core-expand-define-alias%
                                             _%hd193432%_)
                                            (_%K193433%_
                                             _%rest193434%_
                                             _%r193435%_))
                                          (_%$%E193462193542%_))))
                                  (_%$%E193462193542%_))))
                           (_%$%E193448193566%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193436193484%_)
                                  (let ((_%$%e193459193558%_
                                         (gx#syntax-e _%$%e193436193484%_)))
                                    (let ((_%$%hd193460193561%_
                                           (##car _%$%e193459193558%_))
                                          (_%$%tl193461193563%_
                                           (##cdr _%$%e193459193558%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193460193561%_)
                                               (gx#core-identifier=?
                                                _%$%hd193460193561%_
                                                '%#define-syntax))
                                          (begin
                                            (gx#core-expand-define-syntax%
                                             _%hd193432%_)
                                            (_%K193433%_
                                             _%rest193434%_
                                             _%r193435%_))
                                          (_%$%E193458193554%_))))
                                  (_%$%E193458193554%_))))
                           (_%$%E193438193598%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193436193484%_)
                                  (let ((_%$%e193449193570%_
                                         (gx#syntax-e _%$%e193436193484%_)))
                                    (let ((_%$%hd193450193573%_
                                           (##car _%$%e193449193570%_))
                                          (_%$%tl193451193575%_
                                           (##cdr _%$%e193449193570%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193450193573%_)
                                               (gx#core-identifier=?
                                                _%$%hd193450193573%_
                                                '%#define-values))
                                          (if (gx#stx-pair?
                                               _%$%tl193451193575%_)
                                              (let ((_%$%e193452193578%_
                                                     (gx#syntax-e
                                                      _%$%tl193451193575%_)))
                                                (let ((_%$%hd193453193581%_
                                                       (##car _%$%e193452193578%_))
                                                      (_%$%tl193454193583%_
                                                       (##cdr _%$%e193452193578%_)))
                                                  (let ((_%hd-bind193586%_
                                                         _%$%hd193453193581%_))
                                                    (if (gx#stx-pair?
                                                         _%$%tl193454193583%_)
                                                        (let ((_%$%e193455193588%_
                                                               (gx#syntax-e
                                                                _%$%tl193454193583%_)))
                                                          (let ((_%$%hd193456193591%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e193455193588%_))
                        (_%$%tl193457193593%_ (##cdr _%$%e193455193588%_)))
                    (let ((_%expr193596%_ _%$%hd193456193591%_))
                      (if (gx#stx-null? _%$%tl193457193593%_)
                          (if (gx#core-bind-values? _%hd-bind193586%_)
                              (begin
                                (gx#core-bind-values!__0 _%hd-bind193586%_)
                                (_%K193433%_
                                 _%rest193434%_
                                 (cons _%hd193432%_ _%r193435%_)))
                              (_%$%E193448193566%_))
                          (_%$%E193448193566%_)))))
                (_%$%E193448193566%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193448193566%_))
                                          (_%$%E193448193566%_))))
                                  (_%$%E193448193566%_))))
                           (_%$%E193437193632%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e193436193484%_)
                                  (let ((_%$%e193439193602%_
                                         (gx#syntax-e _%$%e193436193484%_)))
                                    (let ((_%$%hd193440193605%_
                                           (##car _%$%e193439193602%_))
                                          (_%$%tl193441193607%_
                                           (##cdr _%$%e193439193602%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd193440193605%_)
                                               (gx#core-identifier=?
                                                _%$%hd193440193605%_
                                                '%#define-values))
                                          (if (gx#stx-pair?
                                               _%$%tl193441193607%_)
                                              (let ((_%$%e193442193610%_
                                                     (gx#syntax-e
                                                      _%$%tl193441193607%_)))
                                                (let ((_%$%hd193443193613%_
                                                       (##car _%$%e193442193610%_))
                                                      (_%$%tl193444193615%_
                                                       (##cdr _%$%e193442193610%_)))
                                                  (let ((_%hd-bind193618%_
                                                         _%$%hd193443193613%_))
                                                    (if (gx#stx-pair?
                                                         _%$%tl193444193615%_)
                                                        (let ((_%$%e193445193620%_
                                                               (gx#syntax-e
                                                                _%$%tl193444193615%_)))
                                                          (let ((_%$%hd193446193623%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e193445193620%_))
                        (_%$%tl193447193625%_ (##cdr _%$%e193445193620%_)))
                    (let* ((_%expr193628%_ _%$%hd193446193623%_)
                           (_%props193630%_ _%$%tl193447193625%_))
                      (if (and (gx#core-bind-values? _%hd-bind193618%_)
                               (gx#stx-list? _%props193630%_)
                               (not (gx#stx-null? _%props193630%_)))
                          (begin
                            (gx#core-bind-values!__0 _%hd-bind193618%_)
                            (_%K193433%_
                             (cons (gx#core-cons
                                    '%#bind-runtime-properties!
                                    (cons _%hd-bind193618%_
                                          (cons _%props193630%_ '())))
                                   _%rest193434%_)
                             (cons (gx#core-cons
                                    '%#define-values
                                    (cons _%hd-bind193618%_
                                          (cons _%expr193628%_ '())))
                                   _%r193435%_)))
                          (_%$%E193438193598%_)))))
                (_%$%E193438193598%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E193438193598%_))
                                          (_%$%E193438193598%_))))
                                  (_%$%E193438193598%_)))))
                      (_%$%E193437193632%_))))
                 (_%wrap-internal193276%_
                  (lambda (_%rbody193278%_)
                    (let _%lp193280%_ ((_%rest193282%_ _%rbody193278%_)
                                       (_%decls193283%_ '())
                                       (_%bind193284%_ '())
                                       (_%body193285%_ '()))
                      (let* ((_%$%e193286193293%_ _%rest193282%_)
                             (_%$%E193288193342%_
                              (lambda ()
                                (let* ((_%body193337%_
                                        (let* ((_%$%body193296193306%_
                                                _%body193285%_)
                                               (_%$%else193299193314%_
                                                (lambda ()
                                                  (gx#core-quote-syntax__1
                                                   (gx#core-cons
                                                    '%#begin
                                                    _%body193285%_)
                                                   (gx#stx-source
                                                    _%stx193270%_)))))
                                          (let ((_%$%K193304193334%_
                                                 (lambda ()
                                                   (gx#raise-syntax-error
                                                    '#f
                                                    '"Bad syntax; empty body"
                                                    _%stx193270%_)))
                                                (_%$%K193301193320%_
                                                 (lambda (_%expr193318%_)
                                                   _%expr193318%_)))
                                            (let ((_%$%try-match193298193330%_
                                                   (lambda ()
                                                     (if (pair? _%$%body193296193306%_)
                                                         (let ((_%$%tl193303193325%_
                                                                (##cdr _%$%body193296193306%_))
                                                               (_%$%hd193302193323%_
                                                                (##car _%$%body193296193306%_)))
                                                           (if (null? _%$%tl193303193325%_)
                                                               (let ((_%expr193328%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%hd193302193323%_))
                         (_%$%K193301193320%_ _%expr193328%_))
                       (_%$%else193299193314%_)))
                 (_%$%else193299193314%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (null? _%$%body193296193306%_)
                                                  (_%$%K193304193334%_)
                                                  (_%$%try-match193298193330%_))))))
                                       (_%body193339%_
                                        (if (null? _%bind193284%_)
                                            _%body193337%_
                                            (gx#core-quote-syntax__1
                                             (cons (gx#core-quote-syntax__0
                                                    '%#letrec*-values)
                                                   (cons _%bind193284%_
                                                         (cons _%body193337%_
                                                               '())))
                                             (gx#stx-source _%stx193270%_)))))
                                  (if (null? _%decls193283%_)
                                      _%body193339%_
                                      (gx#core-quote-syntax__1
                                       (cons (gx#core-quote-syntax__0
                                              '%#begin-annotation)
                                             (cons _%decls193283%_
                                                   (cons _%body193339%_ '())))
                                       (gx#stx-source _%stx193270%_))))))
                             (_%$%E193287193428%_
                              (lambda ()
                                (if (gx#stx-pair? _%$%e193286193293%_)
                                    (let ((_%$%e193289193346%_
                                           (gx#syntax-e _%$%e193286193293%_)))
                                      (let ((_%$%hd193290193349%_
                                             (##car _%$%e193289193346%_))
                                            (_%$%tl193291193351%_
                                             (##cdr _%$%e193289193346%_)))
                                        (let* ((_%hd193354%_
                                                _%$%hd193290193349%_)
                                               (_%rest193356%_
                                                _%$%tl193291193351%_)
                                               (_%$%e193357193374%_
                                                _%hd193354%_)
                                               (_%$%E193369193378%_
                                                (lambda ()
                                                  (if (null? _%bind193284%_)
                                                      (_%lp193280%_
                                                       _%rest193356%_
                                                       _%decls193283%_
                                                       _%bind193284%_
                                                       (cons _%hd193354%_
                                                             _%body193285%_))
                                                      (_%lp193280%_
                                                       _%rest193356%_
                                                       _%decls193283%_
                                                       (cons (cons '#f
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%hd193354%_ '()))
                     _%bind193284%_)
               _%body193285%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%E193359193392%_
                                                (lambda ()
                                                  (if (gx#stx-pair?
                                                       _%$%e193357193374%_)
                                                      (let ((_%$%e193370193382%_
                                                             (gx#syntax-e
                                                              _%$%e193357193374%_)))
                                                        (let ((_%$%hd193371193385%_
                                                               (##car _%$%e193370193382%_))
                                                              (_%$%tl193372193387%_
                                                               (##cdr _%$%e193370193382%_)))
                                                          (if (and (gx#identifier?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%hd193371193385%_)
                           (gx#core-identifier=?
                            _%$%hd193371193385%_
                            '%#declare))
                      (let ((_%xdecls193390%_ _%$%tl193372193387%_))
                        (_%lp193280%_
                         _%rest193356%_
                         (gx#stx-foldr cons _%decls193283%_ _%xdecls193390%_)
                         _%bind193284%_
                         _%body193285%_))
                      (_%$%E193369193378%_))))
              (_%$%E193369193378%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%E193358193424%_
                                                (lambda ()
                                                  (if (gx#stx-pair?
                                                       _%$%e193357193374%_)
                                                      (let ((_%$%e193360193396%_
                                                             (gx#syntax-e
                                                              _%$%e193357193374%_)))
                                                        (let ((_%$%hd193361193399%_
                                                               (##car _%$%e193360193396%_))
                                                              (_%$%tl193362193401%_
                                                               (##cdr _%$%e193360193396%_)))
                                                          (if (and (gx#identifier?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%hd193361193399%_)
                           (gx#core-identifier=?
                            _%$%hd193361193399%_
                            '%#define-values))
                      (if (gx#stx-pair? _%$%tl193362193401%_)
                          (let ((_%$%e193363193404%_
                                 (gx#syntax-e _%$%tl193362193401%_)))
                            (let ((_%$%hd193364193407%_
                                   (##car _%$%e193363193404%_))
                                  (_%$%tl193365193409%_
                                   (##cdr _%$%e193363193404%_)))
                              (let ((_%hd-bind193412%_ _%$%hd193364193407%_))
                                (if (gx#stx-pair? _%$%tl193365193409%_)
                                    (let ((_%$%e193366193414%_
                                           (gx#syntax-e _%$%tl193365193409%_)))
                                      (let ((_%$%hd193367193417%_
                                             (##car _%$%e193366193414%_))
                                            (_%$%tl193368193419%_
                                             (##cdr _%$%e193366193414%_)))
                                        (let ((_%expr193422%_
                                               _%$%hd193367193417%_))
                                          (if (gx#stx-null?
                                               _%$%tl193368193419%_)
                                              (_%lp193280%_
                                               _%rest193356%_
                                               _%decls193283%_
                                               (cons (cons (gx#core-quote-bind-values
                                                            _%hd-bind193412%_)
                                                           (cons (gx#core-expand-expression
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%expr193422%_)
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%bind193284%_)
                                               _%body193285%_)
                                              (_%$%E193359193392%_)))))
                                    (_%$%E193359193392%_)))))
                          (_%$%E193359193392%_))
                      (_%$%E193359193392%_))))
              (_%$%E193359193392%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%E193358193424%_))))
                                    (_%$%E193288193342%_)))))
                        (_%$%E193287193428%_))))))
          (gx#core-expand-block*
           (gx#stx-wrap-source
            (cons '%#begin _%body193271%_)
            (gx#stx-source _%stx193270%_))
           _%expand-special193273%_))))
    (define gx#core-expand-declare%
      (lambda (_%stx193208%_)
        (let* ((_%$%e193209193216%_ _%stx193208%_)
               (_%$%E193211193220%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e193209193216%_)))
               (_%$%E193210193266%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e193209193216%_)
                      (let ((_%$%e193212193224%_
                             (gx#syntax-e _%$%e193209193216%_)))
                        (let ((_%$%hd193213193227%_
                               (##car _%$%e193212193224%_))
                              (_%$%tl193214193229%_
                               (##cdr _%$%e193212193224%_)))
                          (let ((_%body193232%_ _%$%tl193214193229%_))
                            (if (gx#stx-list? _%body193232%_)
                                (gx#core-quote-syntax__1
                                 (gx#core-cons
                                  '%#declare
                                  (gx#stx-map1
                                   (lambda (_%decl193234%_)
                                     (let* ((_%$%e193235193242%_
                                             _%decl193234%_)
                                            (_%$%E193237193246%_
                                             (lambda ()
                                               (gx#raise-syntax-error
                                                '#f
                                                '"Bad syntax; invalid syntax-case clause"
                                                _%$%e193235193242%_)))
                                            (_%$%E193236193262%_
                                             (lambda ()
                                               (if (gx#stx-pair?
                                                    _%$%e193235193242%_)
                                                   (let ((_%$%e193238193250%_
                                                          (gx#syntax-e
                                                           _%$%e193235193242%_)))
                                                     (let ((_%$%hd193239193253%_
                                                            (##car _%$%e193238193250%_))
                                                           (_%$%tl193240193255%_
                                                            (##cdr _%$%e193238193250%_)))
                                                       (let* ((_%head193258%_
                                                               _%$%hd193239193253%_)
                                                              (_%args193260%_
                                                               _%$%tl193240193255%_))
                                                         (if (gx#stx-list?
                                                              _%args193260%_)
                                                             (gx#stx-map1
                                                              gx#core-quote-syntax
                                                              _%decl193234%_)
                                                             (_%$%E193237193246%_)))))
                                                   (_%$%E193237193246%_)))))
                                       (_%$%E193236193262%_)))
                                   _%body193232%_))
                                 (gx#stx-source _%stx193208%_))
                                (_%$%E193211193220%_)))))
                      (_%$%E193211193220%_)))))
          (_%$%E193210193266%_))))
    (define gx#core-expand-extern%
      (lambda (_%stx193112%_)
        (let* ((_%$%e193113193120%_ _%stx193112%_)
               (_%$%E193115193124%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e193113193120%_)))
               (_%$%E193114193204%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e193113193120%_)
                      (let ((_%$%e193116193128%_
                             (gx#syntax-e _%$%e193113193120%_)))
                        (let ((_%$%hd193117193131%_
                               (##car _%$%e193116193128%_))
                              (_%$%tl193118193133%_
                               (##cdr _%$%e193116193128%_)))
                          (let ((_%body193136%_ _%$%tl193118193133%_))
                            (let _%lp193138%_ ((_%rest193140%_ _%body193136%_)
                                               (_%r193141%_ '()))
                              (let* ((_%$%e193142193156%_ _%rest193140%_)
                                     (_%$%E193154193160%_
                                      (lambda ()
                                        (gx#raise-syntax-error
                                         '#f
                                         '"Bad syntax; %#extern expects list of (internal external) identifier lists"
                                         _%stx193112%_)))
                                     (_%$%E193144193164%_
                                      (lambda ()
                                        (if (gx#stx-null? _%$%e193142193156%_)
                                            (gx#core-quote-syntax__1
                                             (gx#core-cons
                                              '%#extern
                                              (reverse _%r193141%_))
                                             (gx#stx-source _%stx193112%_))
                                            (_%$%E193154193160%_))))
                                     (_%$%E193143193200%_
                                      (lambda ()
                                        (if (gx#stx-pair? _%$%e193142193156%_)
                                            (let ((_%$%e193145193168%_
                                                   (gx#syntax-e
                                                    _%$%e193142193156%_)))
                                              (let ((_%$%hd193146193171%_
                                                     (##car _%$%e193145193168%_))
                                                    (_%$%tl193147193173%_
                                                     (##cdr _%$%e193145193168%_)))
                                                (if (gx#stx-pair?
                                                     _%$%hd193146193171%_)
                                                    (let ((_%$%e193148193176%_
                                                           (gx#syntax-e
                                                            _%$%hd193146193171%_)))
                                                      (let ((_%$%hd193149193179%_
                                                             (##car _%$%e193148193176%_))
                                                            (_%$%tl193150193181%_
                                                             (##cdr _%$%e193148193176%_)))
                                                        (let ((_%id193184%_
                                                               _%$%hd193149193179%_))
                                                          (if (gx#stx-pair?
                                                               _%$%tl193150193181%_)
                                                              (let ((_%$%e193151193186%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#syntax-e _%$%tl193150193181%_)))
                        (let ((_%$%hd193152193189%_
                               (##car _%$%e193151193186%_))
                              (_%$%tl193153193191%_
                               (##cdr _%$%e193151193186%_)))
                          (let ((_%eid193194%_ _%$%hd193152193189%_))
                            (if (gx#stx-null? _%$%tl193153193191%_)
                                (let ((_%rest193196%_ _%$%tl193147193173%_))
                                  (if (and (gx#identifier? _%id193184%_)
                                           (gx#identifier? _%eid193194%_))
                                      (let ((_%eid193198%_
                                             (gx#stx-e _%eid193194%_)))
                                        (gx#core-bind-extern!__0
                                         _%id193184%_
                                         _%eid193198%_)
                                        (_%lp193138%_
                                         _%rest193196%_
                                         (cons (cons (gx#core-quote-syntax__0
                                                      _%id193184%_)
                                                     (cons _%eid193198%_ '()))
                                               _%r193141%_)))
                                      (_%$%E193144193164%_)))
                                (_%$%E193144193164%_)))))
                      (_%$%E193144193164%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%E193144193164%_))))
                                            (_%$%E193144193164%_)))))
                                (_%$%E193143193200%_))))))
                      (_%$%E193115193124%_)))))
          (_%$%E193114193204%_))))
    (define gx#core-expand-define-values%
      (lambda (_%stx193014%_)
        (let* ((_%$%e193015193038%_ _%stx193014%_)
               (_%$%E193027193042%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e193015193038%_)))
               (_%$%E193017193074%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e193015193038%_)
                      (let ((_%$%e193028193046%_
                             (gx#syntax-e _%$%e193015193038%_)))
                        (let ((_%$%hd193029193049%_
                               (##car _%$%e193028193046%_))
                              (_%$%tl193030193051%_
                               (##cdr _%$%e193028193046%_)))
                          (if (gx#stx-pair? _%$%tl193030193051%_)
                              (let ((_%$%e193031193054%_
                                     (gx#syntax-e _%$%tl193030193051%_)))
                                (let ((_%$%hd193032193057%_
                                       (##car _%$%e193031193054%_))
                                      (_%$%tl193033193059%_
                                       (##cdr _%$%e193031193054%_)))
                                  (let ((_%hd193062%_ _%$%hd193032193057%_))
                                    (if (gx#stx-pair? _%$%tl193033193059%_)
                                        (let ((_%$%e193034193064%_
                                               (gx#syntax-e
                                                _%$%tl193033193059%_)))
                                          (let ((_%$%hd193035193067%_
                                                 (##car _%$%e193034193064%_))
                                                (_%$%tl193036193069%_
                                                 (##cdr _%$%e193034193064%_)))
                                            (let ((_%expr193072%_
                                                   _%$%hd193035193067%_))
                                              (if (gx#stx-null?
                                                   _%$%tl193036193069%_)
                                                  (if (gx#core-bind-values?
                                                       _%hd193062%_)
                                                      (begin
                                                        (gx#core-bind-values!__0
                                                         _%hd193062%_)
                                                        (gx#core-quote-syntax__1
                                                         (cons (gx#core-quote-syntax__0
                                                                '%#define-values)
                                                               (cons (gx#core-quote-bind-values
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%hd193062%_)
                             (cons (gx#core-expand-expression _%expr193072%_)
                                   '())))
                 (gx#stx-source _%stx193014%_)))
              (_%$%E193027193042%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E193027193042%_)))))
                                        (_%$%E193027193042%_)))))
                              (_%$%E193027193042%_))))
                      (_%$%E193027193042%_))))
               (_%$%E193016193108%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e193015193038%_)
                      (let ((_%$%e193018193078%_
                             (gx#syntax-e _%$%e193015193038%_)))
                        (let ((_%$%hd193019193081%_
                               (##car _%$%e193018193078%_))
                              (_%$%tl193020193083%_
                               (##cdr _%$%e193018193078%_)))
                          (if (gx#stx-pair? _%$%tl193020193083%_)
                              (let ((_%$%e193021193086%_
                                     (gx#syntax-e _%$%tl193020193083%_)))
                                (let ((_%$%hd193022193089%_
                                       (##car _%$%e193021193086%_))
                                      (_%$%tl193023193091%_
                                       (##cdr _%$%e193021193086%_)))
                                  (let ((_%hd193094%_ _%$%hd193022193089%_))
                                    (if (gx#stx-pair? _%$%tl193023193091%_)
                                        (let ((_%$%e193024193096%_
                                               (gx#syntax-e
                                                _%$%tl193023193091%_)))
                                          (let ((_%$%hd193025193099%_
                                                 (##car _%$%e193024193096%_))
                                                (_%$%tl193026193101%_
                                                 (##cdr _%$%e193024193096%_)))
                                            (let* ((_%expr193104%_
                                                    _%$%hd193025193099%_)
                                                   (_%props193106%_
                                                    _%$%tl193026193101%_))
                                              (if (and (gx#stx-list?
                                                        _%props193106%_)
                                                       (not (gx#stx-null?
                                                             _%props193106%_)))
                                                  (gx#core-cons
                                                   '%#begin
                                                   (cons (gx#core-cons
                                                          '%#define-values
                                                          (cons _%hd193094%_
                                                                (cons _%expr193104%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '())))
                 (cons (gx#core-cons
                        '%#bind-runtime-properties!
                        (cons _%hd193094%_ (cons _%props193106%_ '())))
                       '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E193017193074%_)))))
                                        (_%$%E193017193074%_)))))
                              (_%$%E193017193074%_))))
                      (_%$%E193017193074%_)))))
          (_%$%E193016193108%_))))
    (define gx#core-expand-define-runtime%
      (lambda (_%stx192953%_)
        (let* ((_%$%e192954192967%_ _%stx192953%_)
               (_%$%E192956192971%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192954192967%_)))
               (_%$%E192955193010%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192954192967%_)
                      (let ((_%$%e192957192975%_
                             (gx#syntax-e _%$%e192954192967%_)))
                        (let ((_%$%hd192958192978%_
                               (##car _%$%e192957192975%_))
                              (_%$%tl192959192980%_
                               (##cdr _%$%e192957192975%_)))
                          (if (gx#stx-pair? _%$%tl192959192980%_)
                              (let ((_%$%e192960192983%_
                                     (gx#syntax-e _%$%tl192959192980%_)))
                                (let ((_%$%hd192961192986%_
                                       (##car _%$%e192960192983%_))
                                      (_%$%tl192962192988%_
                                       (##cdr _%$%e192960192983%_)))
                                  (let ((_%id192991%_ _%$%hd192961192986%_))
                                    (if (gx#stx-pair? _%$%tl192962192988%_)
                                        (let ((_%$%e192963192993%_
                                               (gx#syntax-e
                                                _%$%tl192962192988%_)))
                                          (let ((_%$%hd192964192996%_
                                                 (##car _%$%e192963192993%_))
                                                (_%$%tl192965192998%_
                                                 (##cdr _%$%e192963192993%_)))
                                            (let* ((_%binding-id193001%_
                                                    _%$%hd192964192996%_)
                                                   (_%props193003%_
                                                    _%$%tl192965192998%_))
                                              (if (and (gx#identifier?
                                                        _%id192991%_)
                                                       (gx#identifier?
                                                        _%binding-id193001%_)
                                                       (gx#stx-list?
                                                        _%props193003%_))
                                                  (let* ((_%eid193005%_
                                                          (gx#stx-e
                                                           _%binding-id193001%_))
                                                         (_%bind193007%_
                                                          (gx#core-bind-runtime-reference!__0
                                                           _%id192991%_
                                                           _%eid193005%_)))
                                                    (gx#core-bind-runtime-properties!
                                                     _%bind193007%_
                                                     _%props193003%_)
                                                    (gx#core-quote-syntax__0
                                                     (cons (gx#core-quote-syntax__0
                                                            '%#define-runtime)
                                                           (cons (gx#core-quote-syntax__0
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%id192991%_)
                         (cons _%eid193005%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E192956192971%_)))))
                                        (_%$%E192956192971%_)))))
                              (_%$%E192956192971%_))))
                      (_%$%E192956192971%_)))))
          (_%$%E192955193010%_))))
    (define gx#core-expand-bind-runtime-properties%
      (lambda (_%stx192886%_)
        (let* ((_%$%e192887192903%_ _%stx192886%_)
               (_%$%E192889192907%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192887192903%_)))
               (_%$%E192888192949%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192887192903%_)
                      (let ((_%$%e192890192911%_
                             (gx#syntax-e _%$%e192887192903%_)))
                        (let ((_%$%hd192891192914%_
                               (##car _%$%e192890192911%_))
                              (_%$%tl192892192916%_
                               (##cdr _%$%e192890192911%_)))
                          (if (gx#stx-pair? _%$%tl192892192916%_)
                              (let ((_%$%e192893192919%_
                                     (gx#syntax-e _%$%tl192892192916%_)))
                                (let ((_%$%hd192894192922%_
                                       (##car _%$%e192893192919%_))
                                      (_%$%tl192895192924%_
                                       (##cdr _%$%e192893192919%_)))
                                  (if (gx#stx-pair? _%$%hd192894192922%_)
                                      (let ((_%$%e192899192927%_
                                             (gx#syntax-e
                                              _%$%hd192894192922%_)))
                                        (let ((_%$%hd192900192930%_
                                               (##car _%$%e192899192927%_))
                                              (_%$%tl192901192932%_
                                               (##cdr _%$%e192899192927%_)))
                                          (let ((_%id192935%_
                                                 _%$%hd192900192930%_))
                                            (if (gx#stx-null?
                                                 _%$%tl192901192932%_)
                                                (if (gx#stx-pair?
                                                     _%$%tl192895192924%_)
                                                    (let ((_%$%e192896192937%_
                                                           (gx#syntax-e
                                                            _%$%tl192895192924%_)))
                                                      (let ((_%$%hd192897192940%_
                                                             (##car _%$%e192896192937%_))
                                                            (_%$%tl192898192942%_
                                                             (##cdr _%$%e192896192937%_)))
                                                        (let ((_%props192945%_
                                                               _%$%hd192897192940%_))
                                                          (if (gx#stx-null?
                                                               _%$%tl192898192942%_)
                                                              (if (and (gx#identifier?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                _%id192935%_)
                               (gx#stx-list? _%props192945%_))
                          (let ((_%bind192947%_
                                 (gx#resolve-identifier__0 _%id192935%_)))
                            (if (##structure-instance-of?
                                 _%bind192947%_
                                 'gx#runtime-binding::t)
                                '#!void
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; expected runtime binding"
                                 _%stx192886%_
                                 _%id192935%_
                                 _%bind192947%_))
                            (gx#core-bind-runtime-properties!
                             _%bind192947%_
                             _%props192945%_)
                            (gx#core-cons '%#begin '()))
                          (_%$%E192889192907%_))
                      (_%$%E192889192907%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%E192889192907%_))
                                                (_%$%E192889192907%_)))))
                                      (_%$%E192889192907%_))))
                              (_%$%E192889192907%_))))
                      (_%$%E192889192907%_)))))
          (_%$%E192888192949%_))))
    (define gx#core-bind-runtime-properties!
      (lambda (_%bind192821%_ _%props192822%_)
        (letrec ((_%eval-prop192824%_
                  (lambda (_%prop192884%_)
                    (gx#eval-expression+1 _%prop192884%_))))
          (let _%loop192826%_ ((_%rest192828%_ _%props192822%_)
                               (_%props192829%_ '()))
            (let* ((_%$%e192830192841%_ _%rest192828%_)
                   (_%$%E192839192845%_
                    (lambda ()
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid syntax-case clause"
                       _%$%e192830192841%_)))
                   (_%$%E192832192849%_
                    (lambda ()
                      (if (gx#stx-null? _%$%e192830192841%_)
                          (if (null? _%props192829%_)
                              '#!void
                              (##structure-set!
                               _%bind192821%_
                               (reverse! _%props192829%_)
                               '4
                               gx#binding::t
                               '#f))
                          (_%$%E192839192845%_))))
                   (_%$%E192831192880%_
                    (lambda ()
                      (if (gx#stx-pair? _%$%e192830192841%_)
                          (let ((_%$%e192833192853%_
                                 (gx#syntax-e _%$%e192830192841%_)))
                            (let ((_%$%hd192834192856%_
                                   (##car _%$%e192833192853%_))
                                  (_%$%tl192835192858%_
                                   (##cdr _%$%e192833192853%_)))
                              (let ((_%key192861%_ _%$%hd192834192856%_))
                                (if (gx#stx-pair? _%$%tl192835192858%_)
                                    (let ((_%$%e192836192863%_
                                           (gx#syntax-e _%$%tl192835192858%_)))
                                      (let ((_%$%hd192837192866%_
                                             (##car _%$%e192836192863%_))
                                            (_%$%tl192838192868%_
                                             (##cdr _%$%e192836192863%_)))
                                        (let* ((_%prop192871%_
                                                _%$%hd192837192866%_)
                                               (_%rest192873%_
                                                _%$%tl192838192868%_))
                                          (if (gx#stx-keyword? _%key192861%_)
                                              (let* ((_%key192875%_
                                                      (gx#stx-e _%key192861%_))
                                                     (_%$e192877%_
                                                      _%key192875%_))
                                                (if (eq? 'macro: _%$e192877%_)
                                                    (begin
                                                      (##structure-set!
                                                       _%bind192821%_
                                                       (if (gx#identifier?
                                                            _%prop192871%_)
                                                           (gx#core-quote-syntax__0
                                                            _%prop192871%_)
                                                           (gx#eval-expression+1
                                                            _%prop192871%_))
                                                       '6
                                                       gx#runtime-binding::t
                                                       '#f)
                                                      (_%loop192826%_
                                                       _%rest192873%_
                                                       _%props192829%_))
                                                    (if (eq? 'type:
                                                             _%$e192877%_)
                                                        (begin
                                                          (##structure-set!
                                                           _%bind192821%_
                                                           (gx#eval-expression+1
                                                            _%prop192871%_)
                                                           '5
                                                           gx#runtime-binding::t
                                                           '#f)
                                                          (_%loop192826%_
                                                           _%rest192873%_
                                                           _%props192829%_))
                                                        (_%loop192826%_
                                                         _%rest192873%_
                                                         (cons (gx#eval-expression+1
                                                                _%prop192871%_)
                                                               (cons _%key192875%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%props192829%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E192832192849%_)))))
                                    (_%$%E192832192849%_)))))
                          (_%$%E192832192849%_)))))
              (_%$%E192831192880%_))))))
    (define gx#core-expand-define-syntax%
      (lambda (_%stx192764%_)
        (let* ((_%$%e192765192778%_ _%stx192764%_)
               (_%$%E192767192782%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192765192778%_)))
               (_%$%E192766192817%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192765192778%_)
                      (let ((_%$%e192768192786%_
                             (gx#syntax-e _%$%e192765192778%_)))
                        (let ((_%$%hd192769192789%_
                               (##car _%$%e192768192786%_))
                              (_%$%tl192770192791%_
                               (##cdr _%$%e192768192786%_)))
                          (if (gx#stx-pair? _%$%tl192770192791%_)
                              (let ((_%$%e192771192794%_
                                     (gx#syntax-e _%$%tl192770192791%_)))
                                (let ((_%$%hd192772192797%_
                                       (##car _%$%e192771192794%_))
                                      (_%$%tl192773192799%_
                                       (##cdr _%$%e192771192794%_)))
                                  (let ((_%id192802%_ _%$%hd192772192797%_))
                                    (if (gx#stx-pair? _%$%tl192773192799%_)
                                        (let ((_%$%e192774192804%_
                                               (gx#syntax-e
                                                _%$%tl192773192799%_)))
                                          (let ((_%$%hd192775192807%_
                                                 (##car _%$%e192774192804%_))
                                                (_%$%tl192776192809%_
                                                 (##cdr _%$%e192774192804%_)))
                                            (let ((_%expr192812%_
                                                   _%$%hd192775192807%_))
                                              (if (gx#stx-null?
                                                   _%$%tl192776192809%_)
                                                  (if (gx#identifier?
                                                       _%id192802%_)
                                                      (let ((_g194112_
                                                             (gx#core-expand-expression+1
                                                              _%expr192812%_)))
                                                        (begin
                                                          (let ((_g194113_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (if (##values? _g194112_)
                             (##values-length _g194112_)
                             1)))
                    (if (not (##fx= _g194113_ 2))
                        (error "Context expects 2 values" _g194113_)))
                  (let ((_%e-stx192814%_ (##values-ref _g194112_ 0))
                        (_%e192815%_ (##values-ref _g194112_ 1)))
                    (begin
                      (gx#core-bind-syntax!__0 _%id192802%_ _%e192815%_)
                      (gx#core-quote-syntax__1
                       (cons (gx#core-quote-syntax__0 '%#define-syntax)
                             (cons (gx#core-quote-syntax__0 _%id192802%_)
                                   (cons _%e-stx192814%_ '())))
                       (gx#stx-source _%stx192764%_))))))
              (_%$%E192767192782%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E192767192782%_)))))
                                        (_%$%E192767192782%_)))))
                              (_%$%E192767192782%_))))
                      (_%$%E192767192782%_)))))
          (_%$%E192766192817%_))))
    (define gx#core-expand-define-alias%
      (lambda (_%stx192708%_)
        (let* ((_%$%e192709192722%_ _%stx192708%_)
               (_%$%E192711192726%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192709192722%_)))
               (_%$%E192710192760%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192709192722%_)
                      (let ((_%$%e192712192730%_
                             (gx#syntax-e _%$%e192709192722%_)))
                        (let ((_%$%hd192713192733%_
                               (##car _%$%e192712192730%_))
                              (_%$%tl192714192735%_
                               (##cdr _%$%e192712192730%_)))
                          (if (gx#stx-pair? _%$%tl192714192735%_)
                              (let ((_%$%e192715192738%_
                                     (gx#syntax-e _%$%tl192714192735%_)))
                                (let ((_%$%hd192716192741%_
                                       (##car _%$%e192715192738%_))
                                      (_%$%tl192717192743%_
                                       (##cdr _%$%e192715192738%_)))
                                  (let ((_%id192746%_ _%$%hd192716192741%_))
                                    (if (gx#stx-pair? _%$%tl192717192743%_)
                                        (let ((_%$%e192718192748%_
                                               (gx#syntax-e
                                                _%$%tl192717192743%_)))
                                          (let ((_%$%hd192719192751%_
                                                 (##car _%$%e192718192748%_))
                                                (_%$%tl192720192753%_
                                                 (##cdr _%$%e192718192748%_)))
                                            (let ((_%alias-id192756%_
                                                   _%$%hd192719192751%_))
                                              (if (gx#stx-null?
                                                   _%$%tl192720192753%_)
                                                  (if (and (gx#identifier?
                                                            _%id192746%_)
                                                           (gx#identifier?
                                                            _%alias-id192756%_))
                                                      (let ((_%alias-id192758%_
                                                             (gx#core-quote-syntax__0
                                                              _%alias-id192756%_)))
                                                        (gx#core-bind-alias!__0
                                                         _%id192746%_
                                                         _%alias-id192758%_)
                                                        (gx#core-quote-syntax__0
                                                         (cons (gx#core-quote-syntax__0
                                                                '%#define-alias)
                                                               (cons (gx#core-quote-syntax__0
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%id192746%_)
                             (cons _%alias-id192758%_ '())))))
              (_%$%E192711192726%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E192711192726%_)))))
                                        (_%$%E192711192726%_)))))
                              (_%$%E192711192726%_))))
                      (_%$%E192711192726%_)))))
          (_%$%E192710192760%_))))
    (define gx#core-expand-lambda%__%
      (lambda (_%stx192651%_ _%wrap?192652%_)
        (let* ((_%$%e192653192663%_ _%stx192651%_)
               (_%$%E192655192667%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192653192663%_)))
               (_%$%E192654192694%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192653192663%_)
                      (let ((_%$%e192656192671%_
                             (gx#syntax-e _%$%e192653192663%_)))
                        (let ((_%$%hd192657192674%_
                               (##car _%$%e192656192671%_))
                              (_%$%tl192658192676%_
                               (##cdr _%$%e192656192671%_)))
                          (if (gx#stx-pair? _%$%tl192658192676%_)
                              (let ((_%$%e192659192679%_
                                     (gx#syntax-e _%$%tl192658192676%_)))
                                (let ((_%$%hd192660192682%_
                                       (##car _%$%e192659192679%_))
                                      (_%$%tl192661192684%_
                                       (##cdr _%$%e192659192679%_)))
                                  (let* ((_%hd192687%_ _%$%hd192660192682%_)
                                         (_%body192689%_ _%$%tl192661192684%_))
                                    (if (gx#core-bind-values? _%hd192687%_)
                                        (call-with-parameters__1
                                         (lambda ()
                                           (gx#core-bind-values!__0
                                            _%hd192687%_)
                                           (let ((_%body192692%_
                                                  (cons (gx#core-quote-bind-values
                                                         _%hd192687%_)
                                                        (cons (gx#core-expand-local-block
                                                               _%stx192651%_
                                                               _%body192689%_)
                                                              '()))))
                                             (if _%wrap?192652%_
                                                 (gx#core-quote-syntax__1
                                                  (gx#core-cons
                                                   '%#lambda
                                                   _%body192692%_)
                                                  (gx#stx-source
                                                   _%stx192651%_))
                                                 _%body192692%_)))
                                         gx#current-expander-context
                                         (let ((__obj194095
                                                (##structure
                                                 gx#local-context::t
                                                 '#f
                                                 '#f
                                                 '#f
                                                 '#f
                                                 '#f)))
                                           (gx#local-context:::init!__0
                                            __obj194095)
                                           __obj194095))
                                        (_%$%E192655192667%_)))))
                              (_%$%E192655192667%_))))
                      (_%$%E192655192667%_)))))
          (_%$%E192654192694%_))))
    (define gx#core-expand-lambda%__0
      (lambda (_%stx192701%_)
        (let ((_%wrap?192703%_ '#t))
          (gx#core-expand-lambda%__% _%stx192701%_ _%wrap?192703%_))))
    (define gx#core-expand-lambda%
      (lambda _g194114_
        (let ((_g194115_ (##length _g194114_)))
          (cond ((##fx= _g194115_ 1)
                 (apply gx#core-expand-lambda%__0 _g194114_))
                ((##fx= _g194115_ 2)
                 (apply gx#core-expand-lambda%__% _g194114_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-lambda%
                  _g194114_))))))
    (define gx#core-expand-case-lambda%
      (lambda (_%stx192615%_)
        (let* ((_%$%e192616192623%_ _%stx192615%_)
               (_%$%E192618192627%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192616192623%_)))
               (_%$%E192617192646%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192616192623%_)
                      (let ((_%$%e192619192631%_
                             (gx#syntax-e _%$%e192616192623%_)))
                        (let ((_%$%hd192620192634%_
                               (##car _%$%e192619192631%_))
                              (_%$%tl192621192636%_
                               (##cdr _%$%e192619192631%_)))
                          (let ((_%clauses192639%_ _%$%tl192621192636%_))
                            (if (gx#stx-list? _%clauses192639%_)
                                (gx#core-quote-syntax__1
                                 (gx#core-cons
                                  '%#case-lambda
                                  (gx#stx-map1
                                   (lambda (_%clause192641%_)
                                     (gx#core-expand-lambda%__%
                                      (gx#stx-wrap-source
                                       (cons '%#case-lambda-clause
                                             _%clause192641%_)
                                       (let ((_%$e192643%_
                                              (gx#stx-source
                                               _%clause192641%_)))
                                         (if _%$e192643%_
                                             _%$e192643%_
                                             (gx#stx-source _%stx192615%_))))
                                      '#f))
                                   _%clauses192639%_))
                                 (gx#stx-source _%stx192615%_))
                                (_%$%E192618192627%_)))))
                      (_%$%E192618192627%_)))))
          (_%$%E192617192646%_))))
    (define gx#core-expand-let-values%
      (lambda (_%stx192569%_)
        (let* ((_%$%e192570192580%_ _%stx192569%_)
               (_%$%E192572192584%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192570192580%_)))
               (_%$%E192571192611%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192570192580%_)
                      (let ((_%$%e192573192588%_
                             (gx#syntax-e _%$%e192570192580%_)))
                        (let ((_%$%hd192574192591%_
                               (##car _%$%e192573192588%_))
                              (_%$%tl192575192593%_
                               (##cdr _%$%e192573192588%_)))
                          (if (gx#stx-pair? _%$%tl192575192593%_)
                              (let ((_%$%e192576192596%_
                                     (gx#syntax-e _%$%tl192575192593%_)))
                                (let ((_%$%hd192577192599%_
                                       (##car _%$%e192576192596%_))
                                      (_%$%tl192578192601%_
                                       (##cdr _%$%e192576192596%_)))
                                  (let* ((_%hd192604%_ _%$%hd192577192599%_)
                                         (_%body192606%_ _%$%tl192578192601%_))
                                    (if (gx#core-expand-let-bind? _%hd192604%_)
                                        (let ((_%expressions192608%_
                                               (gx#stx-map1
                                                gx#core-expand-let-bind-expression
                                                _%hd192604%_)))
                                          (call-with-parameters__1
                                           (lambda ()
                                             (gx#stx-for-each1
                                              gx#core-expand-let-bind-values!
                                              _%hd192604%_)
                                             (gx#core-quote-syntax__1
                                              (cons (gx#core-quote-syntax__0
                                                     '%#let-values)
                                                    (cons (gx#stx-map2
                                                           gx#core-expand-let-bind-quote
                                                           _%hd192604%_
                                                           _%expressions192608%_)
                                                          (cons (gx#core-expand-local-block
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%stx192569%_
                         _%body192606%_)
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (gx#stx-source _%stx192569%_)))
                                           gx#current-expander-context
                                           (let ((__obj194096
                                                  (##structure
                                                   gx#local-context::t
                                                   '#f
                                                   '#f
                                                   '#f
                                                   '#f
                                                   '#f)))
                                             (gx#local-context:::init!__0
                                              __obj194096)
                                             __obj194096)))
                                        (_%$%E192572192584%_)))))
                              (_%$%E192572192584%_))))
                      (_%$%E192572192584%_)))))
          (_%$%E192571192611%_))))
    (define gx#core-expand-letrec-values%__%
      (lambda (_%stx192514%_ _%form192515%_)
        (let* ((_%$%e192516192526%_ _%stx192514%_)
               (_%$%E192518192530%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192516192526%_)))
               (_%$%E192517192555%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192516192526%_)
                      (let ((_%$%e192519192534%_
                             (gx#syntax-e _%$%e192516192526%_)))
                        (let ((_%$%hd192520192537%_
                               (##car _%$%e192519192534%_))
                              (_%$%tl192521192539%_
                               (##cdr _%$%e192519192534%_)))
                          (if (gx#stx-pair? _%$%tl192521192539%_)
                              (let ((_%$%e192522192542%_
                                     (gx#syntax-e _%$%tl192521192539%_)))
                                (let ((_%$%hd192523192545%_
                                       (##car _%$%e192522192542%_))
                                      (_%$%tl192524192547%_
                                       (##cdr _%$%e192522192542%_)))
                                  (let* ((_%hd192550%_ _%$%hd192523192545%_)
                                         (_%body192552%_ _%$%tl192524192547%_))
                                    (if (gx#core-expand-let-bind? _%hd192550%_)
                                        (call-with-parameters__1
                                         (lambda ()
                                           (gx#stx-for-each1
                                            gx#core-expand-let-bind-values!
                                            _%hd192550%_)
                                           (gx#core-quote-syntax__1
                                            (cons (gx#core-quote-syntax__0
                                                   _%form192515%_)
                                                  (cons (gx#stx-map2
                                                         gx#core-expand-let-bind-quote
                                                         _%hd192550%_
                                                         (gx#stx-map1
                                                          gx#core-expand-let-bind-expression
                                                          _%hd192550%_))
                                                        (cons (gx#core-expand-local-block
                                                               _%stx192514%_
                                                               _%body192552%_)
                                                              '())))
                                            (gx#stx-source _%stx192514%_)))
                                         gx#current-expander-context
                                         (let ((__obj194097
                                                (##structure
                                                 gx#local-context::t
                                                 '#f
                                                 '#f
                                                 '#f
                                                 '#f
                                                 '#f)))
                                           (gx#local-context:::init!__0
                                            __obj194097)
                                           __obj194097))
                                        (_%$%E192518192530%_)))))
                              (_%$%E192518192530%_))))
                      (_%$%E192518192530%_)))))
          (_%$%E192517192555%_))))
    (define gx#core-expand-letrec-values%__0
      (lambda (_%stx192562%_)
        (let ((_%form192564%_ '%#letrec-values))
          (gx#core-expand-letrec-values%__% _%stx192562%_ _%form192564%_))))
    (define gx#core-expand-letrec-values%
      (lambda _g194116_
        (let ((_g194117_ (##length _g194116_)))
          (cond ((##fx= _g194117_ 1)
                 (apply gx#core-expand-letrec-values%__0 _g194116_))
                ((##fx= _g194117_ 2)
                 (apply gx#core-expand-letrec-values%__% _g194116_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-letrec-values%
                  _g194116_))))))
    (define gx#core-expand-letrec*-values%
      (lambda (_%stx192511%_)
        (gx#core-expand-letrec-values%__% _%stx192511%_ '%#letrec*-values)))
    (define gx#core-expand-let-bind?
      (lambda (_%stx192468%_)
        (if (gx#stx-list? _%stx192468%_)
            (gx#stx-andmap
             (lambda (_%bind192470%_)
               (let* ((_%$%e192471192481%_ _%bind192470%_)
                      (_%$%E192473192485%_ (lambda () '#f))
                      (_%$%E192472192507%_
                       (lambda ()
                         (if (gx#stx-pair? _%$%e192471192481%_)
                             (let ((_%$%e192474192489%_
                                    (gx#syntax-e _%$%e192471192481%_)))
                               (let ((_%$%hd192475192492%_
                                      (##car _%$%e192474192489%_))
                                     (_%$%tl192476192494%_
                                      (##cdr _%$%e192474192489%_)))
                                 (let ((_%hd192497%_ _%$%hd192475192492%_))
                                   (if (gx#stx-pair? _%$%tl192476192494%_)
                                       (let ((_%$%e192477192499%_
                                              (gx#syntax-e
                                               _%$%tl192476192494%_)))
                                         (let ((_%$%hd192478192502%_
                                                (##car _%$%e192477192499%_))
                                               (_%$%tl192479192504%_
                                                (##cdr _%$%e192477192499%_)))
                                           (if (gx#stx-null?
                                                _%$%tl192479192504%_)
                                               (gx#core-bind-values?
                                                _%hd192497%_)
                                               (_%$%E192473192485%_))))
                                       (_%$%E192473192485%_)))))
                             (_%$%E192473192485%_)))))
                 (_%$%E192472192507%_)))
             _%stx192468%_)
            '#f)))
    (define gx#core-expand-let-bind-expression
      (lambda (_%bind192427%_)
        (let* ((_%$%e192428192438%_ _%bind192427%_)
               (_%$%E192430192442%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192428192438%_)))
               (_%$%E192429192464%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192428192438%_)
                      (let ((_%$%e192431192446%_
                             (gx#syntax-e _%$%e192428192438%_)))
                        (let ((_%$%hd192432192449%_
                               (##car _%$%e192431192446%_))
                              (_%$%tl192433192451%_
                               (##cdr _%$%e192431192446%_)))
                          (if (gx#stx-pair? _%$%tl192433192451%_)
                              (let ((_%$%e192434192454%_
                                     (gx#syntax-e _%$%tl192433192451%_)))
                                (let ((_%$%hd192435192457%_
                                       (##car _%$%e192434192454%_))
                                      (_%$%tl192436192459%_
                                       (##cdr _%$%e192434192454%_)))
                                  (let ((_%expr192462%_ _%$%hd192435192457%_))
                                    (if (gx#stx-null? _%$%tl192436192459%_)
                                        (gx#core-expand-expression
                                         _%expr192462%_)
                                        (_%$%E192430192442%_)))))
                              (_%$%E192430192442%_))))
                      (_%$%E192430192442%_)))))
          (_%$%E192429192464%_))))
    (define gx#core-expand-let-bind-values!
      (lambda (_%bind192386%_)
        (let* ((_%$%e192387192397%_ _%bind192386%_)
               (_%$%E192389192401%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192387192397%_)))
               (_%$%E192388192423%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192387192397%_)
                      (let ((_%$%e192390192405%_
                             (gx#syntax-e _%$%e192387192397%_)))
                        (let ((_%$%hd192391192408%_
                               (##car _%$%e192390192405%_))
                              (_%$%tl192392192410%_
                               (##cdr _%$%e192390192405%_)))
                          (let ((_%hd192413%_ _%$%hd192391192408%_))
                            (if (gx#stx-pair? _%$%tl192392192410%_)
                                (let ((_%$%e192393192415%_
                                       (gx#syntax-e _%$%tl192392192410%_)))
                                  (let ((_%$%hd192394192418%_
                                         (##car _%$%e192393192415%_))
                                        (_%$%tl192395192420%_
                                         (##cdr _%$%e192393192415%_)))
                                    (if (gx#stx-null? _%$%tl192395192420%_)
                                        (gx#core-bind-values!__0 _%hd192413%_)
                                        (_%$%E192389192401%_))))
                                (_%$%E192389192401%_)))))
                      (_%$%E192389192401%_)))))
          (_%$%E192388192423%_))))
    (define gx#core-expand-let-bind-quote
      (lambda (_%bind192344%_ _%expr192345%_)
        (let* ((_%$%e192346192356%_ _%bind192344%_)
               (_%$%E192348192360%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192346192356%_)))
               (_%$%E192347192382%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192346192356%_)
                      (let ((_%$%e192349192364%_
                             (gx#syntax-e _%$%e192346192356%_)))
                        (let ((_%$%hd192350192367%_
                               (##car _%$%e192349192364%_))
                              (_%$%tl192351192369%_
                               (##cdr _%$%e192349192364%_)))
                          (let ((_%hd192372%_ _%$%hd192350192367%_))
                            (if (gx#stx-pair? _%$%tl192351192369%_)
                                (let ((_%$%e192352192374%_
                                       (gx#syntax-e _%$%tl192351192369%_)))
                                  (let ((_%$%hd192353192377%_
                                         (##car _%$%e192352192374%_))
                                        (_%$%tl192354192379%_
                                         (##cdr _%$%e192352192374%_)))
                                    (if (gx#stx-null? _%$%tl192354192379%_)
                                        (cons (gx#core-quote-bind-values
                                               _%hd192372%_)
                                              (cons _%expr192345%_ '()))
                                        (_%$%E192348192360%_))))
                                (_%$%E192348192360%_)))))
                      (_%$%E192348192360%_)))))
          (_%$%E192347192382%_))))
    (define gx#core-expand-let-syntax%
      (lambda (_%stx192298%_)
        (let* ((_%$%e192299192309%_ _%stx192298%_)
               (_%$%E192301192313%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192299192309%_)))
               (_%$%E192300192340%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192299192309%_)
                      (let ((_%$%e192302192317%_
                             (gx#syntax-e _%$%e192299192309%_)))
                        (let ((_%$%hd192303192320%_
                               (##car _%$%e192302192317%_))
                              (_%$%tl192304192322%_
                               (##cdr _%$%e192302192317%_)))
                          (if (gx#stx-pair? _%$%tl192304192322%_)
                              (let ((_%$%e192305192325%_
                                     (gx#syntax-e _%$%tl192304192322%_)))
                                (let ((_%$%hd192306192328%_
                                       (##car _%$%e192305192325%_))
                                      (_%$%tl192307192330%_
                                       (##cdr _%$%e192305192325%_)))
                                  (let* ((_%hd192333%_ _%$%hd192306192328%_)
                                         (_%body192335%_ _%$%tl192307192330%_))
                                    (if (gx#core-expand-let-bind-syntax?
                                         _%hd192333%_)
                                        (let ((_%expanders192337%_
                                               (gx#stx-map1
                                                gx#core-expand-let-bind-syntax-expression
                                                _%hd192333%_)))
                                          (call-with-parameters__1
                                           (lambda ()
                                             (gx#stx-for-each2
                                              gx#core-expand-let-bind-syntax!
                                              _%hd192333%_
                                              _%expanders192337%_)
                                             (gx#core-expand-local-block
                                              _%stx192298%_
                                              _%body192335%_))
                                           gx#current-expander-context
                                           (let ((__obj194098
                                                  (##structure
                                                   gx#local-context::t
                                                   '#f
                                                   '#f
                                                   '#f
                                                   '#f
                                                   '#f)))
                                             (gx#local-context:::init!__0
                                              __obj194098)
                                             __obj194098)))
                                        (_%$%E192301192313%_)))))
                              (_%$%E192301192313%_))))
                      (_%$%E192301192313%_)))))
          (_%$%E192300192340%_))))
    (define gx#core-expand-letrec-syntax%
      (lambda (_%stx192247%_)
        (let* ((_%$%e192248192258%_ _%stx192247%_)
               (_%$%E192250192262%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192248192258%_)))
               (_%$%E192249192294%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192248192258%_)
                      (let ((_%$%e192251192266%_
                             (gx#syntax-e _%$%e192248192258%_)))
                        (let ((_%$%hd192252192269%_
                               (##car _%$%e192251192266%_))
                              (_%$%tl192253192271%_
                               (##cdr _%$%e192251192266%_)))
                          (if (gx#stx-pair? _%$%tl192253192271%_)
                              (let ((_%$%e192254192274%_
                                     (gx#syntax-e _%$%tl192253192271%_)))
                                (let ((_%$%hd192255192277%_
                                       (##car _%$%e192254192274%_))
                                      (_%$%tl192256192279%_
                                       (##cdr _%$%e192254192274%_)))
                                  (let* ((_%hd192282%_ _%$%hd192255192277%_)
                                         (_%body192284%_ _%$%tl192256192279%_))
                                    (if (gx#core-expand-let-bind-syntax?
                                         _%hd192282%_)
                                        (call-with-parameters__1
                                         (lambda ()
                                           (gx#stx-for-each2
                                            gx#core-expand-let-bind-syntax!
                                            _%hd192282%_
                                            (make-list
                                             (gx#stx-length _%hd192282%_)
                                             '#!void))
                                           (gx#stx-for-each2
                                            (lambda (_%$%g192286192289%_
                                                     _%$%g192287192291%_)
                                              (gx#core-expand-let-bind-syntax!__%
                                               _%$%g192286192289%_
                                               _%$%g192287192291%_
                                               '#t))
                                            _%hd192282%_
                                            (gx#stx-map1
                                             gx#core-expand-let-bind-syntax-expression
                                             _%hd192282%_))
                                           (gx#core-expand-local-block
                                            _%stx192247%_
                                            _%body192284%_))
                                         gx#current-expander-context
                                         (let ((__obj194099
                                                (##structure
                                                 gx#local-context::t
                                                 '#f
                                                 '#f
                                                 '#f
                                                 '#f
                                                 '#f)))
                                           (gx#local-context:::init!__0
                                            __obj194099)
                                           __obj194099))
                                        (_%$%E192250192262%_)))))
                              (_%$%E192250192262%_))))
                      (_%$%E192250192262%_)))))
          (_%$%E192249192294%_))))
    (define gx#core-expand-let-bind-syntax?
      (lambda (_%stx192204%_)
        (if (gx#stx-list? _%stx192204%_)
            (gx#stx-andmap
             (lambda (_%bind192206%_)
               (let* ((_%$%e192207192217%_ _%bind192206%_)
                      (_%$%E192209192221%_ (lambda () '#f))
                      (_%$%E192208192243%_
                       (lambda ()
                         (if (gx#stx-pair? _%$%e192207192217%_)
                             (let ((_%$%e192210192225%_
                                    (gx#syntax-e _%$%e192207192217%_)))
                               (let ((_%$%hd192211192228%_
                                      (##car _%$%e192210192225%_))
                                     (_%$%tl192212192230%_
                                      (##cdr _%$%e192210192225%_)))
                                 (let ((_%hd192233%_ _%$%hd192211192228%_))
                                   (if (gx#stx-pair? _%$%tl192212192230%_)
                                       (let ((_%$%e192213192235%_
                                              (gx#syntax-e
                                               _%$%tl192212192230%_)))
                                         (let ((_%$%hd192214192238%_
                                                (##car _%$%e192213192235%_))
                                               (_%$%tl192215192240%_
                                                (##cdr _%$%e192213192235%_)))
                                           (if (gx#stx-null?
                                                _%$%tl192215192240%_)
                                               (gx#identifier? _%hd192233%_)
                                               (_%$%E192209192221%_))))
                                       (_%$%E192209192221%_)))))
                             (_%$%E192209192221%_)))))
                 (_%$%E192208192243%_)))
             _%stx192204%_)
            '#f)))
    (define gx#core-expand-let-bind-syntax-expression
      (lambda (_%bind192160%_)
        (let* ((_%$%e192161192171%_ _%bind192160%_)
               (_%$%E192163192175%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192161192171%_)))
               (_%$%E192162192200%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192161192171%_)
                      (let ((_%$%e192164192179%_
                             (gx#syntax-e _%$%e192161192171%_)))
                        (let ((_%$%hd192165192182%_
                               (##car _%$%e192164192179%_))
                              (_%$%tl192166192184%_
                               (##cdr _%$%e192164192179%_)))
                          (if (gx#stx-pair? _%$%tl192166192184%_)
                              (let ((_%$%e192167192187%_
                                     (gx#syntax-e _%$%tl192166192184%_)))
                                (let ((_%$%hd192168192190%_
                                       (##car _%$%e192167192187%_))
                                      (_%$%tl192169192192%_
                                       (##cdr _%$%e192167192187%_)))
                                  (let ((_%expr192195%_ _%$%hd192168192190%_))
                                    (if (gx#stx-null? _%$%tl192169192192%_)
                                        (let ((_g194118_
                                               (gx#core-expand-expression+1
                                                _%expr192195%_)))
                                          (begin
                                            (let ((_g194119_
                                                   (if (##values? _g194118_)
                                                       (##values-length
                                                        _g194118_)
                                                       1)))
                                              (if (not (##fx= _g194119_ 2))
                                                  (error "Context expects 2 values"
                                                         _g194119_)))
                                            (let ((_%_192197%_
                                                   (##values-ref _g194118_ 0))
                                                  (_%e192198%_
                                                   (##values-ref _g194118_ 1)))
                                              _%e192198%_)))
                                        (_%$%E192163192175%_)))))
                              (_%$%E192163192175%_))))
                      (_%$%E192163192175%_)))))
          (_%$%E192162192200%_))))
    (define gx#core-expand-let-bind-syntax!__%
      (lambda (_%bind192105%_ _%e192106%_ _%rebind?192107%_)
        (let* ((_%$%e192108192118%_ _%bind192105%_)
               (_%$%E192110192122%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192108192118%_)))
               (_%$%E192109192144%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192108192118%_)
                      (let ((_%$%e192111192126%_
                             (gx#syntax-e _%$%e192108192118%_)))
                        (let ((_%$%hd192112192129%_
                               (##car _%$%e192111192126%_))
                              (_%$%tl192113192131%_
                               (##cdr _%$%e192111192126%_)))
                          (let ((_%id192134%_ _%$%hd192112192129%_))
                            (if (gx#stx-pair? _%$%tl192113192131%_)
                                (let ((_%$%e192114192136%_
                                       (gx#syntax-e _%$%tl192113192131%_)))
                                  (let ((_%$%hd192115192139%_
                                         (##car _%$%e192114192136%_))
                                        (_%$%tl192116192141%_
                                         (##cdr _%$%e192114192136%_)))
                                    (if (gx#stx-null? _%$%tl192116192141%_)
                                        (gx#core-bind-syntax!__1
                                         _%id192134%_
                                         _%e192106%_
                                         _%rebind?192107%_)
                                        (_%$%E192110192122%_))))
                                (_%$%E192110192122%_)))))
                      (_%$%E192110192122%_)))))
          (_%$%E192109192144%_))))
    (define gx#core-expand-let-bind-syntax!__0
      (lambda (_%bind192151%_ _%e192152%_)
        (let ((_%rebind?192154%_ '#f))
          (gx#core-expand-let-bind-syntax!__%
           _%bind192151%_
           _%e192152%_
           _%rebind?192154%_))))
    (define gx#core-expand-let-bind-syntax!
      (lambda _g194120_
        (let ((_g194121_ (##length _g194120_)))
          (cond ((##fx= _g194121_ 2)
                 (apply gx#core-expand-let-bind-syntax!__0 _g194120_))
                ((##fx= _g194121_ 3)
                 (apply gx#core-expand-let-bind-syntax!__% _g194120_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-let-bind-syntax!
                  _g194120_))))))
    (define gx#core-expand-expression%
      (lambda (_%stx192063%_)
        (let* ((_%$%e192064192074%_ _%stx192063%_)
               (_%$%E192066192078%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192064192074%_)))
               (_%$%E192065192100%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192064192074%_)
                      (let ((_%$%e192067192082%_
                             (gx#syntax-e _%$%e192064192074%_)))
                        (let ((_%$%hd192068192085%_
                               (##car _%$%e192067192082%_))
                              (_%$%tl192069192087%_
                               (##cdr _%$%e192067192082%_)))
                          (if (gx#stx-pair? _%$%tl192069192087%_)
                              (let ((_%$%e192070192090%_
                                     (gx#syntax-e _%$%tl192069192087%_)))
                                (let ((_%$%hd192071192093%_
                                       (##car _%$%e192070192090%_))
                                      (_%$%tl192072192095%_
                                       (##cdr _%$%e192070192090%_)))
                                  (let ((_%expr192098%_ _%$%hd192071192093%_))
                                    (if (gx#stx-null? _%$%tl192072192095%_)
                                        (gx#core-expand-expression
                                         _%expr192098%_)
                                        (_%$%E192066192078%_)))))
                              (_%$%E192066192078%_))))
                      (_%$%E192066192078%_)))))
          (_%$%E192065192100%_))))
    (define gx#core-expand-quote%
      (lambda (_%stx192022%_)
        (let* ((_%$%e192023192033%_ _%stx192022%_)
               (_%$%E192025192037%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e192023192033%_)))
               (_%$%E192024192059%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e192023192033%_)
                      (let ((_%$%e192026192041%_
                             (gx#syntax-e _%$%e192023192033%_)))
                        (let ((_%$%hd192027192044%_
                               (##car _%$%e192026192041%_))
                              (_%$%tl192028192046%_
                               (##cdr _%$%e192026192041%_)))
                          (if (gx#stx-pair? _%$%tl192028192046%_)
                              (let ((_%$%e192029192049%_
                                     (gx#syntax-e _%$%tl192028192046%_)))
                                (let ((_%$%hd192030192052%_
                                       (##car _%$%e192029192049%_))
                                      (_%$%tl192031192054%_
                                       (##cdr _%$%e192029192049%_)))
                                  (let ((_%e192057%_ _%$%hd192030192052%_))
                                    (if (gx#stx-null? _%$%tl192031192054%_)
                                        (gx#core-quote-syntax__1
                                         (cons (gx#core-quote-syntax__0
                                                '%#quote)
                                               (cons (gx#syntax->datum
                                                      _%e192057%_)
                                                     '()))
                                         (gx#stx-source _%stx192022%_))
                                        (_%$%E192025192037%_)))))
                              (_%$%E192025192037%_))))
                      (_%$%E192025192037%_)))))
          (_%$%E192024192059%_))))
    (define gx#core-expand-quote-syntax%
      (lambda (_%stx191981%_)
        (let* ((_%$%e191982191992%_ _%stx191981%_)
               (_%$%E191984191996%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e191982191992%_)))
               (_%$%E191983192018%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191982191992%_)
                      (let ((_%$%e191985192000%_
                             (gx#syntax-e _%$%e191982191992%_)))
                        (let ((_%$%hd191986192003%_
                               (##car _%$%e191985192000%_))
                              (_%$%tl191987192005%_
                               (##cdr _%$%e191985192000%_)))
                          (if (gx#stx-pair? _%$%tl191987192005%_)
                              (let ((_%$%e191988192008%_
                                     (gx#syntax-e _%$%tl191987192005%_)))
                                (let ((_%$%hd191989192011%_
                                       (##car _%$%e191988192008%_))
                                      (_%$%tl191990192013%_
                                       (##cdr _%$%e191988192008%_)))
                                  (let ((_%e192016%_ _%$%hd191989192011%_))
                                    (if (gx#stx-null? _%$%tl191990192013%_)
                                        (gx#core-quote-syntax__1
                                         (cons (gx#core-quote-syntax__0
                                                '%#quote-syntax)
                                               (cons (gx#core-quote-syntax__0
                                                      _%e192016%_)
                                                     '()))
                                         (gx#stx-source _%stx191981%_))
                                        (_%$%E191984191996%_)))))
                              (_%$%E191984191996%_))))
                      (_%$%E191984191996%_)))))
          (_%$%E191983192018%_))))
    (define gx#core-expand-call%
      (lambda (_%stx191875%_)
        (letrec ((_%expand-runtime-call191877%_
                  (lambda (_%rator-expr191978%_ _%args191979%_)
                    (gx#core-quote-syntax__1
                     (gx#core-cons*
                      '%#call
                      _%rator-expr191978%_
                      (gx#stx-map1 gx#core-expand-expression _%args191979%_))
                     (gx#stx-source _%stx191875%_)))))
          (let* ((_%$%e191878191888%_ _%stx191875%_)
                 (_%$%E191880191892%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e191878191888%_)))
                 (_%$%E191879191974%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e191878191888%_)
                        (let ((_%$%e191881191896%_
                               (gx#syntax-e _%$%e191878191888%_)))
                          (let ((_%$%hd191882191899%_
                                 (##car _%$%e191881191896%_))
                                (_%$%tl191883191901%_
                                 (##cdr _%$%e191881191896%_)))
                            (if (gx#stx-pair? _%$%tl191883191901%_)
                                (let ((_%$%e191884191904%_
                                       (gx#syntax-e _%$%tl191883191901%_)))
                                  (let ((_%$%hd191885191907%_
                                         (##car _%$%e191884191904%_))
                                        (_%$%tl191886191909%_
                                         (##cdr _%$%e191884191904%_)))
                                    (let* ((_%rator191912%_
                                            _%$%hd191885191907%_)
                                           (_%args191914%_
                                            _%$%tl191886191909%_))
                                      (if (gx#stx-list? _%args191914%_)
                                          (let* ((_%rator-expr191916%_
                                                  (gx#core-expand-expression
                                                   _%rator191912%_))
                                                 (_%$%e191917191927%_
                                                  _%rator-expr191916%_)
                                                 (_%$%E191919191931%_
                                                  (lambda ()
                                                    (_%expand-runtime-call191877%_
                                                     _%rator-expr191916%_
                                                     _%args191914%_)))
                                                 (_%$%E191918191970%_
                                                  (lambda ()
                                                    (if (gx#stx-pair?
                                                         _%$%e191917191927%_)
                                                        (let ((_%$%e191920191935%_
                                                               (gx#syntax-e
                                                                _%$%e191917191927%_)))
                                                          (let ((_%$%hd191921191938%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e191920191935%_))
                        (_%$%tl191922191940%_ (##cdr _%$%e191920191935%_)))
                    (if (and (gx#identifier? _%$%hd191921191938%_)
                             (gx#core-identifier=?
                              _%$%hd191921191938%_
                              '%#ref))
                        (if (gx#stx-pair? _%$%tl191922191940%_)
                            (let ((_%$%e191923191943%_
                                   (gx#syntax-e _%$%tl191922191940%_)))
                              (let ((_%$%hd191924191946%_
                                     (##car _%$%e191923191943%_))
                                    (_%$%tl191925191948%_
                                     (##cdr _%$%e191923191943%_)))
                                (let ((_%id191951%_ _%$%hd191924191946%_))
                                  (if (gx#stx-null? _%$%tl191925191948%_)
                                      (let ((_%$e191953%_
                                             (gx#resolve-identifier__0
                                              _%id191951%_)))
                                        (if _%$e191953%_
                                            (let _%again191958%_ ((_%bind191960%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$e191953%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ((_%$e191962%_
                                                     (if (##structure-instance-of?
                                                          _%bind191960%_
                                                          'gx#runtime-binding::t)
                                                         (##unchecked-structure-ref
                                                          _%bind191960%_
                                                          '6
                                                          '#f
                                                          '#f)
                                                         '#f)))
                                                (if _%$e191962%_
                                                    (gx#core-expand-expression
                                                     (gx#stx-wrap-source
                                                      (cons _%$e191962%_
                                                            _%args191914%_)
                                                      (gx#stx-source
                                                       _%stx191875%_)))
                                                    (if (##structure-direct-instance-of?
                                                         _%bind191960%_
                                                         'gx#import-binding::t)
                                                        (_%again191958%_
                                                         (##unchecked-structure-ref
                                                          _%bind191960%_
                                                          '5
                                                          '#f
                                                          '#f))
                                                        (_%expand-runtime-call191877%_
                                                         _%rator-expr191916%_
                                                         _%args191914%_)))))
                                            (_%expand-runtime-call191877%_
                                             _%rator-expr191916%_
                                             _%args191914%_)))
                                      (_%$%E191919191931%_)))))
                            (_%$%E191919191931%_))
                        (_%$%E191919191931%_))))
                (_%$%E191919191931%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%E191918191970%_))
                                          (_%$%E191880191892%_)))))
                                (_%$%E191880191892%_))))
                        (_%$%E191880191892%_)))))
            (_%$%E191879191974%_)))))
    (define gx#core-expand-if%
      (lambda (_%stx191808%_)
        (let* ((_%$%e191809191825%_ _%stx191808%_)
               (_%$%E191811191829%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e191809191825%_)))
               (_%$%E191810191871%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191809191825%_)
                      (let ((_%$%e191812191833%_
                             (gx#syntax-e _%$%e191809191825%_)))
                        (let ((_%$%hd191813191836%_
                               (##car _%$%e191812191833%_))
                              (_%$%tl191814191838%_
                               (##cdr _%$%e191812191833%_)))
                          (if (gx#stx-pair? _%$%tl191814191838%_)
                              (let ((_%$%e191815191841%_
                                     (gx#syntax-e _%$%tl191814191838%_)))
                                (let ((_%$%hd191816191844%_
                                       (##car _%$%e191815191841%_))
                                      (_%$%tl191817191846%_
                                       (##cdr _%$%e191815191841%_)))
                                  (let ((_%test191849%_ _%$%hd191816191844%_))
                                    (if (gx#stx-pair? _%$%tl191817191846%_)
                                        (let ((_%$%e191818191851%_
                                               (gx#syntax-e
                                                _%$%tl191817191846%_)))
                                          (let ((_%$%hd191819191854%_
                                                 (##car _%$%e191818191851%_))
                                                (_%$%tl191820191856%_
                                                 (##cdr _%$%e191818191851%_)))
                                            (let ((_%K191859%_
                                                   _%$%hd191819191854%_))
                                              (if (gx#stx-pair?
                                                   _%$%tl191820191856%_)
                                                  (let ((_%$%e191821191861%_
                                                         (gx#syntax-e
                                                          _%$%tl191820191856%_)))
                                                    (let ((_%$%hd191822191864%_
                                                           (##car _%$%e191821191861%_))
                                                          (_%$%tl191823191866%_
                                                           (##cdr _%$%e191821191861%_)))
                                                      (let ((_%E191869%_
                                                             _%$%hd191822191864%_))
                                                        (if (gx#stx-null?
                                                             _%$%tl191823191866%_)
                                                            (gx#core-quote-syntax__1
                                                             (cons (gx#core-quote-syntax__0
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '%#if)
                           (cons (gx#core-expand-expression _%test191849%_)
                                 (cons (gx#core-expand-expression _%K191859%_)
                                       (cons (gx#core-expand-expression
                                              _%E191869%_)
                                             '()))))
                     (gx#stx-source _%stx191808%_))
                    (_%$%E191811191829%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E191811191829%_)))))
                                        (_%$%E191811191829%_)))))
                              (_%$%E191811191829%_))))
                      (_%$%E191811191829%_)))))
          (_%$%E191810191871%_))))
    (define gx#core-expand-ref%
      (lambda (_%stx191767%_)
        (let* ((_%$%e191768191778%_ _%stx191767%_)
               (_%$%E191770191782%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e191768191778%_)))
               (_%$%E191769191804%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191768191778%_)
                      (let ((_%$%e191771191786%_
                             (gx#syntax-e _%$%e191768191778%_)))
                        (let ((_%$%hd191772191789%_
                               (##car _%$%e191771191786%_))
                              (_%$%tl191773191791%_
                               (##cdr _%$%e191771191786%_)))
                          (if (gx#stx-pair? _%$%tl191773191791%_)
                              (let ((_%$%e191774191794%_
                                     (gx#syntax-e _%$%tl191773191791%_)))
                                (let ((_%$%hd191775191797%_
                                       (##car _%$%e191774191794%_))
                                      (_%$%tl191776191799%_
                                       (##cdr _%$%e191774191794%_)))
                                  (let ((_%id191802%_ _%$%hd191775191797%_))
                                    (if (gx#stx-null? _%$%tl191776191799%_)
                                        (if (gx#identifier? _%id191802%_)
                                            (gx#core-quote-syntax__1
                                             (cons (gx#core-quote-syntax__0
                                                    '%#ref)
                                                   (cons (gx#core-quote-runtime-ref
                                                          _%id191802%_
                                                          _%stx191767%_)
                                                         '()))
                                             (gx#stx-source _%stx191767%_))
                                            (_%$%E191770191782%_))
                                        (_%$%E191770191782%_)))))
                              (_%$%E191770191782%_))))
                      (_%$%E191770191782%_)))))
          (_%$%E191769191804%_))))
    (define gx#core-expand-setq%
      (lambda (_%stx191713%_)
        (let* ((_%$%e191714191727%_ _%stx191713%_)
               (_%$%E191716191731%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e191714191727%_)))
               (_%$%E191715191763%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191714191727%_)
                      (let ((_%$%e191717191735%_
                             (gx#syntax-e _%$%e191714191727%_)))
                        (let ((_%$%hd191718191738%_
                               (##car _%$%e191717191735%_))
                              (_%$%tl191719191740%_
                               (##cdr _%$%e191717191735%_)))
                          (if (gx#stx-pair? _%$%tl191719191740%_)
                              (let ((_%$%e191720191743%_
                                     (gx#syntax-e _%$%tl191719191740%_)))
                                (let ((_%$%hd191721191746%_
                                       (##car _%$%e191720191743%_))
                                      (_%$%tl191722191748%_
                                       (##cdr _%$%e191720191743%_)))
                                  (let ((_%id191751%_ _%$%hd191721191746%_))
                                    (if (gx#stx-pair? _%$%tl191722191748%_)
                                        (let ((_%$%e191723191753%_
                                               (gx#syntax-e
                                                _%$%tl191722191748%_)))
                                          (let ((_%$%hd191724191756%_
                                                 (##car _%$%e191723191753%_))
                                                (_%$%tl191725191758%_
                                                 (##cdr _%$%e191723191753%_)))
                                            (let ((_%expr191761%_
                                                   _%$%hd191724191756%_))
                                              (if (gx#stx-null?
                                                   _%$%tl191725191758%_)
                                                  (if (gx#identifier?
                                                       _%id191751%_)
                                                      (gx#core-quote-syntax__1
                                                       (cons (gx#core-quote-syntax__0
                                                              '%#set!)
                                                             (cons (gx#core-quote-runtime-ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%id191751%_
                            _%stx191713%_)
                           (cons (gx#core-expand-expression _%expr191761%_)
                                 '())))
               (gx#stx-source _%stx191713%_))
              (_%$%E191716191731%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E191716191731%_)))))
                                        (_%$%E191716191731%_)))))
                              (_%$%E191716191731%_))))
                      (_%$%E191716191731%_)))))
          (_%$%E191715191763%_))))
    (define gx#macro-expand-extern
      (lambda (_%stx191558%_)
        (letrec ((_%generate191560%_
                  (lambda (_%body191590%_)
                    (let _%lp191592%_ ((_%rest191594%_ _%body191590%_)
                                       (_%ns191595%_
                                        (gx#core-context-namespace__0))
                                       (_%r191596%_ '()))
                      (let* ((_%$%e191597191612%_ _%rest191594%_)
                             (_%$%E191610191616%_
                              (lambda ()
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid syntax-case clause"
                                 _%$%e191597191612%_)))
                             (_%$%E191606191620%_
                              (lambda ()
                                (if (gx#stx-null? _%$%e191597191612%_)
                                    (reverse _%r191596%_)
                                    (_%$%E191610191616%_))))
                             (_%$%E191599191677%_
                              (lambda ()
                                (if (gx#stx-pair? _%$%e191597191612%_)
                                    (let ((_%$%e191607191624%_
                                           (gx#syntax-e _%$%e191597191612%_)))
                                      (let ((_%$%hd191608191627%_
                                             (##car _%$%e191607191624%_))
                                            (_%$%tl191609191629%_
                                             (##cdr _%$%e191607191624%_)))
                                        (let* ((_%hd191632%_
                                                _%$%hd191608191627%_)
                                               (_%rest191634%_
                                                _%$%tl191609191629%_))
                                          (if (gx#identifier? _%hd191632%_)
                                              (_%lp191592%_
                                               _%rest191634%_
                                               _%ns191595%_
                                               (cons (cons _%hd191632%_
                                                           (cons (if _%ns191595%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gx#stx-identifier
                              _%hd191632%_
                              _%ns191595%_
                              '"#"
                              _%hd191632%_)
                             _%hd191632%_)
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%r191596%_))
                                              (let* ((_%$%e191635191645%_
                                                      _%hd191632%_)
                                                     (_%$%E191637191649%_
                                                      (lambda ()
                                                        (gx#raise-syntax-error
                                                         '#f
                                                         '"Bad syntax; invalid syntax-case clause"
                                                         _%$%e191635191645%_)))
                                                     (_%$%E191636191673%_
                                                      (lambda ()
                                                        (if (gx#stx-pair?
                                                             _%$%e191635191645%_)
                                                            (let ((_%$%e191638191653%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gx#syntax-e _%$%e191635191645%_)))
                      (let ((_%$%hd191639191656%_ (##car _%$%e191638191653%_))
                            (_%$%tl191640191658%_ (##cdr _%$%e191638191653%_)))
                        (let ((_%id191661%_ _%$%hd191639191656%_))
                          (if (gx#stx-pair? _%$%tl191640191658%_)
                              (let ((_%$%e191641191663%_
                                     (gx#syntax-e _%$%tl191640191658%_)))
                                (let ((_%$%hd191642191666%_
                                       (##car _%$%e191641191663%_))
                                      (_%$%tl191643191668%_
                                       (##cdr _%$%e191641191663%_)))
                                  (let ((_%eid191671%_ _%$%hd191642191666%_))
                                    (if (gx#stx-null? _%$%tl191643191668%_)
                                        (if (and (gx#identifier? _%id191661%_)
                                                 (gx#identifier?
                                                  _%eid191671%_))
                                            (_%lp191592%_
                                             _%rest191634%_
                                             _%ns191595%_
                                             (cons (cons _%id191661%_
                                                         (cons _%eid191671%_
                                                               '()))
                                                   _%r191596%_))
                                            (_%$%E191637191649%_))
                                        (_%$%E191637191649%_)))))
                              (_%$%E191637191649%_)))))
                    (_%$%E191637191649%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%E191636191673%_))))))
                                    (_%$%E191606191620%_))))
                             (_%$%E191598191709%_
                              (lambda ()
                                (if (gx#stx-pair? _%$%e191597191612%_)
                                    (let ((_%$%e191600191681%_
                                           (gx#syntax-e _%$%e191597191612%_)))
                                      (let ((_%$%hd191601191684%_
                                             (##car _%$%e191600191681%_))
                                            (_%$%tl191602191686%_
                                             (##cdr _%$%e191600191681%_)))
                                        (if (eq? (gx#stx-e
                                                  _%$%hd191601191684%_)
                                                 'namespace:)
                                            (if (gx#stx-pair?
                                                 _%$%tl191602191686%_)
                                                (let ((_%$%e191603191689%_
                                                       (gx#syntax-e
                                                        _%$%tl191602191686%_)))
                                                  (let ((_%$%hd191604191692%_
                                                         (##car _%$%e191603191689%_))
                                                        (_%$%tl191605191694%_
                                                         (##cdr _%$%e191603191689%_)))
                                                    (let* ((_%ns191697%_
                                                            _%$%hd191604191692%_)
                                                           (_%rest191699%_
                                                            _%$%tl191605191694%_)
                                                           (_%ns191707%_
                                                            (if (gx#identifier?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%ns191697%_)
                        (symbol->string (gx#stx-e _%ns191697%_))
                        (if (or (gx#stx-string? _%ns191697%_)
                                (gx#stx-false? _%ns191697%_))
                            (gx#stx-e _%ns191697%_)
                            (gx#raise-syntax-error
                             '#f
                             '"Bad syntax; extern expects namespace identifier"
                             _%stx191558%_
                             _%ns191697%_)))))
              (_%lp191592%_ _%rest191699%_ _%ns191707%_ _%r191596%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%E191599191677%_))
                                            (_%$%E191599191677%_))))
                                    (_%$%E191599191677%_)))))
                        (_%$%E191598191709%_))))))
          (let* ((_%$%e191561191568%_ _%stx191558%_)
                 (_%$%E191563191572%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e191561191568%_)))
                 (_%$%E191562191586%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e191561191568%_)
                        (let ((_%$%e191564191576%_
                               (gx#syntax-e _%$%e191561191568%_)))
                          (let ((_%$%hd191565191579%_
                                 (##car _%$%e191564191576%_))
                                (_%$%tl191566191581%_
                                 (##cdr _%$%e191564191576%_)))
                            (let ((_%body191584%_ _%$%tl191566191581%_))
                              (if (gx#stx-list? _%body191584%_)
                                  (gx#core-cons
                                   '%#extern
                                   (_%generate191560%_ _%body191584%_))
                                  (_%$%E191563191572%_)))))
                        (_%$%E191563191572%_)))))
            (_%$%E191562191586%_)))))
    (define gx#macro-expand-lambda%
      (lambda (_%stx191515%_)
        (let* ((_%$%e191516191526%_ _%stx191515%_)
               (_%$%E191518191530%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e191516191526%_)))
               (_%$%E191517191554%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191516191526%_)
                      (let ((_%$%e191519191534%_
                             (gx#syntax-e _%$%e191516191526%_)))
                        (let ((_%$%hd191520191537%_
                               (##car _%$%e191519191534%_))
                              (_%$%tl191521191539%_
                               (##cdr _%$%e191519191534%_)))
                          (if (gx#stx-pair? _%$%tl191521191539%_)
                              (let ((_%$%e191522191542%_
                                     (gx#syntax-e _%$%tl191521191539%_)))
                                (let ((_%$%hd191523191545%_
                                       (##car _%$%e191522191542%_))
                                      (_%$%tl191524191547%_
                                       (##cdr _%$%e191522191542%_)))
                                  (let* ((_%hd191550%_ _%$%hd191523191545%_)
                                         (_%body191552%_ _%$%tl191524191547%_))
                                    (if (and (gx#stx-andmap
                                              gx#identifier?
                                              _%hd191550%_)
                                             (gx#stx-list? _%body191552%_)
                                             (not (gx#stx-null?
                                                   _%body191552%_)))
                                        (gx#core-cons*
                                         '%#lambda
                                         (gx#stx-map1 identity _%hd191550%_)
                                         _%body191552%_)
                                        (_%$%E191518191530%_)))))
                              (_%$%E191518191530%_))))
                      (_%$%E191518191530%_)))))
          (_%$%E191517191554%_))))
    (define gx#macro-expand-case-lambda
      (lambda (_%stx191451%_)
        (letrec ((_%generate191453%_
                  (lambda (_%clause191483%_)
                    (let* ((_%$%e191484191491%_ _%clause191483%_)
                           (_%$%E191486191495%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; malformed clause"
                               _%stx191451%_
                               _%clause191483%_)))
                           (_%$%E191485191511%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e191484191491%_)
                                  (let ((_%$%e191487191499%_
                                         (gx#syntax-e _%$%e191484191491%_)))
                                    (let ((_%$%hd191488191502%_
                                           (##car _%$%e191487191499%_))
                                          (_%$%tl191489191504%_
                                           (##cdr _%$%e191487191499%_)))
                                      (let* ((_%hd191507%_
                                              _%$%hd191488191502%_)
                                             (_%body191509%_
                                              _%$%tl191489191504%_))
                                        (if (and (gx#stx-andmap
                                                  gx#identifier?
                                                  _%hd191507%_)
                                                 (gx#stx-list? _%body191509%_)
                                                 (not (gx#stx-null?
                                                       _%body191509%_)))
                                            (gx#stx-wrap-source
                                             (cons (gx#stx-map1
                                                    identity
                                                    _%hd191507%_)
                                                   _%body191509%_)
                                             (gx#stx-source _%clause191483%_))
                                            (_%$%E191486191495%_)))))
                                  (_%$%E191486191495%_)))))
                      (_%$%E191485191511%_)))))
          (let* ((_%$%e191454191461%_ _%stx191451%_)
                 (_%$%E191456191465%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e191454191461%_)))
                 (_%$%E191455191479%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e191454191461%_)
                        (let ((_%$%e191457191469%_
                               (gx#syntax-e _%$%e191454191461%_)))
                          (let ((_%$%hd191458191472%_
                                 (##car _%$%e191457191469%_))
                                (_%$%tl191459191474%_
                                 (##cdr _%$%e191457191469%_)))
                            (let ((_%clauses191477%_ _%$%tl191459191474%_))
                              (if (gx#stx-list? _%clauses191477%_)
                                  (gx#core-cons
                                   '%#case-lambda
                                   (gx#stx-map1
                                    _%generate191453%_
                                    _%clauses191477%_))
                                  (_%$%E191456191465%_)))))
                        (_%$%E191456191465%_)))))
            (_%$%E191455191479%_)))))
    (define gx#macro-expand-let-values__%
      (lambda (_%stx191352%_ _%form191353%_)
        (letrec ((_%generate191355%_
                  (lambda (_%bind191398%_)
                    (let* ((_%$%e191399191409%_ _%bind191398%_)
                           (_%$%E191401191413%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; malformed binding"
                               _%stx191352%_
                               _%bind191398%_)))
                           (_%$%E191400191437%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e191399191409%_)
                                  (let ((_%$%e191402191417%_
                                         (gx#syntax-e _%$%e191399191409%_)))
                                    (let ((_%$%hd191403191420%_
                                           (##car _%$%e191402191417%_))
                                          (_%$%tl191404191422%_
                                           (##cdr _%$%e191402191417%_)))
                                      (let ((_%ids191425%_
                                             _%$%hd191403191420%_))
                                        (if (gx#stx-pair? _%$%tl191404191422%_)
                                            (let ((_%$%e191405191427%_
                                                   (gx#syntax-e
                                                    _%$%tl191404191422%_)))
                                              (let ((_%$%hd191406191430%_
                                                     (##car _%$%e191405191427%_))
                                                    (_%$%tl191407191432%_
                                                     (##cdr _%$%e191405191427%_)))
                                                (let ((_%expr191435%_
                                                       _%$%hd191406191430%_))
                                                  (if (gx#stx-null?
                                                       _%$%tl191407191432%_)
                                                      (if (gx#stx-andmap
                                                           gx#identifier?
                                                           _%ids191425%_)
                                                          (cons (gx#stx-map1
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         identity
                         _%ids191425%_)
                        (cons _%expr191435%_ '()))
                  (_%$%E191401191413%_))
              (_%$%E191401191413%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%E191401191413%_)))))
                                  (_%$%E191401191413%_)))))
                      (_%$%E191400191437%_)))))
          (let* ((_%$%e191356191366%_ _%stx191352%_)
                 (_%$%E191358191370%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e191356191366%_)))
                 (_%$%E191357191394%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e191356191366%_)
                        (let ((_%$%e191359191374%_
                               (gx#syntax-e _%$%e191356191366%_)))
                          (let ((_%$%hd191360191377%_
                                 (##car _%$%e191359191374%_))
                                (_%$%tl191361191379%_
                                 (##cdr _%$%e191359191374%_)))
                            (if (gx#stx-pair? _%$%tl191361191379%_)
                                (let ((_%$%e191362191382%_
                                       (gx#syntax-e _%$%tl191361191379%_)))
                                  (let ((_%$%hd191363191385%_
                                         (##car _%$%e191362191382%_))
                                        (_%$%tl191364191387%_
                                         (##cdr _%$%e191362191382%_)))
                                    (let* ((_%hd191390%_ _%$%hd191363191385%_)
                                           (_%body191392%_
                                            _%$%tl191364191387%_))
                                      (if (and (gx#stx-list? _%hd191390%_)
                                               (gx#stx-list? _%body191392%_)
                                               (not (gx#stx-null?
                                                     _%body191392%_)))
                                          (gx#core-cons*
                                           _%form191353%_
                                           (gx#stx-map1
                                            _%generate191355%_
                                            _%hd191390%_)
                                           _%body191392%_)
                                          (_%$%E191358191370%_)))))
                                (_%$%E191358191370%_))))
                        (_%$%E191358191370%_)))))
            (_%$%E191357191394%_)))))
    (define gx#macro-expand-let-values__0
      (lambda (_%stx191444%_)
        (let ((_%form191446%_ '%#let-values))
          (gx#macro-expand-let-values__% _%stx191444%_ _%form191446%_))))
    (define gx#macro-expand-let-values
      (lambda _g194122_
        (let ((_g194123_ (##length _g194122_)))
          (cond ((##fx= _g194123_ 1)
                 (apply gx#macro-expand-let-values__0 _g194122_))
                ((##fx= _g194123_ 2)
                 (apply gx#macro-expand-let-values__% _g194122_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#macro-expand-let-values
                  _g194122_))))))
    (define gx#macro-expand-letrec-values
      (lambda (_%stx191349%_)
        (gx#macro-expand-let-values__% _%stx191349%_ '%#letrec-values)))
    (define gx#macro-expand-letrec*-values
      (lambda (_%stx191347%_)
        (gx#macro-expand-let-values__% _%stx191347%_ '%#letrec*-values)))
    (define gx#macro-expand-if
      (lambda (_%stx191238%_)
        (let* ((_%$%e191239191265%_ _%stx191238%_)
               (_%$%E191251191269%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e191239191265%_)))
               (_%$%E191241191311%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191239191265%_)
                      (let ((_%$%e191252191273%_
                             (gx#syntax-e _%$%e191239191265%_)))
                        (let ((_%$%hd191253191276%_
                               (##car _%$%e191252191273%_))
                              (_%$%tl191254191278%_
                               (##cdr _%$%e191252191273%_)))
                          (if (gx#stx-pair? _%$%tl191254191278%_)
                              (let ((_%$%e191255191281%_
                                     (gx#syntax-e _%$%tl191254191278%_)))
                                (let ((_%$%hd191256191284%_
                                       (##car _%$%e191255191281%_))
                                      (_%$%tl191257191286%_
                                       (##cdr _%$%e191255191281%_)))
                                  (let ((_%test191289%_ _%$%hd191256191284%_))
                                    (if (gx#stx-pair? _%$%tl191257191286%_)
                                        (let ((_%$%e191258191291%_
                                               (gx#syntax-e
                                                _%$%tl191257191286%_)))
                                          (let ((_%$%hd191259191294%_
                                                 (##car _%$%e191258191291%_))
                                                (_%$%tl191260191296%_
                                                 (##cdr _%$%e191258191291%_)))
                                            (let ((_%K191299%_
                                                   _%$%hd191259191294%_))
                                              (if (gx#stx-pair?
                                                   _%$%tl191260191296%_)
                                                  (let ((_%$%e191261191301%_
                                                         (gx#syntax-e
                                                          _%$%tl191260191296%_)))
                                                    (let ((_%$%hd191262191304%_
                                                           (##car _%$%e191261191301%_))
                                                          (_%$%tl191263191306%_
                                                           (##cdr _%$%e191261191301%_)))
                                                      (let ((_%E191309%_
                                                             _%$%hd191262191304%_))
                                                        (if (gx#stx-null?
                                                             _%$%tl191263191306%_)
                                                            (gx#core-list
                                                             '%#if
                                                             _%test191289%_
                                                             _%K191299%_
                                                             _%E191309%_)
                                                            (_%$%E191251191269%_)))))
                                                  (_%$%E191251191269%_)))))
                                        (_%$%E191251191269%_)))))
                              (_%$%E191251191269%_))))
                      (_%$%E191251191269%_))))
               (_%$%E191240191343%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e191239191265%_)
                      (let ((_%$%e191242191315%_
                             (gx#syntax-e _%$%e191239191265%_)))
                        (let ((_%$%hd191243191318%_
                               (##car _%$%e191242191315%_))
                              (_%$%tl191244191320%_
                               (##cdr _%$%e191242191315%_)))
                          (if (gx#stx-pair? _%$%tl191244191320%_)
                              (let ((_%$%e191245191323%_
                                     (gx#syntax-e _%$%tl191244191320%_)))
                                (let ((_%$%hd191246191326%_
                                       (##car _%$%e191245191323%_))
                                      (_%$%tl191247191328%_
                                       (##cdr _%$%e191245191323%_)))
                                  (let ((_%test191331%_ _%$%hd191246191326%_))
                                    (if (gx#stx-pair? _%$%tl191247191328%_)
                                        (let ((_%$%e191248191333%_
                                               (gx#syntax-e
                                                _%$%tl191247191328%_)))
                                          (let ((_%$%hd191249191336%_
                                                 (##car _%$%e191248191333%_))
                                                (_%$%tl191250191338%_
                                                 (##cdr _%$%e191248191333%_)))
                                            (let ((_%K191341%_
                                                   _%$%hd191249191336%_))
                                              (if (gx#stx-null?
                                                   _%$%tl191250191338%_)
                                                  (gx#core-list
                                                   '%#if
                                                   _%test191331%_
                                                   _%K191341%_
                                                   '#!void)
                                                  (_%$%E191241191311%_)))))
                                        (_%$%E191241191311%_)))))
                              (_%$%E191241191311%_))))
                      (_%$%E191241191311%_)))))
          (_%$%E191240191343%_))))
    (define gx#free-identifier=?
      (lambda (_%xid191223%_ _%yid191224%_)
        (let ((_%xe191226%_ (gx#resolve-identifier__0 _%xid191223%_))
              (_%ye191227%_ (gx#resolve-identifier__0 _%yid191224%_)))
          (if (and _%xe191226%_ _%ye191227%_)
              (let ((_%$e191230%_ (eq? _%xe191226%_ _%ye191227%_)))
                (if _%$e191230%_
                    _%$e191230%_
                    (if (##structure-instance-of? _%xe191226%_ 'gx#binding::t)
                        (if (##structure-instance-of?
                             _%ye191227%_
                             'gx#binding::t)
                            (eq? (##unchecked-structure-ref
                                  _%xe191226%_
                                  '1
                                  '#f
                                  '#f)
                                 (##unchecked-structure-ref
                                  _%ye191227%_
                                  '1
                                  '#f
                                  '#f))
                            '#f)
                        '#f)))
              (if (or _%xe191226%_ _%ye191227%_)
                  '#f
                  (gx#stx-eq? _%xid191223%_ _%yid191224%_))))))
    (define gx#bound-identifier=?
      (lambda (_%xid191204%_ _%yid191205%_)
        (letrec ((_%context191207%_
                  (lambda (_%e191221%_)
                    (if (##structure-direct-instance-of?
                         _%e191221%_
                         'gx#syntax-quote::t)
                        (##unchecked-structure-ref _%e191221%_ '3 '#f '#f)
                        (gx#current-expander-context))))
                 (_%marks191208%_
                  (lambda (_%e191216%_)
                    (if (symbol? _%e191216%_)
                        '()
                        (if (##structure-direct-instance-of?
                             _%e191216%_
                             'gx#identifier-wrap::t)
                            (##unchecked-structure-ref _%e191216%_ '3 '#f '#f)
                            (##unchecked-structure-ref
                             _%e191216%_
                             '4
                             '#f
                             '#f)))))
                 (_%unwrap191209%_
                  (lambda (_%e191214%_)
                    (if (symbol? _%e191214%_)
                        _%e191214%_
                        (gx#syntax-local-unwrap _%e191214%_)))))
          (let ((_%x191211%_ (_%unwrap191209%_ _%xid191204%_))
                (_%y191212%_ (_%unwrap191209%_ _%yid191205%_)))
            (if (gx#stx-eq? _%x191211%_ _%y191212%_)
                (if (eq? (_%context191207%_ _%x191211%_)
                         (_%context191207%_ _%y191212%_))
                    (equal? (_%marks191208%_ _%x191211%_)
                            (_%marks191208%_ _%y191212%_))
                    '#f)
                '#f)))))
    (define gx#underscore?
      (lambda (_%stx191202%_)
        (if (gx#identifier? _%stx191202%_)
            (gx#core-identifier=? _%stx191202%_ '_)
            '#f)))
    (define gx#ellipsis?
      (lambda (_%stx191200%_)
        (if (gx#identifier? _%stx191200%_)
            (gx#core-identifier=? _%stx191200%_ '...)
            '#f)))
    (define gx#check-duplicate-identifiers__%
      (lambda (_%stx191143%_ _%where191144%_)
        (let _%lp191146%_ ((_%rest191148%_ (gx#syntax->list _%stx191143%_)))
          (let* ((_%$%rest191149191157%_ _%rest191148%_)
                 (_%$%else191151191165%_ (lambda () '#t))
                 (_%$%K191153191178%_
                  (lambda (_%rest191168%_ _%hd191169%_)
                    (if (gx#identifier? _%hd191169%_)
                        (if (__find (lambda (_%$%g191171191173%_)
                                      (gx#bound-identifier=?
                                       _%$%g191171191173%_
                                       _%hd191169%_))
                                    _%rest191168%_)
                            (gx#raise-syntax-error
                             '#f
                             '"Duplicate identifier"
                             _%where191144%_
                             _%hd191169%_)
                            (_%lp191146%_ _%rest191168%_))
                        (gx#raise-syntax-error
                         '#f
                         '"Bad identifier"
                         _%where191144%_
                         _%hd191169%_)))))
            (if (pair? _%$%rest191149191157%_)
                (let ((_%$%hd191154191181%_ (##car _%$%rest191149191157%_))
                      (_%$%tl191155191183%_ (##cdr _%$%rest191149191157%_)))
                  (let* ((_%hd191186%_ _%$%hd191154191181%_)
                         (_%rest191188%_ _%$%tl191155191183%_))
                    (_%$%K191153191178%_ _%rest191188%_ _%hd191186%_)))
                (_%$%else191151191165%_))))))
    (define gx#check-duplicate-identifiers__0
      (lambda (_%stx191193%_)
        (let ((_%where191195%_ _%stx191193%_))
          (gx#check-duplicate-identifiers__% _%stx191193%_ _%where191195%_))))
    (define gx#check-duplicate-identifiers
      (lambda _g194124_
        (let ((_g194125_ (##length _g194124_)))
          (cond ((##fx= _g194125_ 1)
                 (apply gx#check-duplicate-identifiers__0 _g194124_))
                ((##fx= _g194125_ 2)
                 (apply gx#check-duplicate-identifiers__% _g194124_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#check-duplicate-identifiers
                  _g194124_))))))
    (define gx#core-bind-values?
      (lambda (_%stx191135%_)
        (gx#stx-andmap
         (lambda (_%x191137%_)
           (let ((_%$e191139%_ (gx#identifier? _%x191137%_)))
             (if _%$e191139%_ _%$e191139%_ (gx#stx-false? _%x191137%_))))
         _%stx191135%_)))
    (define gx#core-bind-values!__%
      (lambda (_%stx191099%_ _%rebind?191100%_ _%phi191101%_ _%ctx191102%_)
        (gx#stx-for-each1
         (lambda (_%id191104%_)
           (if (gx#identifier? _%id191104%_)
               (gx#core-bind-runtime!__%
                _%id191104%_
                _%rebind?191100%_
                _%phi191101%_
                _%ctx191102%_)
               '#!void))
         _%stx191099%_)))
    (define gx#core-bind-values!__0
      (lambda (_%stx191109%_)
        (let* ((_%rebind?191111%_ '#f)
               (_%phi191113%_ (gx#current-expander-phi))
               (_%ctx191115%_ (gx#current-expander-context)))
          (gx#core-bind-values!__%
           _%stx191109%_
           _%rebind?191111%_
           _%phi191113%_
           _%ctx191115%_))))
    (define gx#core-bind-values!__1
      (lambda (_%stx191117%_ _%rebind?191118%_)
        (let* ((_%phi191120%_ (gx#current-expander-phi))
               (_%ctx191122%_ (gx#current-expander-context)))
          (gx#core-bind-values!__%
           _%stx191117%_
           _%rebind?191118%_
           _%phi191120%_
           _%ctx191122%_))))
    (define gx#core-bind-values!__2
      (lambda (_%stx191124%_ _%rebind?191125%_ _%phi191126%_)
        (let ((_%ctx191128%_ (gx#current-expander-context)))
          (gx#core-bind-values!__%
           _%stx191124%_
           _%rebind?191125%_
           _%phi191126%_
           _%ctx191128%_))))
    (define gx#core-bind-values!
      (lambda _g194126_
        (let ((_g194127_ (##length _g194126_)))
          (cond ((##fx= _g194127_ 1) (apply gx#core-bind-values!__0 _g194126_))
                ((##fx= _g194127_ 2) (apply gx#core-bind-values!__1 _g194126_))
                ((##fx= _g194127_ 3) (apply gx#core-bind-values!__2 _g194126_))
                ((##fx= _g194127_ 4) (apply gx#core-bind-values!__% _g194126_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-values!
                  _g194126_))))))
    (define gx#core-quote-bind-values
      (lambda (_%stx191094%_)
        (gx#stx-map1
         (lambda (_%x191096%_)
           (if (gx#identifier? _%x191096%_)
               (gx#core-quote-syntax__0 _%x191096%_)
               '#f))
         _%stx191094%_)))
    (define gx#core-runtime-ref?
      (lambda (_%stx191087%_)
        (if (gx#identifier? _%stx191087%_)
            (let* ((_%bind191089%_ (gx#resolve-identifier__0 _%stx191087%_))
                   (_%$e191091%_ (not _%bind191089%_)))
              (if _%$e191091%_
                  _%$e191091%_
                  (##structure-instance-of?
                   _%bind191089%_
                   'gx#runtime-binding::t)))
            '#f)))
    (define gx#core-quote-runtime-ref
      (lambda (_%id191076%_ _%form191077%_)
        (let ((_%bind191079%_ (gx#resolve-identifier__0 _%id191076%_)))
          (if (##structure-instance-of? _%bind191079%_ 'gx#runtime-binding::t)
              (gx#core-quote-syntax__0 _%id191076%_)
              (if _%bind191079%_
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; not a runtime binding"
                   _%form191077%_
                   _%id191076%_)
                  (if (or (gx#core-context-rebind?__% (gx#core-context-top__0))
                          (gx#core-extern-symbol? (gx#stx-e _%id191076%_)))
                      (gx#core-quote-syntax__0 _%id191076%_)
                      (gx#raise-syntax-error
                       '#f
                       '"Reference to unbound identifier"
                       _%form191077%_
                       _%id191076%_)))))))
    (define gx#core-bind-runtime!__%
      (lambda (_%id191031%_ _%rebind?191032%_ _%phi191033%_ _%ctx191034%_)
        (let* ((_%key191036%_ (gx#core-identifier-key _%id191031%_))
               (_%eid191038%_
                (gx#make-binding-id__%
                 _%key191036%_
                 '#f
                 _%phi191033%_
                 _%ctx191034%_))
               (_%bind191044%_
                (if (##structure-instance-of?
                     _%ctx191034%_
                     'gx#module-context::t)
                    (let ((__obj194103
                           (##structure
                            gx#module-binding::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f)))
                      (gx#module-binding:::init!
                       __obj194103
                       _%eid191038%_
                       _%key191036%_
                       _%phi191033%_
                       _%ctx191034%_)
                      __obj194103)
                    (if (##structure-instance-of?
                         _%ctx191034%_
                         'gx#top-context::t)
                        (let ((__obj194102
                               (##structure
                                gx#top-binding::t
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f)))
                          (gx#top-binding:::init!
                           __obj194102
                           _%eid191038%_
                           _%key191036%_
                           _%phi191033%_)
                          __obj194102)
                        (if (##structure-instance-of?
                             _%ctx191034%_
                             'gx#local-context::t)
                            (let ((__obj194101
                                   (##structure
                                    gx#local-binding::t
                                    '#f
                                    '#f
                                    '#f
                                    '#f
                                    '#f
                                    '#f)))
                              (gx#local-binding:::init!
                               __obj194101
                               _%eid191038%_
                               _%key191036%_
                               _%phi191033%_)
                              __obj194101)
                            (let ((__obj194100
                                   (##structure
                                    gx#runtime-binding::t
                                    '#f
                                    '#f
                                    '#f
                                    '#f
                                    '#f
                                    '#f)))
                              (gx#runtime-binding:::init!
                               __obj194100
                               _%eid191038%_
                               _%key191036%_
                               _%phi191033%_)
                              __obj194100))))))
          (gx#bind-identifier!__%
           _%id191031%_
           _%bind191044%_
           _%rebind?191032%_
           _%phi191033%_
           _%ctx191034%_))))
    (define gx#core-bind-runtime!__0
      (lambda (_%id191050%_)
        (let* ((_%rebind?191052%_ '#f)
               (_%phi191054%_ (gx#current-expander-phi))
               (_%ctx191056%_ (gx#current-expander-context)))
          (gx#core-bind-runtime!__%
           _%id191050%_
           _%rebind?191052%_
           _%phi191054%_
           _%ctx191056%_))))
    (define gx#core-bind-runtime!__1
      (lambda (_%id191058%_ _%rebind?191059%_)
        (let* ((_%phi191061%_ (gx#current-expander-phi))
               (_%ctx191063%_ (gx#current-expander-context)))
          (gx#core-bind-runtime!__%
           _%id191058%_
           _%rebind?191059%_
           _%phi191061%_
           _%ctx191063%_))))
    (define gx#core-bind-runtime!__2
      (lambda (_%id191065%_ _%rebind?191066%_ _%phi191067%_)
        (let ((_%ctx191069%_ (gx#current-expander-context)))
          (gx#core-bind-runtime!__%
           _%id191065%_
           _%rebind?191066%_
           _%phi191067%_
           _%ctx191069%_))))
    (define gx#core-bind-runtime!
      (lambda _g194128_
        (let ((_g194129_ (##length _g194128_)))
          (cond ((##fx= _g194129_ 1)
                 (apply gx#core-bind-runtime!__0 _g194128_))
                ((##fx= _g194129_ 2)
                 (apply gx#core-bind-runtime!__1 _g194128_))
                ((##fx= _g194129_ 3)
                 (apply gx#core-bind-runtime!__2 _g194128_))
                ((##fx= _g194129_ 4)
                 (apply gx#core-bind-runtime!__% _g194128_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-runtime!
                  _g194128_))))))
    (define gx#core-bind-runtime-reference!__%
      (lambda (_%id190983%_
               _%eid190984%_
               _%rebind?190985%_
               _%phi190986%_
               _%ctx190987%_)
        (let* ((_%key190989%_ (gx#core-identifier-key _%id190983%_))
               (_%bind190994%_
                (if (##structure-instance-of?
                     _%ctx190987%_
                     'gx#module-context::t)
                    (let ((__obj194106
                           (##structure
                            gx#module-binding::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f)))
                      (gx#module-binding:::init!
                       __obj194106
                       _%eid190984%_
                       _%key190989%_
                       _%phi190986%_
                       _%ctx190987%_)
                      __obj194106)
                    (if (##structure-instance-of?
                         _%ctx190987%_
                         'gx#top-context::t)
                        (let ((__obj194105
                               (##structure
                                gx#top-binding::t
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f)))
                          (gx#top-binding:::init!
                           __obj194105
                           _%eid190984%_
                           _%key190989%_
                           _%phi190986%_)
                          __obj194105)
                        (let ((__obj194104
                               (##structure
                                gx#runtime-binding::t
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f)))
                          (gx#runtime-binding:::init!
                           __obj194104
                           _%eid190984%_
                           _%key190989%_
                           _%phi190986%_)
                          __obj194104)))))
          (gx#bind-identifier!__%
           _%id190983%_
           _%bind190994%_
           _%rebind?190985%_
           _%phi190986%_
           _%ctx190987%_))))
    (define gx#core-bind-runtime-reference!__0
      (lambda (_%id191000%_ _%eid191001%_)
        (let* ((_%rebind?191003%_ '#f)
               (_%phi191005%_ (gx#current-expander-phi))
               (_%ctx191007%_ (gx#current-expander-context)))
          (gx#core-bind-runtime-reference!__%
           _%id191000%_
           _%eid191001%_
           _%rebind?191003%_
           _%phi191005%_
           _%ctx191007%_))))
    (define gx#core-bind-runtime-reference!__1
      (lambda (_%id191009%_ _%eid191010%_ _%rebind?191011%_)
        (let* ((_%phi191013%_ (gx#current-expander-phi))
               (_%ctx191015%_ (gx#current-expander-context)))
          (gx#core-bind-runtime-reference!__%
           _%id191009%_
           _%eid191010%_
           _%rebind?191011%_
           _%phi191013%_
           _%ctx191015%_))))
    (define gx#core-bind-runtime-reference!__2
      (lambda (_%id191017%_ _%eid191018%_ _%rebind?191019%_ _%phi191020%_)
        (let ((_%ctx191022%_ (gx#current-expander-context)))
          (gx#core-bind-runtime-reference!__%
           _%id191017%_
           _%eid191018%_
           _%rebind?191019%_
           _%phi191020%_
           _%ctx191022%_))))
    (define gx#core-bind-runtime-reference!
      (lambda _g194130_
        (let ((_g194131_ (##length _g194130_)))
          (cond ((##fx= _g194131_ 2)
                 (apply gx#core-bind-runtime-reference!__0 _g194130_))
                ((##fx= _g194131_ 3)
                 (apply gx#core-bind-runtime-reference!__1 _g194130_))
                ((##fx= _g194131_ 4)
                 (apply gx#core-bind-runtime-reference!__2 _g194130_))
                ((##fx= _g194131_ 5)
                 (apply gx#core-bind-runtime-reference!__% _g194130_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-runtime-reference!
                  _g194130_))))))
    (define gx#core-bind-extern!__%
      (lambda (_%id190943%_
               _%eid190944%_
               _%rebind?190945%_
               _%phi190946%_
               _%ctx190947%_)
        (gx#bind-identifier!__%
         _%id190943%_
         (let ((__obj194107
                (##structure gx#extern-binding::t '#f '#f '#f '#f '#f '#f)))
           (gx#extern-binding:::init!
            __obj194107
            _%eid190944%_
            (gx#core-identifier-key _%id190943%_)
            _%phi190946%_)
           __obj194107)
         _%rebind?190945%_
         _%phi190946%_
         _%ctx190947%_)))
    (define gx#core-bind-extern!__0
      (lambda (_%id190952%_ _%eid190953%_)
        (let* ((_%rebind?190955%_ '#f)
               (_%phi190957%_ (gx#current-expander-phi))
               (_%ctx190959%_ (gx#current-expander-context)))
          (gx#core-bind-extern!__%
           _%id190952%_
           _%eid190953%_
           _%rebind?190955%_
           _%phi190957%_
           _%ctx190959%_))))
    (define gx#core-bind-extern!__1
      (lambda (_%id190961%_ _%eid190962%_ _%rebind?190963%_)
        (let* ((_%phi190965%_ (gx#current-expander-phi))
               (_%ctx190967%_ (gx#current-expander-context)))
          (gx#core-bind-extern!__%
           _%id190961%_
           _%eid190962%_
           _%rebind?190963%_
           _%phi190965%_
           _%ctx190967%_))))
    (define gx#core-bind-extern!__2
      (lambda (_%id190969%_ _%eid190970%_ _%rebind?190971%_ _%phi190972%_)
        (let ((_%ctx190974%_ (gx#current-expander-context)))
          (gx#core-bind-extern!__%
           _%id190969%_
           _%eid190970%_
           _%rebind?190971%_
           _%phi190972%_
           _%ctx190974%_))))
    (define gx#core-bind-extern!
      (lambda _g194132_
        (let ((_g194133_ (##length _g194132_)))
          (cond ((##fx= _g194133_ 2) (apply gx#core-bind-extern!__0 _g194132_))
                ((##fx= _g194133_ 3) (apply gx#core-bind-extern!__1 _g194132_))
                ((##fx= _g194133_ 4) (apply gx#core-bind-extern!__2 _g194132_))
                ((##fx= _g194133_ 5) (apply gx#core-bind-extern!__% _g194132_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-extern!
                  _g194132_))))))
    (define gx#core-bind-syntax!__%
      (lambda (_%id190897%_
               _%e190898%_
               _%rebind?190899%_
               _%phi190900%_
               _%ctx190901%_)
        (gx#bind-identifier!__%
         _%id190897%_
         (let ((_%key190906%_ (gx#core-identifier-key _%id190897%_))
               (_%e190907%_
                (if (or (##structure-instance-of? _%e190898%_ 'gx#expander::t)
                        (##structure-instance-of?
                         _%e190898%_
                         'gx#expander-context::t))
                    _%e190898%_
                    (##structure
                     gx#user-expander::t
                     _%e190898%_
                     _%ctx190901%_
                     _%phi190900%_))))
           (let ((__obj194108
                  (##structure gx#syntax-binding::t '#f '#f '#f '#f '#f)))
             (gx#syntax-binding:::init!
              __obj194108
              (gx#make-binding-id__%
               _%key190906%_
               '#t
               _%phi190900%_
               _%ctx190901%_)
              _%key190906%_
              _%phi190900%_
              _%e190907%_)
             __obj194108))
         _%rebind?190899%_
         _%phi190900%_
         _%ctx190901%_)))
    (define gx#core-bind-syntax!__0
      (lambda (_%id190912%_ _%e190913%_)
        (let* ((_%rebind?190915%_ '#f)
               (_%phi190917%_ (gx#current-expander-phi))
               (_%ctx190919%_ (gx#current-expander-context)))
          (gx#core-bind-syntax!__%
           _%id190912%_
           _%e190913%_
           _%rebind?190915%_
           _%phi190917%_
           _%ctx190919%_))))
    (define gx#core-bind-syntax!__1
      (lambda (_%id190921%_ _%e190922%_ _%rebind?190923%_)
        (let* ((_%phi190925%_ (gx#current-expander-phi))
               (_%ctx190927%_ (gx#current-expander-context)))
          (gx#core-bind-syntax!__%
           _%id190921%_
           _%e190922%_
           _%rebind?190923%_
           _%phi190925%_
           _%ctx190927%_))))
    (define gx#core-bind-syntax!__2
      (lambda (_%id190929%_ _%e190930%_ _%rebind?190931%_ _%phi190932%_)
        (let ((_%ctx190934%_ (gx#current-expander-context)))
          (gx#core-bind-syntax!__%
           _%id190929%_
           _%e190930%_
           _%rebind?190931%_
           _%phi190932%_
           _%ctx190934%_))))
    (define gx#core-bind-syntax!
      (lambda _g194134_
        (let ((_g194135_ (##length _g194134_)))
          (cond ((##fx= _g194135_ 2) (apply gx#core-bind-syntax!__0 _g194134_))
                ((##fx= _g194135_ 3) (apply gx#core-bind-syntax!__1 _g194134_))
                ((##fx= _g194135_ 4) (apply gx#core-bind-syntax!__2 _g194134_))
                ((##fx= _g194135_ 5) (apply gx#core-bind-syntax!__% _g194134_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-syntax!
                  _g194134_))))))
    (define gx#core-bind-root-syntax!__%
      (lambda (_%id190880%_ _%e190881%_ _%rebind?190882%_)
        (gx#core-bind-syntax!__%
         _%id190880%_
         _%e190881%_
         _%rebind?190882%_
         '0
         (gx#core-context-root__0))))
    (define gx#core-bind-root-syntax!__0
      (lambda (_%id190887%_ _%e190888%_)
        (let ((_%rebind?190890%_ '#f))
          (gx#core-bind-root-syntax!__%
           _%id190887%_
           _%e190888%_
           _%rebind?190890%_))))
    (define gx#core-bind-root-syntax!
      (lambda _g194136_
        (let ((_g194137_ (##length _g194136_)))
          (cond ((##fx= _g194137_ 2)
                 (apply gx#core-bind-root-syntax!__0 _g194136_))
                ((##fx= _g194137_ 3)
                 (apply gx#core-bind-root-syntax!__% _g194136_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-root-syntax!
                  _g194136_))))))
    (define gx#core-bind-alias!__%
      (lambda (_%id190838%_
               _%alias-id190839%_
               _%rebind?190840%_
               _%phi190841%_
               _%ctx190842%_)
        (gx#bind-identifier!__%
         _%id190838%_
         (let* ((_%key190844%_ (gx#core-identifier-key _%id190838%_))
                (__obj194109
                 (##structure gx#alias-binding::t '#f '#f '#f '#f '#f)))
           (gx#alias-binding:::init!
            __obj194109
            (gx#make-binding-id__%
             _%key190844%_
             '#t
             _%phi190841%_
             _%ctx190842%_)
            _%key190844%_
            _%phi190841%_
            _%alias-id190839%_)
           __obj194109)
         _%rebind?190840%_
         _%phi190841%_
         _%ctx190842%_)))
    (define gx#core-bind-alias!__0
      (lambda (_%id190849%_ _%alias-id190850%_)
        (let* ((_%rebind?190852%_ '#f)
               (_%phi190854%_ (gx#current-expander-phi))
               (_%ctx190856%_ (gx#current-expander-context)))
          (gx#core-bind-alias!__%
           _%id190849%_
           _%alias-id190850%_
           _%rebind?190852%_
           _%phi190854%_
           _%ctx190856%_))))
    (define gx#core-bind-alias!__1
      (lambda (_%id190858%_ _%alias-id190859%_ _%rebind?190860%_)
        (let* ((_%phi190862%_ (gx#current-expander-phi))
               (_%ctx190864%_ (gx#current-expander-context)))
          (gx#core-bind-alias!__%
           _%id190858%_
           _%alias-id190859%_
           _%rebind?190860%_
           _%phi190862%_
           _%ctx190864%_))))
    (define gx#core-bind-alias!__2
      (lambda (_%id190866%_ _%alias-id190867%_ _%rebind?190868%_ _%phi190869%_)
        (let ((_%ctx190871%_ (gx#current-expander-context)))
          (gx#core-bind-alias!__%
           _%id190866%_
           _%alias-id190867%_
           _%rebind?190868%_
           _%phi190869%_
           _%ctx190871%_))))
    (define gx#core-bind-alias!
      (lambda _g194138_
        (let ((_g194139_ (##length _g194138_)))
          (cond ((##fx= _g194139_ 2) (apply gx#core-bind-alias!__0 _g194138_))
                ((##fx= _g194139_ 3) (apply gx#core-bind-alias!__1 _g194138_))
                ((##fx= _g194139_ 4) (apply gx#core-bind-alias!__2 _g194138_))
                ((##fx= _g194139_ 5) (apply gx#core-bind-alias!__% _g194138_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-alias!
                  _g194138_))))))
    (define gx#make-binding-id__%
      (lambda (_%key190788%_ _%syntax?190789%_ _%phi190790%_ _%ctx190791%_)
        (if (uninterned-symbol? _%key190788%_)
            (##gensym 'L)
            (if (pair? _%key190788%_)
                (gensym (##car _%key190788%_))
                (if (##structure-instance-of? _%ctx190791%_ 'gx#top-context::t)
                    (let ((_%ns190796%_
                           (gx#core-context-namespace__% _%ctx190791%_)))
                      (if (and (fxzero? _%phi190790%_) (not _%syntax?190789%_))
                          (if _%ns190796%_
                              (make-symbol__1 _%ns190796%_ '"#" _%key190788%_)
                              _%key190788%_)
                          (if _%syntax?190789%_
                              (make-symbol__1
                               (let ((_%$e190800%_ _%ns190796%_))
                                 (if _%$e190800%_ _%$e190800%_ '""))
                               '"[:"
                               (number->string _%phi190790%_)
                               '":]#"
                               _%key190788%_)
                              (make-symbol__1
                               (let ((_%$e190804%_ _%ns190796%_))
                                 (if _%$e190804%_ _%$e190804%_ '""))
                               '"["
                               (number->string _%phi190790%_)
                               '"]#"
                               _%key190788%_))))
                    (gensym _%key190788%_))))))
    (define gx#make-binding-id__0
      (lambda (_%key190811%_)
        (let* ((_%syntax?190813%_ '#f)
               (_%phi190815%_ (gx#current-expander-phi))
               (_%ctx190817%_ (gx#current-expander-context)))
          (gx#make-binding-id__%
           _%key190811%_
           _%syntax?190813%_
           _%phi190815%_
           _%ctx190817%_))))
    (define gx#make-binding-id__1
      (lambda (_%key190819%_ _%syntax?190820%_)
        (let* ((_%phi190822%_ (gx#current-expander-phi))
               (_%ctx190824%_ (gx#current-expander-context)))
          (gx#make-binding-id__%
           _%key190819%_
           _%syntax?190820%_
           _%phi190822%_
           _%ctx190824%_))))
    (define gx#make-binding-id__2
      (lambda (_%key190826%_ _%syntax?190827%_ _%phi190828%_)
        (let ((_%ctx190830%_ (gx#current-expander-context)))
          (gx#make-binding-id__%
           _%key190826%_
           _%syntax?190827%_
           _%phi190828%_
           _%ctx190830%_))))
    (define gx#make-binding-id
      (lambda _g194140_
        (let ((_g194141_ (##length _g194140_)))
          (cond ((##fx= _g194141_ 1) (apply gx#make-binding-id__0 _g194140_))
                ((##fx= _g194141_ 2) (apply gx#make-binding-id__1 _g194140_))
                ((##fx= _g194141_ 3) (apply gx#make-binding-id__2 _g194140_))
                ((##fx= _g194141_ 4) (apply gx#make-binding-id__% _g194140_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#make-binding-id
                  _g194140_))))))))
