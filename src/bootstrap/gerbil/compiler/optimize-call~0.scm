(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/optimize-call::timestamp 1795039824)
  (begin
    (define gxc#::optimize-call::t
      (let ((__tmp270750 (list gxc#::basic-xform::t))
            (__tmp270749 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::optimize-call::t
         '::optimize-call
         __tmp270750
         '()
         __tmp270749
         '#f)))
    (define gxc#::optimize-call?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::optimize-call::t)))
    (define gxc#make-::optimize-call
      (lambda _%$args269815%_
        (apply make-instance gxc#::optimize-call::t _%$args269815%_)))
    (define gxc#::optimize-call-bind-methods!
      (let ((__tmp270751
             (lambda ()
               (force gxc#::basic-xform-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::optimize-call::t
                  '%#call
                  gxc#optimize-call%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::optimize-call::t
                  '%#if
                  gxc#optimize-if%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::optimize-call::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp270751)))
    (define gxc#apply-optimize-call
      (lambda (_%stx269807%_)
        (force gxc#::optimize-call-bind-methods!)
        (let* ((_%self269810%_
                (let ((__obj270741
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::optimize-call::t))))
                  __obj270741))
               (__tmp270752
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self269810%_ _%stx269807%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp270752
           gxc#current-compile-method
           _%self269810%_))))
    (define gxc#::check-return-type::t
      (let ((__tmp270754 (list gxc#::void::t))
            (__tmp270753 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::check-return-type::t
         '::check-return-type
         __tmp270754
         '()
         __tmp270753
         '#f)))
    (define gxc#::check-return-type?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::check-return-type::t)))
    (define gxc#make-::check-return-type
      (lambda _%$args269804%_
        (apply make-instance gxc#::check-return-type::t _%$args269804%_)))
    (define gxc#::check-return-type-bind-methods!
      (let ((__tmp270755
             (lambda ()
               (force gxc#::void-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#begin
                  gxc#apply-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#begin-syntax
                  gxc#apply-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#begin-annotation
                  gxc#apply-check-return-type-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#module
                  gxc#apply-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#define-values
                  gxc#apply-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#define-syntax
                  gxc#apply-define-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#lambda
                  gxc#apply-body-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#case-lambda
                  gxc#apply-body-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#let-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#letrec-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#letrec*-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#call
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#if
                  gxc#apply-path-type-if%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::check-return-type::t
                  '%#set!
                  gxc#apply-body-setq%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::check-return-type::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp270755)))
    (define gxc#apply-check-return-type
      (lambda (_%stx269796%_)
        (force gxc#::check-return-type-bind-methods!)
        (let* ((_%self269799%_
                (let ((__obj270743
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::check-return-type::t))))
                  __obj270743))
               (__tmp270756
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self269799%_ _%stx269796%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp270756
           gxc#current-compile-method
           _%self269799%_))))
    (define gxc#optimize-call%
      (lambda (_%self268932%_ _%stx268933%_)
        (let* ((_%__stx269956269957%_ _%stx268933%_)
               (_%$%g268937269019%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx269956269957%_)))))
          (let ((_%__kont269958269959%_
                 (lambda (_%$%g268939269583%_ _%$%g268940269584%_)
                   (let* ((_%rator-id269604%_
                           (let ()
                             (declare (not safe))
                             (gxc#identifier-symbol _%$%g268940269584%_)))
                          (_%rator-type269606%_
                           (let ()
                             (declare (not safe))
                             (gxc#optimizer-resolve-type _%rator-id269604%_)))
                          (_%$e269609%_
                           (let ()
                             (declare (not safe))
                             (__hash-get
                              gxc#special-procedure-optimizers
                              _%rator-id269604%_))))
                     (if _%$e269609%_
                         (_%$e269609%_ _%self268932%_ _%stx268933%_)
                         (if (or (not _%rator-type269606%_)
                                 (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%rator-type269606%_
                                    'gxc#!nullable-type::t))
                                 (eq? (##structure-ref
                                       _%rator-type269606%_
                                       '1
                                       gxc#!type::t
                                       '#f)
                                      't))
                             (let ()
                               (declare (not safe))
                               (gxc#xform-call% _%self268932%_ _%stx268933%_))
                             (if (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%rator-type269606%_
                                    'gxc#!procedure::t))
                                 (let ()
                                   (let ((__tmp270757
                                          (let ()
                                            (declare (not safe))
                                            (##unchecked-structure-ref
                                             _%rator-type269606%_
                                             '1
                                             '#f
                                             '#f))))
                                     (declare (not safe))
                                     (gxc#verbose
                                      '"optimize-call "
                                      _%rator-id269604%_
                                      '" => "
                                      _%rator-type269606%_
                                      '" "
                                      __tmp270757))
                                   (let* ((_%optimized269629%_
                                           (let ((__method270744
                                                  (let ()
                                                    (declare (not safe))
                                                    (__method-ref
                                                     _%rator-type269606%_
                                                     'optimize-call))))
                                             (if __method270744
                                                 (let ((__tmp270758
                                                        (let ((__tmp270759
                                                               (lambda (_%$%g269621269624%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                _%$%g269622269626%_)
                         (cons _%$%g269621269624%_ _%$%g269622269626%_))))
                  (declare (not safe))
                  (foldr__0 __tmp270759 '() _%$%g268939269583%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (declare (not safe))
                                                   (__method270744
                                                    _%rator-type269606%_
                                                    _%self268932%_
                                                    _%stx268933%_
                                                    __tmp270758))
                                                 (begin
                                                   (let ()
                                                     (declare (not safe))
                                                     (error '"Missing method"
                                                            _%rator-type269606%_
                                                            'optimize-call))
                                                   '#!void))))
                                          (_%__stx269904269905%_
                                           _%optimized269629%_)
                                          (_%$%g269632269661%_
                                           (lambda ()
                                             (let ()
                                               (declare (not safe))
                                               (gx#raise-syntax-error
                                                '#f
                                                '"Bad syntax; invalid match target"
                                                _%__stx269904269905%_)))))
                                     (let ((_%__kont269906269907%_
                                            (lambda (_%$%g269634269727%_
                                                     _%$%g269635269728%_)
                                              (let* ((_%optimized-rator-id269756%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gxc#identifier-symbol
                                                         _%$%g269635269728%_)))
                                                     (_%rator-type269761%_
                                                      (let ((_%$e269758%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gxc#optimizer-lookup-type
                        _%optimized-rator-id269756%_))))
                (if _%$e269758%_ _%$e269758%_ _%rator-type269606%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (or (let ()
                                                          (declare (not safe))
                                                          (class-instance?
                                                           gxc#!primitive::t
                                                           _%rator-type269761%_))
                                                        (let ()
                                                          (declare (not safe))
                                                          (##memq _%optimized-rator-id269756%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          gxc#checked-primitives))
                (and (let ()
                       (declare (not safe))
                       (##structure-instance-of?
                        _%rator-type269761%_
                        'gxc#!procedure::t))
                     (eq? (let ()
                            (declare (not safe))
                            (gxc#!procedure-origin _%rator-type269761%_))
                          (##structure-ref
                           (let ()
                             (declare (not safe))
                             (gx#current-expander-context))
                           '1
                           gx#expander-context::t
                           '#f))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    _%optimized269629%_
                                                    (let ((__tmp270760
                                                           (cons '%#call-unchecked
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f '%#ref))
                                     (cons _%$%g269635269728%_ '()))
                               (let ((__tmp270761
                                      (lambda (_%$%g269769269772%_
                                               _%$%g269770269774%_)
                                        (cons _%$%g269769269772%_
                                              _%$%g269770269774%_))))
                                 (declare (not safe))
                                 (foldr__0
                                  __tmp270761
                                  '()
                                  _%$%g269634269727%_))))))
              (declare (not safe))
              (gxc#xform-wrap-source __tmp270760 _%stx268933%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (_%__kont269910269911%_
                                            (lambda () _%optimized269629%_)))
                                       (let ((_%__match269953269954%_
                                              (lambda (_%$%e269636269673%_
                                                       _%$%hd269637269676%_
                                                       _%$%tl269638269678%_
                                                       _%$%e269639269681%_
                                                       _%$%hd269640269684%_
                                                       _%$%tl269641269686%_
                                                       _%$%e269642269689%_
                                                       _%$%hd269643269692%_
                                                       _%$%tl269644269694%_
                                                       _%$%e269645269697%_
                                                       _%$%hd269646269700%_
                                                       _%$%tl269647269702%_
                                                       _%__splice269908269909%_
                                                       _%$%target269648269705%_
                                                       _%$%tl269650269707%_)
                                                (letrec ((_%$%loop269651269710%_
                                                          (lambda (_%$%hd269649269713%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%arg269655269715%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd269649269713%_))
                        (let ((_%$%e269652269717%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd269649269713%_))))
                          (let ((_%$%lp-tl269654269722%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e269652269717%_)))
                                (_%$%lp-hd269653269720%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e269652269717%_))))
                            (_%$%loop269651269710%_
                             _%$%lp-tl269654269722%_
                             (cons _%$%lp-hd269653269720%_
                                   _%$%arg269655269715%_))))
                        (let ((_%$%arg269656269725%_
                               (reverse _%$%arg269655269715%_)))
                          (_%__kont269906269907%_
                           _%$%arg269656269725%_
                           _%$%hd269646269700%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop269651269710%_
                                                   _%$%target269648269705%_
                                                   '())))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%__stx269904269905%_))
                                             (let ((_%$%e269636269673%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%__stx269904269905%_))))
                                               (let ((_%$%tl269638269678%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e269636269673%_)))
                                                     (_%$%hd269637269676%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e269636269673%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#identifier?
                                                        _%$%hd269637269676%_))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-eq?
                                                            '%#call
                                                            _%$%hd269637269676%_))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-pair? _%$%tl269638269678%_))
                     (let ((_%$%e269639269681%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl269638269678%_))))
                       (let ((_%$%tl269641269686%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e269639269681%_)))
                             (_%$%hd269640269684%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e269639269681%_))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-pair? _%$%hd269640269684%_))
                             (let ((_%$%e269642269689%_
                                    (let ()
                                      (declare (not safe))
                                      (gx#stx-e _%$%hd269640269684%_))))
                               (let ((_%$%tl269644269694%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e269642269689%_)))
                                     (_%$%hd269643269692%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e269642269689%_))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#identifier? _%$%hd269643269692%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-eq?
                                            '%#ref
                                            _%$%hd269643269692%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%$%tl269644269694%_))
                                             (let ((_%$%e269645269697%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%tl269644269694%_))))
                                               (let ((_%$%tl269647269702%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e269645269697%_)))
                                                     (_%$%hd269646269700%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e269645269697%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-null?
                                                        _%$%tl269647269702%_))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-pair/null?
                                                            _%$%tl269641269686%_))
                                                         (let ((_%__splice269908269909%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#syntax-split-splice->vector
                           _%$%tl269641269686%_
                           '0))))
                   (let ((_%$%tl269650269707%_
                          (let ()
                            (declare (not safe))
                            (##vector-ref _%__splice269908269909%_ '1)))
                         (_%$%target269648269705%_
                          (let ()
                            (declare (not safe))
                            (##vector-ref _%__splice269908269909%_ '0))))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-null? _%$%tl269650269707%_))
                         (_%__match269953269954%_
                          _%$%e269636269673%_
                          _%$%hd269637269676%_
                          _%$%tl269638269678%_
                          _%$%e269639269681%_
                          _%$%hd269640269684%_
                          _%$%tl269641269686%_
                          _%$%e269642269689%_
                          _%$%hd269643269692%_
                          _%$%tl269644269694%_
                          _%$%e269645269697%_
                          _%$%hd269646269700%_
                          _%$%tl269647269702%_
                          _%__splice269908269909%_
                          _%$%target269648269705%_
                          _%$%tl269650269707%_)
                         (_%__kont269910269911%_))))
                 (_%__kont269910269911%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%__kont269910269911%_))))
                                             (_%__kont269910269911%_))
                                         (_%__kont269910269911%_))
                                     (_%__kont269910269911%_))))
                             (_%__kont269910269911%_))))
                     (_%__kont269910269911%_))
                 (_%__kont269910269911%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%__kont269910269911%_))))
                                             (_%__kont269910269911%_))))))
                                 (if (and (let ()
                                            (declare (not safe))
                                            (##structure-instance-of?
                                             _%rator-type269606%_
                                             'gxc#!class::t))
                                          (eq? (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%rator-type269606%_
                                                  '1
                                                  '#f
                                                  '#f))
                                               'procedure))
                                     (let ((__tmp270762
                                            (cons '%#call-unchecked
                                                  (cons (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f '%#ref))
                      (cons _%$%g268940269584%_ '()))
                (map (lambda (_%$%g269780269782%_)
                       (let ()
                         (declare (not safe))
                         (gxc#compile-e__1
                          _%self268932%_
                          _%$%g269780269782%_)))
                     (let ((__tmp270763
                            (lambda (_%$%g269784269787%_ _%$%g269785269789%_)
                              (cons _%$%g269784269787%_ _%$%g269785269789%_))))
                       (declare (not safe))
                       (foldr__0 __tmp270763 '() _%$%g268939269583%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (declare (not safe))
                                       (gxc#xform-wrap-source
                                        __tmp270762
                                        _%stx268933%_))
                                     (let ()
                                       (declare (not safe))
                                       (gxc#raise-compile-error
                                        '"illegal application; not a procedure"
                                        _%stx268933%_
                                        _%rator-type269606%_)))))))))
                (_%__kont269962269963%_
                 (lambda (_%$%g268962269191%_
                          _%$%g268963269192%_
                          _%$%g268964269193%_)
                   (let _%loop269311%_ ((_%rest-arg269313%_
                                         (let ((__tmp270770
                                                (lambda (_%$%g269509269512%_
                                                         _%$%g269510269514%_)
                                                  (cons _%$%g269509269512%_
                                                        _%$%g269510269514%_))))
                                           (declare (not safe))
                                           (foldr__0
                                            __tmp270770
                                            '()
                                            _%$%g268964269193%_)))
                                        (_%rest-rand269314%_
                                         (let ((__tmp270771
                                                (lambda (_%$%g269516269519%_
                                                         _%$%g269517269521%_)
                                                  (cons _%$%g269516269519%_
                                                        _%$%g269517269521%_))))
                                           (declare (not safe))
                                           (foldr__0
                                            __tmp270771
                                            '()
                                            _%$%g268962269191%_)))
                                        (_%bind269315%_ '())
                                        (_%subst269316%_ '()))
                     (let* ((_%$%rest-arg269317269325%_ _%rest-arg269313%_)
                            (_%$%else269319269338%_
                             (lambda ()
                               (let* ((_%body269333%_
                                       (if (null? _%subst269316%_)
                                           _%$%g268963269192%_
                                           (let ((__tmp270764
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#apply-inline-subst__%
                                                     '#f
                                                     _%subst269316%_
                                                     _%$%g268963269192%_))))
                                             (declare (not safe))
                                             (gxc#xform-wrap-source
                                              __tmp270764
                                              _%stx268933%_))))
                                      (_%expr269335%_
                                       (let ((__tmp270765
                                              (cons '%#let-values
                                                    (cons _%bind269315%_
                                                          (cons _%body269333%_
                                                                '())))))
                                         (declare (not safe))
                                         (gxc#xform-wrap-source
                                          __tmp270765
                                          _%stx268933%_))))
                                 (let ()
                                   (declare (not safe))
                                   (gxc#apply-refine-type-info _%expr269335%_))
                                 (let ()
                                   (declare (not safe))
                                   (gxc#compile-e__1
                                    _%self268932%_
                                    _%expr269335%_)))))
                            (_%$%K269321269498%_
                             (lambda (_%rest-arg269341%_ _%arg-id269342%_)
                               (let* ((_%$%rest-rand269343269351%_
                                       _%rest-rand269314%_)
                                      (_%$%else269345269373%_
                                       (lambda ()
                                         (let ((__tmp270768
                                                (let ((__tmp270769
                                                       (lambda (_%$%g269358269361%_
                                                                _%$%g269359269363%_)
                                                         (cons _%$%g269358269361%_
                                                               _%$%g269359269363%_))))
                                                  (declare (not safe))
                                                  (foldr__0
                                                   __tmp270769
                                                   '()
                                                   _%$%g268964269193%_)))
                                               (__tmp270766
                                                (let ((__tmp270767
                                                       (lambda (_%$%g269365269368%_
                                                                _%$%g269366269370%_)
                                                         (cons _%$%g269365269368%_
                                                               _%$%g269366269370%_))))
                                                  (declare (not safe))
                                                  (foldr__0
                                                   __tmp270767
                                                   '()
                                                   _%$%g268962269191%_))))
                                           (declare (not safe))
                                           (gxc#raise-compile-error
                                            '"inline lambda arity mismatch"
                                            _%stx268933%_
                                            __tmp270768
                                            __tmp270766))))
                                      (_%$%K269347269486%_
                                       (lambda (_%rest-rand269376%_
                                                _%rand269377%_)
                                         (let* ((_%__stx269858269859%_
                                                 _%rand269377%_)
                                                (_%$%g269381269401%_
                                                 (lambda ()
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#raise-syntax-error
                                                      '#f
                                                      '"Bad syntax; invalid match target"
                                                      _%__stx269858269859%_)))))
                                           (let ((_%__kont269860269861%_
                                                  (lambda (_%$%g269383269472%_)
                                                    (_%loop269311%_
                                                     _%rest-arg269341%_
                                                     _%rest-rand269376%_
                                                     _%bind269315%_
                                                     (cons (cons _%arg-id269342%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%rand269377%_)
                   _%subst269316%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%__kont269862269863%_
                                                  (lambda (_%$%g269390269429%_)
                                                    (_%loop269311%_
                                                     _%rest-arg269341%_
                                                     _%rest-rand269376%_
                                                     _%bind269315%_
                                                     (cons (cons _%arg-id269342%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%rand269377%_)
                   _%subst269316%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%__kont269864269865%_
                                                  (lambda ()
                                                    (_%loop269311%_
                                                     _%rest-arg269341%_
                                                     _%rest-rand269376%_
                                                     (cons (cons (cons _%arg-id269342%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               '())
                         (cons _%rand269377%_ '()))
                   _%bind269315%_)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%subst269316%_))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%__stx269858269859%_))
                                                 (let ((_%$%e269384269456%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%__stx269858269859%_))))
                                                   (let ((_%$%tl269386269461%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e269384269456%_)))
                                                         (_%$%hd269385269459%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e269384269456%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#identifier?
                                                            _%$%hd269385269459%_))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-eq? '%#quote _%$%hd269385269459%_))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%tl269386269461%_))
                         (let ((_%$%e269387269464%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%tl269386269461%_))))
                           (let ((_%$%tl269389269469%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e269387269464%_)))
                                 (_%$%hd269388269467%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e269387269464%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-null? _%$%tl269389269469%_))
                                 (_%__kont269860269861%_ _%$%hd269388269467%_)
                                 (_%__kont269864269865%_))))
                         (_%__kont269864269865%_))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-eq? '%#ref _%$%hd269385269459%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-pair? _%$%tl269386269461%_))
                             (let ((_%$%e269394269421%_
                                    (let ()
                                      (declare (not safe))
                                      (gx#stx-e _%$%tl269386269461%_))))
                               (let ((_%$%tl269396269426%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e269394269421%_)))
                                     (_%$%hd269395269424%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e269394269421%_))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-null? _%$%tl269396269426%_))
                                     (_%__kont269862269863%_
                                      _%$%hd269395269424%_)
                                     (_%__kont269864269865%_))))
                             (_%__kont269864269865%_))
                         (_%__kont269864269865%_)))
                 (_%__kont269864269865%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%__kont269864269865%_)))))))
                                 (if (pair? _%$%rest-rand269343269351%_)
                                     (let ((_%$%hd269348269489%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%rest-rand269343269351%_)))
                                           (_%$%tl269349269491%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%rest-rand269343269351%_))))
                                       (let* ((_%rand269494%_
                                               _%$%hd269348269489%_)
                                              (_%rest-rand269496%_
                                               _%$%tl269349269491%_))
                                         (_%$%K269347269486%_
                                          _%rest-rand269496%_
                                          _%rand269494%_)))
                                     (_%$%else269345269373%_))))))
                       (if (pair? _%$%rest-arg269317269325%_)
                           (let ((_%$%hd269322269501%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%rest-arg269317269325%_)))
                                 (_%$%tl269323269503%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%rest-arg269317269325%_))))
                             (let* ((_%arg-id269506%_ _%$%hd269322269501%_)
                                    (_%rest-arg269508%_ _%$%tl269323269503%_))
                               (_%$%K269321269498%_
                                _%rest-arg269508%_
                                _%arg-id269506%_)))
                           (_%$%else269319269338%_))))))
                (_%__kont269968269969%_
                 (lambda (_%$%g268998269062%_ _%$%g268999269063%_)
                   (let ((_%rator-type269080%_
                          (let ()
                            (declare (not safe))
                            (gxc#apply-basic-expression-type
                             _%$%g268999269063%_))))
                     (if (and _%rator-type269080%_
                              (eq? (##structure-ref
                                    _%rator-type269080%_
                                    '1
                                    gxc#!type::t
                                    '#f)
                                   'procedure)
                              (if (let ()
                                    (declare (not safe))
                                    (class-instance?
                                     gxc#!primitive::t
                                     _%rator-type269080%_))
                                  '#f
                                  (not (and (let ()
                                              (declare (not safe))
                                              (##structure-instance-of?
                                               _%rator-type269080%_
                                               'gxc#!procedure::t))
                                            (eq? (let ()
                                                   (declare (not safe))
                                                   (gxc#!procedure-origin
                                                    _%rator-type269080%_))
                                                 (##structure-ref
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#current-expander-context))
                                                  '1
                                                  gx#expander-context::t
                                                  '#f))))))
                         (let ((__tmp270772
                                (cons '%#call-unchecked
                                      (cons (let ()
                                              (declare (not safe))
                                              (gxc#compile-e__1
                                               _%self268932%_
                                               _%$%g268999269063%_))
                                            (map (lambda (_%$%g269082269084%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#compile-e__1
                                                      _%self268932%_
                                                      _%$%g269082269084%_)))
                                                 (let ((__tmp270773
                                                        (lambda (_%$%g269086269089%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g269087269091%_)
                  (cons _%$%g269086269089%_ _%$%g269087269091%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (declare (not safe))
                                                   (foldr__0
                                                    __tmp270773
                                                    '()
                                                    _%$%g268998269062%_)))))))
                           (declare (not safe))
                           (gxc#xform-wrap-source __tmp270772 _%stx268933%_))
                         (if (or (not _%rator-type269080%_)
                                 (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%rator-type269080%_
                                    'gxc#!nullable-type::t))
                                 (let ((__tmp270774
                                        (##structure-ref
                                         _%rator-type269080%_
                                         '1
                                         gxc#!type::t
                                         '#f)))
                                   (declare (not safe))
                                   (##memq __tmp270774 '(t procedure))))
                             (let ()
                               (declare (not safe))
                               (gxc#xform-call% _%self268932%_ _%stx268933%_))
                             (let ()
                               (declare (not safe))
                               (gxc#raise-compile-error
                                '"illegal application; not a procedure"
                                _%stx268933%_
                                _%rator-type269080%_))))))))
            (let* ((_%__match270065270066%_
                    (lambda (_%$%e269000269024%_
                             _%$%hd269001269027%_
                             _%$%tl269002269029%_
                             _%$%e269003269032%_
                             _%$%hd269004269035%_
                             _%$%tl269005269037%_
                             _%__splice269970269971%_
                             _%$%target269006269040%_
                             _%$%tl269008269042%_)
                      (letrec ((_%$%loop269009269045%_
                                (lambda (_%$%hd269007269048%_
                                         _%$%rand269013269050%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd269007269048%_))
                                      (let ((_%$%e269010269052%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd269007269048%_))))
                                        (let ((_%$%lp-tl269012269057%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e269010269052%_)))
                                              (_%$%lp-hd269011269055%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e269010269052%_))))
                                          (_%$%loop269009269045%_
                                           _%$%lp-tl269012269057%_
                                           (cons _%$%lp-hd269011269055%_
                                                 _%$%rand269013269050%_))))
                                      (let ((_%$%rand269014269060%_
                                             (reverse _%$%rand269013269050%_)))
                                        (_%__kont269968269969%_
                                         _%$%rand269014269060%_
                                         _%$%hd269004269035%_))))))
                        (_%$%loop269009269045%_
                         _%$%target269006269040%_
                         '()))))
                   (_%__match270057270058%_
                    (lambda (_%$%e269000269024%_
                             _%$%hd269001269027%_
                             _%$%tl269002269029%_
                             _%$%e269003269032%_
                             _%$%hd269004269035%_
                             _%$%tl269005269037%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair/null? _%$%tl269005269037%_))
                          (let ((_%__splice269970269971%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-split-splice->vector
                                    _%$%tl269005269037%_
                                    '0))))
                            (let ((_%$%tl269008269042%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice269970269971%_
                                      '1)))
                                  (_%$%target269006269040%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice269970269971%_
                                      '0))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl269008269042%_))
                                  (_%__match270065270066%_
                                   _%$%e269000269024%_
                                   _%$%hd269001269027%_
                                   _%$%tl269002269029%_
                                   _%$%e269003269032%_
                                   _%$%hd269004269035%_
                                   _%$%tl269005269037%_
                                   _%__splice269970269971%_
                                   _%$%target269006269040%_
                                   _%$%tl269008269042%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g268937269019%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g268937269019%_)))))
                   (_%__match270045270046%_
                    (lambda (_%$%e268965269107%_
                             _%$%hd268966269110%_
                             _%$%tl268967269112%_
                             _%$%e268968269115%_
                             _%$%hd268969269118%_
                             _%$%tl268970269120%_
                             _%$%e268971269123%_
                             _%$%hd268972269126%_
                             _%$%tl268973269128%_
                             _%$%e268974269131%_
                             _%$%hd268975269134%_
                             _%$%tl268976269136%_
                             _%__splice269964269965%_
                             _%$%target268977269139%_
                             _%$%tl268979269141%_)
                      (letrec ((_%$%loop268980269144%_
                                (lambda (_%$%hd268978269147%_
                                         _%$%arg268984269149%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd268978269147%_))
                                      (let ((_%$%e268981269151%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd268978269147%_))))
                                        (let ((_%$%lp-tl268983269156%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e268981269151%_)))
                                              (_%$%lp-hd268982269154%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e268981269151%_))))
                                          (_%$%loop268980269144%_
                                           _%$%lp-tl268983269156%_
                                           (cons _%$%lp-hd268982269154%_
                                                 _%$%arg268984269149%_))))
                                      (let ((_%$%arg268985269159%_
                                             (reverse _%$%arg268984269149%_)))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl268976269136%_))
                                            (let ((_%$%e268986269161%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl268976269136%_))))
                                              (let ((_%$%tl268988269166%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e268986269161%_)))
                                                    (_%$%hd268987269164%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e268986269161%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl268988269166%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair/null?
                                                           _%$%tl268970269120%_))
                                                        (let ((_%__splice269966269967%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-split-splice->vector
                          _%$%tl268970269120%_
                          '0))))
                  (let ((_%$%tl268991269171%_
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice269966269967%_ '1)))
                        (_%$%target268989269169%_
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice269966269967%_ '0))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl268991269171%_))
                        (letrec ((_%$%loop268992269174%_
                                  (lambda (_%$%hd268990269177%_
                                           _%$%rand268996269179%_)
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%hd268990269177%_))
                                        (let ((_%$%e268993269181%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd268990269177%_))))
                                          (let ((_%$%lp-tl268995269186%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e268993269181%_)))
                                                (_%$%lp-hd268994269184%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e268993269181%_))))
                                            (_%$%loop268992269174%_
                                             _%$%lp-tl268995269186%_
                                             (cons _%$%lp-hd268994269184%_
                                                   _%$%rand268996269179%_))))
                                        (let ((_%$%rand268997269189%_
                                               (reverse _%$%rand268996269179%_)))
                                          (let ((_%$%g268962269191%_
                                                 _%$%rand268997269189%_)
                                                (_%$%g268963269192%_
                                                 _%$%hd268987269164%_)
                                                (_%$%g268964269193%_
                                                 _%$%arg268985269159%_))
                                            (if (and (= (length (let ((__tmp270775
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (lambda (_%$%g269219269222%_
                                        _%$%g269220269224%_)
                                 (cons _%$%g269219269222%_
                                       _%$%g269220269224%_))))
                          (declare (not safe))
                          (foldr__0 __tmp270775 '() _%$%g268964269193%_)))
                (length (let ((__tmp270776
                               (lambda (_%$%g269226269229%_
                                        _%$%g269227269231%_)
                                 (cons _%$%g269226269229%_
                                       _%$%g269227269231%_))))
                          (declare (not safe))
                          (foldr__0 __tmp270776 '() _%$%g268962269191%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ((__tmp270779
                                                            (lambda (_%id269234%_)
                                                              (not (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (declare (not safe))
                             (gxc#mutable-binding? _%id269234%_)))))
                   (__tmp270777
                    (let ((__tmp270778
                           (lambda (_%$%g269235269238%_ _%$%g269236269240%_)
                             (cons _%$%g269235269238%_ _%$%g269236269240%_))))
                      (declare (not safe))
                      (foldr__0 __tmp270778 '() _%$%g268964269193%_))))
               (declare (not safe))
               (andmap__0 __tmp270779 __tmp270777))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ((__tmp270782
                                                            (lambda (_%rand269243%_)
                                                              (let* ((_%__stx269832269833%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%rand269243%_)
                             (_%$%g269246269259%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx269832269833%_)))))
                        (let ((_%__kont269834269835%_
                               (lambda (_%$%g269248269287%_)
                                 (not (let ()
                                        (declare (not safe))
                                        (gxc#mutable-binding?
                                         _%$%g269248269287%_)))))
                              (_%__kont269836269837%_ (lambda () '#t)))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx269832269833%_))
                              (let ((_%$%e269249269271%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx269832269833%_))))
                                (let ((_%$%tl269251269276%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e269249269271%_)))
                                      (_%$%hd269250269274%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e269249269271%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd269250269274%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd269250269274%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl269251269276%_))
                                              (let ((_%$%e269252269279%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl269251269276%_))))
                                                (let ((_%$%tl269254269284%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e269252269279%_)))
                                                      (_%$%hd269253269282%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e269252269279%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl269254269284%_))
                                                      (_%__kont269834269835%_
                                                       _%$%hd269253269282%_)
                                                      (_%__kont269836269837%_))))
                                              (_%__kont269836269837%_))
                                          (_%__kont269836269837%_))
                                      (_%__kont269836269837%_))))
                              (_%__kont269836269837%_))))))
                   (__tmp270780
                    (let ((__tmp270781
                           (lambda (_%$%g269303269306%_ _%$%g269304269308%_)
                             (cons _%$%g269303269306%_ _%$%g269304269308%_))))
                      (declare (not safe))
                      (foldr__0 __tmp270781 '() _%$%g268962269191%_))))
               (declare (not safe))
               (andmap__0 __tmp270782 __tmp270780)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__kont269962269963%_
                                                 _%$%g268962269191%_
                                                 _%$%g268963269192%_
                                                 _%$%g268964269193%_)
                                                (_%__match270065270066%_
                                                 _%$%e268965269107%_
                                                 _%$%hd268966269110%_
                                                 _%$%tl268967269112%_
                                                 _%$%e268968269115%_
                                                 _%$%hd268969269118%_
                                                 _%$%tl268970269120%_
                                                 _%__splice269966269967%_
                                                 _%$%target268989269169%_
                                                 _%$%tl268991269171%_))))))))
                          (_%$%loop268992269174%_
                           _%$%target268989269169%_
                           '()))
                        (let () (declare (not safe)) (_%$%g268937269019%_)))))
                (let () (declare (not safe)) (_%$%g268937269019%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__match270057270058%_
                                                     _%$%e268965269107%_
                                                     _%$%hd268966269110%_
                                                     _%$%tl268967269112%_
                                                     _%$%e268968269115%_
                                                     _%$%hd268969269118%_
                                                     _%$%tl268970269120%_))))
                                            (_%__match270057270058%_
                                             _%$%e268965269107%_
                                             _%$%hd268966269110%_
                                             _%$%tl268967269112%_
                                             _%$%e268968269115%_
                                             _%$%hd268969269118%_
                                             _%$%tl268970269120%_)))))))
                        (_%$%loop268980269144%_
                         _%$%target268977269139%_
                         '()))))
                   (_%__match270009270010%_
                    (lambda (_%$%e268941269529%_
                             _%$%hd268942269532%_
                             _%$%tl268943269534%_
                             _%$%e268944269537%_
                             _%$%hd268945269540%_
                             _%$%tl268946269542%_
                             _%$%e268947269545%_
                             _%$%hd268948269548%_
                             _%$%tl268949269550%_
                             _%$%e268950269553%_
                             _%$%hd268951269556%_
                             _%$%tl268952269558%_
                             _%__splice269960269961%_
                             _%$%target268953269561%_
                             _%$%tl268955269563%_)
                      (letrec ((_%$%loop268956269566%_
                                (lambda (_%$%hd268954269569%_
                                         _%$%rand268960269571%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd268954269569%_))
                                      (let ((_%$%e268957269573%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd268954269569%_))))
                                        (let ((_%$%lp-tl268959269578%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e268957269573%_)))
                                              (_%$%lp-hd268958269576%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e268957269573%_))))
                                          (_%$%loop268956269566%_
                                           _%$%lp-tl268959269578%_
                                           (cons _%$%lp-hd268958269576%_
                                                 _%$%rand268960269571%_))))
                                      (let ((_%$%rand268961269581%_
                                             (reverse _%$%rand268960269571%_)))
                                        (_%__kont269958269959%_
                                         _%$%rand268961269581%_
                                         _%$%hd268951269556%_))))))
                        (_%$%loop268956269566%_
                         _%$%target268953269561%_
                         '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx269956269957%_))
                  (let ((_%$%e268941269529%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx269956269957%_))))
                    (let ((_%$%tl268943269534%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e268941269529%_)))
                          (_%$%hd268942269532%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e268941269529%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl268943269534%_))
                          (let ((_%$%e268944269537%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl268943269534%_))))
                            (let ((_%$%tl268946269542%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e268944269537%_)))
                                  (_%$%hd268945269540%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e268944269537%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd268945269540%_))
                                  (let ((_%$%e268947269545%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd268945269540%_))))
                                    (let ((_%$%tl268949269550%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e268947269545%_)))
                                          (_%$%hd268948269548%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e268947269545%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd268948269548%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd268948269548%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl268949269550%_))
                                                  (let ((_%$%e268950269553%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl268949269550%_))))
                                                    (let ((_%$%tl268952269558%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e268950269553%_)))
                                                          (_%$%hd268951269556%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e268950269553%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl268952269558%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair/null? _%$%tl268946269542%_))
                      (let ((_%__splice269960269961%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-split-splice->vector
                                _%$%tl268946269542%_
                                '0))))
                        (let ((_%$%tl268955269563%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice269960269961%_ '1)))
                              (_%$%target268953269561%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice269960269961%_ '0))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl268955269563%_))
                              (_%__match270009270010%_
                               _%$%e268941269529%_
                               _%$%hd268942269532%_
                               _%$%tl268943269534%_
                               _%$%e268944269537%_
                               _%$%hd268945269540%_
                               _%$%tl268946269542%_
                               _%$%e268947269545%_
                               _%$%hd268948269548%_
                               _%$%tl268949269550%_
                               _%$%e268950269553%_
                               _%$%hd268951269556%_
                               _%$%tl268952269558%_
                               _%__splice269960269961%_
                               _%$%target268953269561%_
                               _%$%tl268955269563%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g268937269019%_)))))
                      (let () (declare (not safe)) (_%$%g268937269019%_)))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair/null? _%$%tl268946269542%_))
                      (let ((_%__splice269970269971%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-split-splice->vector
                                _%$%tl268946269542%_
                                '0))))
                        (let ((_%$%tl269008269042%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice269970269971%_ '1)))
                              (_%$%target269006269040%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice269970269971%_ '0))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl269008269042%_))
                              (_%__match270065270066%_
                               _%$%e268941269529%_
                               _%$%hd268942269532%_
                               _%$%tl268943269534%_
                               _%$%e268944269537%_
                               _%$%hd268945269540%_
                               _%$%tl268946269542%_
                               _%__splice269970269971%_
                               _%$%target269006269040%_
                               _%$%tl269008269042%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g268937269019%_)))))
                      (let () (declare (not safe)) (_%$%g268937269019%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair/null?
                                                         _%$%tl268946269542%_))
                                                      (let ((_%__splice269970269971%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-split-splice->vector
                        _%$%tl268946269542%_
                        '0))))
                (let ((_%$%tl269008269042%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice269970269971%_ '1)))
                      (_%$%target269006269040%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice269970269971%_ '0))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl269008269042%_))
                      (_%__match270065270066%_
                       _%$%e268941269529%_
                       _%$%hd268942269532%_
                       _%$%tl268943269534%_
                       _%$%e268944269537%_
                       _%$%hd268945269540%_
                       _%$%tl268946269542%_
                       _%__splice269970269971%_
                       _%$%target269006269040%_
                       _%$%tl269008269042%_)
                      (let () (declare (not safe)) (_%$%g268937269019%_)))))
              (let () (declare (not safe)) (_%$%g268937269019%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-eq?
                                                     '%#lambda
                                                     _%$%hd268948269548%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl268949269550%_))
                                                      (let ((_%$%e268974269131%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl268949269550%_))))
                (let ((_%$%tl268976269136%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e268974269131%_)))
                      (_%$%hd268975269134%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e268974269131%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair/null? _%$%hd268975269134%_))
                      (let ((_%__splice269964269965%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-split-splice->vector
                                _%$%hd268975269134%_
                                '0))))
                        (let ((_%$%tl268979269141%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice269964269965%_ '1)))
                              (_%$%target268977269139%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice269964269965%_ '0))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl268979269141%_))
                              (_%__match270045270046%_
                               _%$%e268941269529%_
                               _%$%hd268942269532%_
                               _%$%tl268943269534%_
                               _%$%e268944269537%_
                               _%$%hd268945269540%_
                               _%$%tl268946269542%_
                               _%$%e268947269545%_
                               _%$%hd268948269548%_
                               _%$%tl268949269550%_
                               _%$%e268974269131%_
                               _%$%hd268975269134%_
                               _%$%tl268976269136%_
                               _%__splice269964269965%_
                               _%$%target268977269139%_
                               _%$%tl268979269141%_)
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair/null? _%$%tl268946269542%_))
                                  (let ((_%__splice269970269971%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#syntax-split-splice->vector
                                            _%$%tl268946269542%_
                                            '0))))
                                    (let ((_%$%tl269008269042%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice269970269971%_
                                              '1)))
                                          (_%$%target269006269040%_
                                           (let ()
                                             (declare (not safe))
                                             (##vector-ref
                                              _%__splice269970269971%_
                                              '0))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl269008269042%_))
                                          (_%__match270065270066%_
                                           _%$%e268941269529%_
                                           _%$%hd268942269532%_
                                           _%$%tl268943269534%_
                                           _%$%e268944269537%_
                                           _%$%hd268945269540%_
                                           _%$%tl268946269542%_
                                           _%__splice269970269971%_
                                           _%$%target269006269040%_
                                           _%$%tl269008269042%_)
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g268937269019%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g268937269019%_))))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair/null? _%$%tl268946269542%_))
                          (let ((_%__splice269970269971%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-split-splice->vector
                                    _%$%tl268946269542%_
                                    '0))))
                            (let ((_%$%tl269008269042%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice269970269971%_
                                      '1)))
                                  (_%$%target269006269040%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice269970269971%_
                                      '0))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl269008269042%_))
                                  (_%__match270065270066%_
                                   _%$%e268941269529%_
                                   _%$%hd268942269532%_
                                   _%$%tl268943269534%_
                                   _%$%e268944269537%_
                                   _%$%hd268945269540%_
                                   _%$%tl268946269542%_
                                   _%__splice269970269971%_
                                   _%$%target269006269040%_
                                   _%$%tl269008269042%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g268937269019%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g268937269019%_))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair/null? _%$%tl268946269542%_))
                  (let ((_%__splice269970269971%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-split-splice->vector
                            _%$%tl268946269542%_
                            '0))))
                    (let ((_%$%tl269008269042%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice269970269971%_ '1)))
                          (_%$%target269006269040%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice269970269971%_ '0))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl269008269042%_))
                          (_%__match270065270066%_
                           _%$%e268941269529%_
                           _%$%hd268942269532%_
                           _%$%tl268943269534%_
                           _%$%e268944269537%_
                           _%$%hd268945269540%_
                           _%$%tl268946269542%_
                           _%__splice269970269971%_
                           _%$%target269006269040%_
                           _%$%tl269008269042%_)
                          (let ()
                            (declare (not safe))
                            (_%$%g268937269019%_)))))
                  (let () (declare (not safe)) (_%$%g268937269019%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair/null?
                                                         _%$%tl268946269542%_))
                                                      (let ((_%__splice269970269971%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-split-splice->vector
                        _%$%tl268946269542%_
                        '0))))
                (let ((_%$%tl269008269042%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice269970269971%_ '1)))
                      (_%$%target269006269040%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice269970269971%_ '0))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl269008269042%_))
                      (_%__match270065270066%_
                       _%$%e268941269529%_
                       _%$%hd268942269532%_
                       _%$%tl268943269534%_
                       _%$%e268944269537%_
                       _%$%hd268945269540%_
                       _%$%tl268946269542%_
                       _%__splice269970269971%_
                       _%$%target269006269040%_
                       _%$%tl269008269042%_)
                      (let () (declare (not safe)) (_%$%g268937269019%_)))))
              (let () (declare (not safe)) (_%$%g268937269019%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair/null?
                                                 _%$%tl268946269542%_))
                                              (let ((_%__splice269970269971%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-split-splice->vector
                                                        _%$%tl268946269542%_
                                                        '0))))
                                                (let ((_%$%tl269008269042%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice269970269971%_
                                                          '1)))
                                                      (_%$%target269006269040%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice269970269971%_
                                                          '0))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl269008269042%_))
                                                      (_%__match270065270066%_
                                                       _%$%e268941269529%_
                                                       _%$%hd268942269532%_
                                                       _%$%tl268943269534%_
                                                       _%$%e268944269537%_
                                                       _%$%hd268945269540%_
                                                       _%$%tl268946269542%_
                                                       _%__splice269970269971%_
                                                       _%$%target269006269040%_
                                                       _%$%tl269008269042%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g268937269019%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g268937269019%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl268946269542%_))
                                      (let ((_%__splice269970269971%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice->vector
                                                _%$%tl268946269542%_
                                                '0))))
                                        (let ((_%$%tl269008269042%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice269970269971%_
                                                  '1)))
                                              (_%$%target269006269040%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice269970269971%_
                                                  '0))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl269008269042%_))
                                              (_%__match270065270066%_
                                               _%$%e268941269529%_
                                               _%$%hd268942269532%_
                                               _%$%tl268943269534%_
                                               _%$%e268944269537%_
                                               _%$%hd268945269540%_
                                               _%$%tl268946269542%_
                                               _%__splice269970269971%_
                                               _%$%target269006269040%_
                                               _%$%tl269008269042%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g268937269019%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g268937269019%_))))))
                          (let ()
                            (declare (not safe))
                            (_%$%g268937269019%_)))))
                  (let () (declare (not safe)) (_%$%g268937269019%_))))))))
    (define gxc#optimize-special-cast
      (lambda (_%self268737%_ _%stx268738%_)
        (let* ((_%__stx270068270069%_ _%stx268738%_)
               (_%$%g268742268782%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx270068270069%_)))))
          (let ((_%__kont270070270071%_
                 (lambda (_%$%g268744268898%_ _%$%g268745268899%_)
                   (let* ((_%descriptor-id268919%_
                           (let ()
                             (declare (not safe))
                             (gxc#identifier-symbol _%$%g268745268899%_)))
                          (_%descriptor-type268921%_
                           (let ()
                             (declare (not safe))
                             (gxc#optimizer-resolve-type
                              _%descriptor-id268919%_)))
                          (_%object-type268923%_
                           (let ()
                             (declare (not safe))
                             (gxc#apply-basic-expression-type
                              _%$%g268744268898%_))))
                     (if (let ()
                           (declare (not safe))
                           (##structure-instance-of?
                            _%descriptor-type268921%_
                            'gxc#!interface::t))
                         (if (and _%object-type268923%_
                                  (let ((__tmp270783
                                         (let ((__tmp270784
                                                (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   _%descriptor-type268921%_
                                                   '1
                                                   '#f
                                                   '#f))))
                                           (declare (not safe))
                                           (gxc#optimizer-resolve-class
                                            _%stx268738%_
                                            __tmp270784))))
                                    (declare (not safe))
                                    (gxc#!type-subtype?
                                     _%object-type268923%_
                                     __tmp270783)))
                             (let ()
                               (declare (not safe))
                               (gxc#compile-e__1
                                _%self268737%_
                                _%$%g268744268898%_))
                             (let ((__tmp270785
                                    (cons '%#call-unchecked
                                          (cons '(%#ref cast)
                                                (cons (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               '%#ref))
                                                            (cons _%$%g268745268899%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              (cons (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self268737%_ _%$%g268744268898%_))
                    '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                               (declare (not safe))
                               (gxc#xform-wrap-source
                                __tmp270785
                                _%stx268738%_)))
                         (let ()
                           (declare (not safe))
                           (gxc#raise-compile-error
                            '"illegal cast; not an interface type"
                            _%stx268738%_
                            _%descriptor-type268921%_))))))
                (_%__kont270072270073%_
                 (lambda (_%$%g268764268826%_ _%$%g268765268827%_)
                   (let ((__tmp270786
                          (cons '%#call-unchecked
                                (cons '(%#ref cast)
                                      (cons (let ()
                                              (declare (not safe))
                                              (gxc#compile-e__1
                                               _%self268737%_
                                               _%$%g268765268827%_))
                                            (cons (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%self268737%_
                                                     _%$%g268764268826%_))
                                                  '()))))))
                     (declare (not safe))
                     (gxc#xform-wrap-source __tmp270786 _%stx268738%_))))
                (_%__kont270074270075%_
                 (lambda ()
                   (let ()
                     (declare (not safe))
                     (gxc#raise-compile-error
                      '"illegal cast; arity mismatch"
                      _%stx268738%_)))))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx270068270069%_))
                (let ((_%$%e268746268850%_
                       (let ()
                         (declare (not safe))
                         (gx#stx-e _%__stx270068270069%_))))
                  (let ((_%$%tl268748268855%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e268746268850%_)))
                        (_%$%hd268747268853%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e268746268850%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl268748268855%_))
                        (let ((_%$%e268749268858%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl268748268855%_))))
                          (let ((_%$%tl268751268863%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e268749268858%_)))
                                (_%$%hd268750268861%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e268749268858%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl268751268863%_))
                                (let ((_%$%e268752268866%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl268751268863%_))))
                                  (let ((_%$%tl268754268871%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e268752268866%_)))
                                        (_%$%hd268753268869%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e268752268866%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%hd268753268869%_))
                                        (let ((_%$%e268755268874%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd268753268869%_))))
                                          (let ((_%$%tl268757268879%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e268755268874%_)))
                                                (_%$%hd268756268877%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e268755268874%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#identifier?
                                                   _%$%hd268756268877%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-eq?
                                                       '%#ref
                                                       _%$%hd268756268877%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl268757268879%_))
                                                        (let ((_%$%e268758268882%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl268757268879%_))))
                  (let ((_%$%tl268760268887%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e268758268882%_)))
                        (_%$%hd268759268885%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e268758268882%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl268760268887%_))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl268754268871%_))
                            (let ((_%$%e268761268890%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl268754268871%_))))
                              (let ((_%$%tl268763268895%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e268761268890%_)))
                                    (_%$%hd268762268893%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e268761268890%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl268763268895%_))
                                    (_%__kont270070270071%_
                                     _%$%hd268762268893%_
                                     _%$%hd268759268885%_)
                                    (_%__kont270074270075%_))))
                            (_%__kont270074270075%_))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl268754268871%_))
                            (let ((_%$%e268775268818%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl268754268871%_))))
                              (let ((_%$%tl268777268823%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e268775268818%_)))
                                    (_%$%hd268776268821%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e268775268818%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl268777268823%_))
                                    (_%__kont270072270073%_
                                     _%$%hd268776268821%_
                                     _%$%hd268753268869%_)
                                    (_%__kont270074270075%_))))
                            (_%__kont270074270075%_)))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%$%tl268754268871%_))
                    (let ((_%$%e268775268818%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl268754268871%_))))
                      (let ((_%$%tl268777268823%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e268775268818%_)))
                            (_%$%hd268776268821%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e268775268818%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl268777268823%_))
                            (_%__kont270072270073%_
                             _%$%hd268776268821%_
                             _%$%hd268753268869%_)
                            (_%__kont270074270075%_))))
                    (_%__kont270074270075%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl268754268871%_))
                                                        (let ((_%$%e268775268818%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl268754268871%_))))
                  (let ((_%$%tl268777268823%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e268775268818%_)))
                        (_%$%hd268776268821%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e268775268818%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl268777268823%_))
                        (_%__kont270072270073%_
                         _%$%hd268776268821%_
                         _%$%hd268753268869%_)
                        (_%__kont270074270075%_))))
                (_%__kont270074270075%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl268754268871%_))
                                                    (let ((_%$%e268775268818%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%tl268754268871%_))))
                                                      (let ((_%$%tl268777268823%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e268775268818%_)))
                    (_%$%hd268776268821%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e268775268818%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl268777268823%_))
                    (_%__kont270072270073%_
                     _%$%hd268776268821%_
                     _%$%hd268753268869%_)
                    (_%__kont270074270075%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont270074270075%_)))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl268754268871%_))
                                            (let ((_%$%e268775268818%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl268754268871%_))))
                                              (let ((_%$%tl268777268823%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e268775268818%_)))
                                                    (_%$%hd268776268821%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e268775268818%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl268777268823%_))
                                                    (_%__kont270072270073%_
                                                     _%$%hd268776268821%_
                                                     _%$%hd268753268869%_)
                                                    (_%__kont270074270075%_))))
                                            (_%__kont270074270075%_)))))
                                (_%__kont270074270075%_))))
                        (_%__kont270074270075%_))))
                (_%__kont270074270075%_))))))
    (define gxc#special-procedure-optimizers
      (let ((_%ht268734%_
             (let () (declare (not safe)) (make-hash-table-eq 'size: '1))))
        (let ()
          (declare (not safe))
          (__hash-put! _%ht268734%_ 'cast gxc#optimize-special-cast))
        _%ht268734%_))
    (define gxc#!procedure::optimize-call
      (lambda (_%self268696%_ _%ctx268697%_ _%stx268698%_ _%args268699%_)
        (let ((_%self268702%_ _%self268696%_))
          (if (let ((__method270745
                     (let ()
                       (declare (not safe))
                       (__method-ref _%self268702%_ 'check-arguments))))
                (if __method270745
                    (let ()
                      (declare (not safe))
                      (__method270745
                       _%self268702%_
                       _%ctx268697%_
                       _%stx268698%_
                       _%args268699%_))
                    (begin
                      (let ()
                        (declare (not safe))
                        (error '"Missing method"
                               _%self268702%_
                               'check-arguments))
                      '#!void)))
              (let* ((_%signature268712%_
                      (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self268702%_ '2 '#f '#f)))
                     (_%signature268714%_ _%signature268712%_)
                     (_%$e268724%_
                      (if _%signature268714%_
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%signature268714%_
                             '4
                             '#f
                             '#f))
                          '#f)))
                (if _%$e268724%_
                    (if (let ()
                          (declare (not safe))
                          (gxc#symbol-in-local-scope? _%$e268724%_))
                        (let ((__tmp270787
                               (cons '%#call
                                     (cons (cons '%#ref
                                                 (cons _%$e268724%_ '()))
                                           (map (lambda (_%$%g268728268730%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%ctx268697%_
                                                     _%$%g268728268730%_)))
                                                _%args268699%_)))))
                          (declare (not safe))
                          (gxc#xform-wrap-apply
                           __tmp270787
                           _%stx268698%_
                           _%ctx268697%_))
                        (let ()
                          (declare (not safe))
                          (gxc#xform-call% _%ctx268697%_ _%stx268698%_)))
                    (let ()
                      (declare (not safe))
                      (gxc#xform-call% _%ctx268697%_ _%stx268698%_))))
              (let ()
                (declare (not safe))
                (gxc#xform-call% _%ctx268697%_ _%stx268698%_))))))
    (define gxc#!procedure::optimize-call::specialize
      (lambda (__klass269817 __method-table269818)
        (let ((__check-arguments269819
               (let ((__tmp270788
                      (lambda ()
                        (let ((__method269820
                               (let ()
                                 (declare (not safe))
                                 (symbolic-table-ref
                                  __method-table269818
                                  'check-arguments
                                  '#f))))
                          (if __method269820
                              __method269820
                              (let ()
                                (declare (not safe))
                                (error '"Missing method"
                                       'check-arguments)))))))
                 (declare (not safe))
                 (__make-promise __tmp270788))))
          (lambda (_%self268696%_ _%ctx268697%_ _%stx268698%_ _%args268699%_)
            (let ((_%self268702%_ _%self268696%_))
              (if ((force __check-arguments269819)
                   _%self268702%_
                   _%ctx268697%_
                   _%stx268698%_
                   _%args268699%_)
                  (let* ((_%signature268712%_
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%self268702%_
                             '2
                             '#f
                             '#f)))
                         (_%signature268714%_ _%signature268712%_)
                         (_%$e268724%_
                          (if _%signature268714%_
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 _%signature268714%_
                                 '4
                                 '#f
                                 '#f))
                              '#f)))
                    (if _%$e268724%_
                        (if (let ()
                              (declare (not safe))
                              (gxc#symbol-in-local-scope? _%$e268724%_))
                            (let ((__tmp270789
                                   (cons '%#call
                                         (cons (cons '%#ref
                                                     (cons _%$e268724%_ '()))
                                               (map (lambda (_%$%g268728268730%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (gxc#compile-e__1
                                                         _%ctx268697%_
                                                         _%$%g268728268730%_)))
                                                    _%args268699%_)))))
                              (declare (not safe))
                              (gxc#xform-wrap-apply
                               __tmp270789
                               _%stx268698%_
                               _%ctx268697%_))
                            (let ()
                              (declare (not safe))
                              (gxc#xform-call% _%ctx268697%_ _%stx268698%_)))
                        (let ()
                          (declare (not safe))
                          (gxc#xform-call% _%ctx268697%_ _%stx268698%_))))
                  (let ()
                    (declare (not safe))
                    (gxc#xform-call% _%ctx268697%_ _%stx268698%_))))))))
    (let ()
      (declare (not safe))
      (bind-specializer!
       gxc#!procedure::optimize-call
       gxc#!procedure::optimize-call::specialize))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!procedure::t
       'optimize-call
       gxc#!procedure::optimize-call
       '#f))
    (define gxc#!procedure::check-arguments
      (lambda (_%self268449%_ _%ctx268450%_ _%stx268451%_ _%args268452%_)
        (let* ((_%self268455%_ _%self268449%_)
               (_%$%signature268464268466%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%self268455%_ '2 '#f '#f))))
          (if _%$%signature268464268466%_
              (let* ((_%signature268468%_ _%$%signature268464268466%_)
                     (_%$%argument-types268469268471%_
                      (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref
                         _%signature268468%_
                         '3
                         '#f
                         '#f))))
                (if _%$%argument-types268469268471%_
                    (let* ((_%argument-types268473%_
                            _%$%argument-types268469268471%_)
                           (_%argument-types268478%_
                            (let ((__tmp270790
                                   (lambda (_%t268476%_)
                                     (if _%t268476%_
                                         (let ()
                                           (declare (not safe))
                                           (gxc#optimizer-resolve-type-expression
                                            _%stx268451%_
                                            _%t268476%_))
                                         '#f))))
                              (declare (not safe))
                              (gxc#map-type-expressions
                               __tmp270790
                               _%argument-types268473%_))))
                      (let _%loop268480%_ ((_%rest-args268482%_ _%args268452%_)
                                           (_%rest-types268483%_
                                            _%argument-types268478%_)
                                           (_%result268484%_ '#t))
                        (let* ((_%$%rest-args268485268493%_
                                _%rest-args268482%_)
                               (_%$%else268487268501%_
                                (lambda () _%result268484%_))
                               (_%$%K268489268562%_
                                (lambda (_%rest-args268504%_ _%arg268505%_)
                                  (let* ((_%$%rest-types268506268517%_
                                          _%rest-types268483%_)
                                         (_%$%E268510268521%_
                                          (lambda ()
                                            (let ()
                                              (declare (not safe))
                                              (error '"No clause matching"
                                                     _%$%rest-types268506268517%_
                                                     '([type . rest-types])
                                                     '([])
                                                     '(tail-type)))
                                            '#!void)))
                                    (let ((_%$%K268513268550%_
                                           (lambda (_%rest-types268547%_
                                                    _%type268548%_)
                                             (_%loop268480%_
                                              _%rest-args268504%_
                                              _%rest-types268547%_
                                              (if (gxc#check-expression-type!
                                                   _%stx268451%_
                                                   _%arg268505%_
                                                   _%type268548%_)
                                                  _%result268484%_
                                                  '#f))))
                                          (_%$%K268512268541%_
                                           (lambda ()
                                             (let ()
                                               (declare (not safe))
                                               (gxc#raise-compile-error
                                                '"signature arity mismatch"
                                                _%stx268451%_
                                                _%argument-types268478%_))))
                                          (_%$%K268511268531%_
                                           (lambda (_%tail-type268525%_)
                                             (if (let ((__tmp270791
                                                        (lambda (_%$%g268526268528%_)
                                                          (gxc#check-expression-type!
                                                           _%stx268451%_
                                                           _%$%g268526268528%_
                                                           _%tail-type268525%_))))
                                                   (declare (not safe))
                                                   (andmap__0
                                                    __tmp270791
                                                    _%rest-args268504%_))
                                                 _%result268484%_
                                                 '#f))))
                                      (let ((_%$%try-match268508268544%_
                                             (lambda ()
                                               (if (null? _%$%rest-types268506268517%_)
                                                   (_%$%K268512268541%_)
                                                   (let ((_%tail-type268534%_
                                                          _%$%rest-types268506268517%_))
                                                     (_%$%K268511268531%_
                                                      _%tail-type268534%_))))))
                                        (if (pair? _%$%rest-types268506268517%_)
                                            (let ((_%$%tl268515268555%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%rest-types268506268517%_)))
                                                  (_%$%hd268514268553%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%rest-types268506268517%_))))
                                              (let ((_%type268558%_
                                                     _%$%hd268514268553%_)
                                                    (_%rest-types268560%_
                                                     _%$%tl268515268555%_))
                                                (_%$%K268513268550%_
                                                 _%rest-types268560%_
                                                 _%type268558%_)))
                                            (_%$%try-match268508268544%_))))))))
                          (if (pair? _%$%rest-args268485268493%_)
                              (let ((_%$%hd268490268565%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest-args268485268493%_)))
                                    (_%$%tl268491268567%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest-args268485268493%_))))
                                (let* ((_%arg268570%_ _%$%hd268490268565%_)
                                       (_%rest-args268572%_
                                        _%$%tl268491268567%_))
                                  (_%$%K268489268562%_
                                   _%rest-args268572%_
                                   _%arg268570%_)))
                              (_%$%else268487268501%_)))))
                    '#f))
              '#f))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!procedure::t
       'check-arguments
       gxc#!procedure::check-arguments
       '#f))
    (define gxc#!primitive-predicate::optimize-call
      (lambda (_%self268252%_ _%ctx268253%_ _%stx268254%_ _%args268255%_)
        (let* ((_%self268258%_ _%self268252%_)
               (_%$%g268268268278%_
                (lambda (_%$%g268269268275%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g268269268275%_))))
               (_%$%g268267268324%_
                (lambda (_%$%g268269268281%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g268269268281%_))
                      (let ((_%$%e268271268283%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g268269268281%_))))
                        (let ((_%$%hd268272268286%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e268271268283%_)))
                              (_%$%tl268273268288%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e268271268283%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl268273268288%_))
                              (let* ((_%klass268303%_
                                      (let ((__tmp270792
                                             (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%self268258%_
                                                '1
                                                '#f
                                                '#f))))
                                        (declare (not safe))
                                        (gxc#optimizer-resolve-class
                                         _%stx268254%_
                                         __tmp270792)))
                                     (_%object268305%_
                                      (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%ctx268253%_
                                         _%$%hd268272268286%_)))
                                     (_%instance?268310%_
                                      (let ((_%$e268307%_
                                             (gxc#expression-type?
                                              _%object268305%_
                                              _%klass268303%_)))
                                        (if _%$e268307%_
                                            _%$e268307%_
                                            (gxc#expression-type?
                                             _%$%hd268272268286%_
                                             _%klass268303%_))))
                                     (_%incompatible?268315%_
                                      (let ((_%$e268312%_
                                             (gxc#incompatible-type?
                                              _%object268305%_
                                              _%klass268303%_)))
                                        (if _%$e268312%_
                                            _%$e268312%_
                                            (gxc#incompatible-type?
                                             _%$%hd268272268286%_
                                             _%klass268303%_)))))
                                (if _%instance?268310%_
                                    (let ((__tmp270793
                                           (if (or (gxc#expression-no-side-effects?
                                                    _%object268305%_)
                                                   (gxc#expression-no-side-effects?
                                                    _%$%hd268272268286%_))
                                               (cons '%#quote (cons '#t '()))
                                               (cons '%#begin
                                                     (cons _%object268305%_
                                                           (cons '(%#quote #t)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (declare (not safe))
                                      (gxc#xform-wrap-source
                                       __tmp270793
                                       _%stx268254%_))
                                    (if _%incompatible?268315%_
                                        (let ((__tmp270794
                                               (cons '%#begin
                                                     (cons _%object268305%_
                                                           (cons '(%#quote #f)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (declare (not safe))
                                          (gxc#xform-wrap-source
                                           __tmp270794
                                           _%stx268254%_))
                                        (let ()
                                          (declare (not safe))
                                          (gxc#xform-call%
                                           _%ctx268253%_
                                           _%stx268254%_)))))
                              (_%$%g268268268278%_ _%$%g268269268281%_))))
                      (_%$%g268268268278%_ _%$%g268269268281%_)))))
          (_%$%g268267268324%_ _%args268255%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!primitive-predicate::t
       'optimize-call
       gxc#!primitive-predicate::optimize-call
       '#f))
    (define gxc#!predicate::optimize-call
      (lambda (_%self268041%_ _%ctx268042%_ _%stx268043%_ _%args268044%_)
        (let* ((_%self268047%_ _%self268041%_)
               (_%$%g268057268067%_
                (lambda (_%$%g268058268064%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g268058268064%_))))
               (_%$%g268056268127%_
                (lambda (_%$%g268058268070%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g268058268070%_))
                      (let ((_%$%e268060268072%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g268058268070%_))))
                        (let ((_%$%hd268061268075%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e268060268072%_)))
                              (_%$%tl268062268077%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e268060268072%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl268062268077%_))
                              (let* ((_%klass268092%_
                                      (let ((__tmp270795
                                             (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%self268047%_
                                                '1
                                                '#f
                                                '#f))))
                                        (declare (not safe))
                                        (gxc#optimizer-resolve-class
                                         _%stx268043%_
                                         __tmp270795)))
                                     (_%object268094%_
                                      (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%ctx268042%_
                                         _%$%hd268061268075%_)))
                                     (_%instance?268099%_
                                      (let ((_%$e268096%_
                                             (gxc#expression-type?
                                              _%object268094%_
                                              _%klass268092%_)))
                                        (if _%$e268096%_
                                            _%$e268096%_
                                            (gxc#expression-type?
                                             _%$%hd268061268075%_
                                             _%klass268092%_))))
                                     (_%incompatible?268104%_
                                      (let ((_%$e268101%_
                                             (gxc#incompatible-type?
                                              _%object268094%_
                                              _%klass268092%_)))
                                        (if _%$e268101%_
                                            _%$e268101%_
                                            (gxc#incompatible-type?
                                             _%$%hd268061268075%_
                                             _%klass268092%_))))
                                     (_%klass268107%_ _%klass268092%_))
                                (if _%instance?268099%_
                                    (let ((__tmp270796
                                           (if (or (gxc#expression-no-side-effects?
                                                    _%object268094%_)
                                                   (gxc#expression-no-side-effects?
                                                    _%$%hd268061268075%_))
                                               (cons '%#quote (cons '#t '()))
                                               (cons '%#begin
                                                     (cons _%object268094%_
                                                           (cons '(%#quote #t)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (declare (not safe))
                                      (gxc#xform-wrap-source
                                       __tmp270796
                                       _%stx268043%_))
                                    (if _%incompatible?268104%_
                                        (let ((__tmp270797
                                               (cons '%#begin
                                                     (cons _%object268094%_
                                                           (cons '(%#quote #f)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (declare (not safe))
                                          (gxc#xform-wrap-source
                                           __tmp270797
                                           _%stx268043%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               _%klass268107%_
                                               '8
                                               '#f
                                               '#f))
                                            (let ((__tmp270798
                                                   (cons '%#struct-direct-instance?
                                                         (cons (cons '%#quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (cons (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%klass268107%_
                                      '1
                                      '#f
                                      '#f))
                                   '()))
                       (cons _%object268094%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (gxc#xform-wrap-source
                                               __tmp270798
                                               _%stx268043%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   _%klass268107%_
                                                   '7
                                                   '#f
                                                   '#f))
                                                (let ((__tmp270799
                                                       (cons '%#struct-instance?
                                                             (cons (cons '%#quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%klass268107%_
                                          '1
                                          '#f
                                          '#f))
                                       '()))
                           (cons _%object268094%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gxc#xform-wrap-source
                                                   __tmp270799
                                                   _%stx268043%_))
                                                (let ((__tmp270800
                                                       (cons '%#call
                                                             (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons 'class-instance? '()))
                           (cons (cons '%#ref
                                       (cons (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%self268047%_
                                                '1
                                                '#f
                                                '#f))
                                             '()))
                                 (cons _%object268094%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gxc#xform-wrap-source
                                                   __tmp270800
                                                   _%stx268043%_)))))))
                              (_%$%g268057268067%_ _%$%g268058268070%_))))
                      (_%$%g268057268067%_ _%$%g268058268070%_)))))
          (_%$%g268056268127%_ _%args268044%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!predicate::t
       'optimize-call
       gxc#!predicate::optimize-call
       '#f))
    (define gxc#expression-no-side-effects?
      (lambda (_%stx267709%_)
        (let* ((_%__stx270155270156%_ _%stx267709%_)
               (_%$%g267714267755%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx270155270156%_)))))
          (let ((_%__kont270157270158%_ (lambda () '#t))
                (_%__kont270159270160%_ (lambda () '#t))
                (_%__kont270161270162%_
                 (lambda (_%$%g267728267821%_ _%$%g267729267822%_)
                   (let ((_%$%rator-type267843267845%_
                          (let ((__tmp270801
                                 (let ()
                                   (declare (not safe))
                                   (gxc#identifier-symbol
                                    _%$%g267729267822%_))))
                            (declare (not safe))
                            (gxc#optimizer-resolve-type __tmp270801))))
                     (if _%$%rator-type267843267845%_
                         (let* ((_%rator-type267847%_
                                 _%$%rator-type267843267845%_)
                                (_%$%rator-signature267848267850%_
                                 (if (let ()
                                       (declare (not safe))
                                       (##structure-instance-of?
                                        _%rator-type267847%_
                                        'gxc#!procedure::t))
                                     (let ()
                                       (declare (not safe))
                                       (##unchecked-structure-ref
                                        _%rator-type267847%_
                                        '2
                                        '#f
                                        '#f))
                                     '#f)))
                           (if _%$%rator-signature267848267850%_
                               (let* ((_%rator-signature267852%_
                                       _%$%rator-signature267848267850%_)
                                      (_%$%rator-effect267853267855%_
                                       (if _%rator-signature267852%_
                                           (##direct-structure-ref
                                            _%rator-signature267852%_
                                            '2
                                            gxc#!signature::t
                                            '#f)
                                           '#f)))
                                 (if _%$%rator-effect267853267855%_
                                     (let ((_%rator-effect267857%_
                                            _%$%rator-effect267853267855%_))
                                       (if (or (equal? '(pure)
                                                       _%rator-effect267857%_)
                                               (equal? '(alloc)
                                                       _%rator-effect267857%_))
                                           (let ((__tmp270802
                                                  (let ((__tmp270803
                                                         (lambda (_%$%g267862267865%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%$%g267863267867%_)
                   (cons _%$%g267862267865%_ _%$%g267863267867%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (foldr__0
                                                     __tmp270803
                                                     '()
                                                     _%$%g267728267821%_))))
                                             (declare (not safe))
                                             (andmap__0
                                              gxc#expression-no-side-effects?
                                              __tmp270802))
                                           '#f))
                                     '#f))
                               '#f))
                         '#f))))
                (_%__kont270165270166%_ (lambda () '#f)))
            (let ((_%__match270244270245%_
                   (lambda (_%$%e267730267767%_
                            _%$%hd267731267770%_
                            _%$%tl267732267772%_
                            _%$%e267733267775%_
                            _%$%hd267734267778%_
                            _%$%tl267735267780%_
                            _%$%e267736267783%_
                            _%$%hd267737267786%_
                            _%$%tl267738267788%_
                            _%$%e267739267791%_
                            _%$%hd267740267794%_
                            _%$%tl267741267796%_
                            _%__splice270163270164%_
                            _%$%target267742267799%_
                            _%$%tl267744267801%_)
                     (letrec ((_%$%loop267745267804%_
                               (lambda (_%$%hd267743267807%_
                                        _%$%rand267749267809%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%hd267743267807%_))
                                     (let ((_%$%e267746267811%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%$%hd267743267807%_))))
                                       (let ((_%$%lp-tl267748267816%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e267746267811%_)))
                                             (_%$%lp-hd267747267814%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e267746267811%_))))
                                         (_%$%loop267745267804%_
                                          _%$%lp-tl267748267816%_
                                          (cons _%$%lp-hd267747267814%_
                                                _%$%rand267749267809%_))))
                                     (let ((_%$%rand267750267819%_
                                            (reverse _%$%rand267749267809%_)))
                                       (_%__kont270161270162%_
                                        _%$%rand267750267819%_
                                        _%$%hd267740267794%_))))))
                       (_%$%loop267745267804%_
                        _%$%target267742267799%_
                        '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx270155270156%_))
                  (let ((_%$%e267716267898%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx270155270156%_))))
                    (let ((_%$%tl267718267903%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e267716267898%_)))
                          (_%$%hd267717267901%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e267716267898%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#identifier? _%$%hd267717267901%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-eq? '%#quote _%$%hd267717267901%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl267718267903%_))
                                  (let ((_%$%e267719267906%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl267718267903%_))))
                                    (let ((_%$%tl267721267911%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e267719267906%_)))
                                          (_%$%hd267720267909%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e267719267906%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl267721267911%_))
                                          (_%__kont270157270158%_)
                                          (_%__kont270165270166%_))))
                                  (_%__kont270165270166%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-eq? '%#ref _%$%hd267717267901%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl267718267903%_))
                                      (let ((_%$%e267725267883%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl267718267903%_))))
                                        (let ((_%$%tl267727267888%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e267725267883%_)))
                                              (_%$%hd267726267886%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e267725267883%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl267727267888%_))
                                              (_%__kont270159270160%_)
                                              (_%__kont270165270166%_))))
                                      (_%__kont270165270166%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-eq?
                                         '%#call
                                         _%$%hd267717267901%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl267718267903%_))
                                          (let ((_%$%e267733267775%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl267718267903%_))))
                                            (let ((_%$%tl267735267780%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e267733267775%_)))
                                                  (_%$%hd267734267778%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e267733267775%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd267734267778%_))
                                                  (let ((_%$%e267736267783%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd267734267778%_))))
                                                    (let ((_%$%tl267738267788%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e267736267783%_)))
                                                          (_%$%hd267737267786%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e267736267783%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#identifier?
                                                             _%$%hd267737267786%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-eq? '%#ref _%$%hd267737267786%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl267738267788%_))
                          (let ((_%$%e267739267791%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl267738267788%_))))
                            (let ((_%$%tl267741267796%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e267739267791%_)))
                                  (_%$%hd267740267794%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e267739267791%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl267741267796%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl267735267780%_))
                                      (let ((_%__splice270163270164%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice->vector
                                                _%$%tl267735267780%_
                                                '0))))
                                        (let ((_%$%tl267744267801%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice270163270164%_
                                                  '1)))
                                              (_%$%target267742267799%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice270163270164%_
                                                  '0))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl267744267801%_))
                                              (_%__match270244270245%_
                                               _%$%e267716267898%_
                                               _%$%hd267717267901%_
                                               _%$%tl267718267903%_
                                               _%$%e267733267775%_
                                               _%$%hd267734267778%_
                                               _%$%tl267735267780%_
                                               _%$%e267736267783%_
                                               _%$%hd267737267786%_
                                               _%$%tl267738267788%_
                                               _%$%e267739267791%_
                                               _%$%hd267740267794%_
                                               _%$%tl267741267796%_
                                               _%__splice270163270164%_
                                               _%$%target267742267799%_
                                               _%$%tl267744267801%_)
                                              (_%__kont270165270166%_))))
                                      (_%__kont270165270166%_))
                                  (_%__kont270165270166%_))))
                          (_%__kont270165270166%_))
                      (_%__kont270165270166%_))
                  (_%__kont270165270166%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont270165270166%_))))
                                          (_%__kont270165270166%_))
                                      (_%__kont270165270166%_))))
                          (_%__kont270165270166%_))))
                  (_%__kont270165270166%_)))))))
    (define gxc#expression-type?
      (lambda (_%stx267704%_ _%klass267705%_)
        (let ((_%expr-type267707%_
               (let ()
                 (declare (not safe))
                 (gxc#apply-basic-expression-type _%stx267704%_))))
          (if _%expr-type267707%_
              (let ()
                (declare (not safe))
                (gxc#!type-subtype? _%expr-type267707%_ _%klass267705%_))
              '#f))))
    (define gxc#incompatible-type?
      (lambda (_%expr267684%_ _%type267685%_)
        (if _%type267685%_
            (if (eq? (##structure-ref _%type267685%_ '1 gxc#!type::t '#f) 't)
                '#f
                (if (eq? (##structure-ref _%type267685%_ '1 gxc#!type::t '#f)
                         'false)
                    '#f
                    (let ((_%expr-type267691%_
                           (let ()
                             (declare (not safe))
                             (gxc#apply-basic-expression-type
                              _%expr267684%_))))
                      (if _%expr-type267691%_
                          (if (eq? 't
                                   (##structure-ref
                                    _%expr-type267691%_
                                    '1
                                    gxc#!type::t
                                    '#f))
                              '#f
                              (if (let ()
                                    (declare (not safe))
                                    (##structure-instance-of?
                                     _%expr-type267691%_
                                     'gxc#!abort::t))
                                  '#f
                                  (if (let ()
                                        (declare (not safe))
                                        (gxc#!type-subtype?
                                         _%expr-type267691%_
                                         _%type267685%_))
                                      '#f
                                      (if (or (let ()
                                                (declare (not safe))
                                                (##structure-instance-of?
                                                 _%expr-type267691%_
                                                 'gxc#!nullable-type::t))
                                              (let ()
                                                (declare (not safe))
                                                (##structure-instance-of?
                                                 _%type267685%_
                                                 'gxc#!nullable-type::t)))
                                          '#f
                                          (if (let ()
                                                (declare (not safe))
                                                (gxc#!interface-instance?
                                                 _%type267685%_))
                                              '#f
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gxc#!type-subtype?
                                                     _%type267685%_
                                                     _%expr-type267691%_))
                                                  '#f
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#!type-disjoint?
                                                     _%expr-type267691%_
                                                     _%type267685%_))))))))
                          '#f))))
            '#f)))
    (define gxc#check-expression-type!
      (lambda (_%stx267657%_ _%expr267658%_ _%type267659%_)
        (if _%type267659%_
            (let ((_%$e267662%_
                   (eq? (##structure-ref _%type267659%_ '1 gxc#!type::t '#f)
                        't)))
              (if _%$e267662%_
                  _%$e267662%_
                  (let ((_%expr-type267666%_
                         (let ()
                           (declare (not safe))
                           (gxc#apply-basic-expression-type _%expr267658%_))))
                    (if _%expr-type267666%_
                        (if (eq? 't
                                 (##structure-ref
                                  _%expr-type267666%_
                                  '1
                                  gxc#!type::t
                                  '#f))
                            '#f
                            (let ((_%$e267670%_
                                   (let ()
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      _%expr-type267666%_
                                      'gxc#!abort::t))))
                              (if _%$e267670%_
                                  _%$e267670%_
                                  (let ((_%$e267673%_
                                         (let ()
                                           (declare (not safe))
                                           (gxc#!type-subtype?
                                            _%expr-type267666%_
                                            _%type267659%_))))
                                    (if _%$e267673%_
                                        _%$e267673%_
                                        (if (or (let ()
                                                  (declare (not safe))
                                                  (##structure-instance-of?
                                                   _%expr-type267666%_
                                                   'gxc#!nullable-type::t))
                                                (let ()
                                                  (declare (not safe))
                                                  (##structure-instance-of?
                                                   _%type267659%_
                                                   'gxc#!nullable-type::t)))
                                            '#f
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gxc#!interface-instance?
                                                   _%type267659%_))
                                                '#f
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gxc#!type-subtype?
                                                       _%type267659%_
                                                       _%expr-type267666%_))
                                                    '#f
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gxc#!type-disjoint?
                                                           _%expr-type267666%_
                                                           _%type267659%_))
                                                        (let ()
                                                          (declare (not safe))
                                                          (gxc#raise-compile-error
                                                           '"signature type mismatch"
                                                           _%stx267657%_
                                                           _%expr267658%_
                                                           _%expr-type267666%_
                                                           _%type267659%_))
                                                        '#f)))))))))
                        '#f))))
            '#f)))
    (define gxc#!constructor::optimize-call
      (lambda (_%self267471%_ _%ctx267472%_ _%stx267473%_ _%args267474%_)
        (let* ((_%self267477%_ _%self267471%_)
               (_%klass267487%_
                (let ((__tmp270804
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%self267477%_
                          '1
                          '#f
                          '#f))))
                  (declare (not safe))
                  (gxc#optimizer-resolve-class _%stx267473%_ __tmp270804)))
               (_%fields267489%_
                (length (let ()
                          (declare (not safe))
                          (##unchecked-structure-ref
                           _%klass267487%_
                           '5
                           '#f
                           '#f))))
               (_%args267495%_
                (map (lambda (_%$%g267490267492%_)
                       (let ()
                         (declare (not safe))
                         (gxc#compile-e__1 _%ctx267472%_ _%$%g267490267492%_)))
                     _%args267474%_))
               (_%inline-make-object267497%_
                (cons '%#begin-annotation
                      (cons (cons '@type
                                  (cons (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           _%self267477%_
                                           '1
                                           '#f
                                           '#f))
                                        '()))
                            (cons (cons '%#call
                                        (cons (cons '%#ref
                                                    (cons '##structure '()))
                                              (cons (cons '%#ref
                                                          (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (##unchecked-structure-ref
                           _%self267477%_
                           '1
                           '#f
                           '#f))
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (make-list
                                                     _%fields267489%_
                                                     '(%#quote #f)))))
                                  '()))))
               (_%klass267500%_ _%klass267487%_)
               (_%$e267514%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass267500%_ '6 '#f '#f))))
          (if _%$e267514%_
              (let ((_%$obj267519%_
                     (let ((__tmp270805
                            (let () (declare (not safe)) (##gensym '__obj))))
                       (declare (not safe))
                       (make-symbol__0 __tmp270805)))
                    (_%ctor-impl267520%_
                     (let ()
                       (declare (not safe))
                       (gxc#!class-lookup-method
                        _%klass267500%_
                        _%$e267514%_))))
                (let ((__tmp270806
                       (cons '%#let-values
                             (cons (cons (cons (cons _%$obj267519%_ '())
                                               (cons _%inline-make-object267497%_
                                                     '()))
                                         '())
                                   (cons (cons '%#begin
                                               (cons (if _%ctor-impl267520%_
                                                         (let ((__tmp270807
                                                                (cons '%#call
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (cons '%#ref
                                          (cons _%ctor-impl267520%_ '()))
                                    (cons (cons '%#ref
                                                (cons _%$obj267519%_ '()))
                                          _%args267495%_)))))
                   (declare (not safe))
                   (gxc#xform-wrap-apply
                    __tmp270807
                    _%stx267473%_
                    _%ctx267472%_))
                 (let ((_%$ctor267522%_
                        (let ((__tmp270808
                               (let ()
                                 (declare (not safe))
                                 (##gensym '__constructor))))
                          (declare (not safe))
                          (make-symbol__0 __tmp270808))))
                   (cons '%#let-values
                         (cons (cons (cons (cons _%$ctor267522%_ '())
                                           (cons (cons '%#call
                                                       (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons 'direct-method-ref '()))
                     (cons (cons '%#ref
                                 (cons (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%self267477%_
                                          '1
                                          '#f
                                          '#f))
                                       '()))
                           (cons (cons '%#ref (cons _%$obj267519%_ '()))
                                 (cons (cons '%#quote (cons _%$e267514%_ '()))
                                       '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '()))
                                     '())
                               (cons (cons '%#if
                                           (cons (cons '%#ref
                                                       (cons _%$ctor267522%_
                                                             '()))
                                                 (cons (cons '%#call
                                                             (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons _%$ctor267522%_ '()))
                           (cons (cons '%#ref (cons _%$obj267519%_ '()))
                                 _%args267495%_)))
               (cons (cons '%#call
                           (cons (cons '%#ref (cons 'error '()))
                                 (cons (cons '%#quote
                                             (cons '"missing constructor method implementation"
                                                   '()))
                                       (cons (cons '%#quote (cons 'class: '()))
                                             (cons (cons '%#ref
                                                         (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##unchecked-structure-ref _%self267477%_ '1 '#f '#f))
                       '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (cons (cons '%#quote
                                                               (cons 'method:
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '()))
                 (cons (cons '%#quote (cons _%$e267514%_ '())) '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                     '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons _%$obj267519%_ '()))
                   '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         '())))))
                  (declare (not safe))
                  (gxc#xform-wrap-source __tmp270806 _%stx267473%_)))
              (let ((_%$e267524%_
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref
                        _%klass267500%_
                        '10
                        '#f
                        '#f))))
                (if _%$e267524%_
                    (let* ((_%$obj267529%_
                            (let ((__tmp270809
                                   (let ()
                                     (declare (not safe))
                                     (##gensym '__obj))))
                              (declare (not safe))
                              (make-symbol__0 __tmp270809)))
                           (_%metakons267531%_
                            (let ((__tmp270810
                                   (let ()
                                     (declare (not safe))
                                     (gxc#optimizer-resolve-class
                                      _%stx267473%_
                                      _%$e267524%_))))
                              (declare (not safe))
                              (gxc#!class-lookup-method
                               __tmp270810
                               'instance-init!)))
                           (__tmp270811
                            (cons '%#let-values
                                  (cons (cons (cons (cons _%$obj267529%_ '())
                                                    (cons _%inline-make-object267497%_
                                                          '()))
                                              '())
                                        (cons (cons '%#begin
                                                    (cons (if _%metakons267531%_
                                                              (let ((__tmp270812
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (cons '%#call
                                   (cons (cons '%#ref
                                               (cons _%metakons267531%_ '()))
                                         (cons (cons '%#ref
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (##unchecked-structure-ref
                                                              _%self267477%_
                                                              '1
                                                              '#f
                                                              '#f))
                                                           '()))
                                               (cons (cons '%#ref
                                                           (cons _%$obj267529%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%args267495%_))))))
                        (declare (not safe))
                        (gxc#xform-wrap-apply
                         __tmp270812
                         _%stx267473%_
                         _%ctx267472%_))
                      (cons '%#call
                            (cons (cons '%#ref (cons 'call-method '()))
                                  (cons (cons '%#ref
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (##unchecked-structure-ref
                                                       _%self267477%_
                                                       '1
                                                       '#f
                                                       '#f))
                                                    '()))
                                        (cons (cons '%#quote
                                                    (cons 'instance-init! '()))
                                              (cons (cons '%#ref
                                                          (cons _%$obj267529%_
                                                                '()))
                                                    _%args267495%_))))))
                  (cons (cons '%#ref (cons _%$obj267529%_ '())) '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '())))))
                      (declare (not safe))
                      (gxc#xform-wrap-source __tmp270811 _%stx267473%_))
                    (if (let ()
                          (declare (not safe))
                          (##unchecked-structure-ref
                           _%klass267500%_
                           '7
                           '#f
                           '#f))
                        (if (let ((__tmp270813
                                   (let ()
                                     (declare (not safe))
                                     (##length _%args267495%_))))
                              (declare (not safe))
                              (##fx= __tmp270813 _%fields267489%_))
                            (let ((__tmp270814
                                   (cons '%#begin-annotation
                                         (cons (cons '@type
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (##unchecked-structure-ref
                                                              _%self267477%_
                                                              '1
                                                              '#f
                                                              '#f))
                                                           '()))
                                               (cons (cons '%#call
                                                           (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (cons '##structure '()))
                         (cons (cons '%#ref
                                     (cons (let ()
                                             (declare (not safe))
                                             (##unchecked-structure-ref
                                              _%self267477%_
                                              '1
                                              '#f
                                              '#f))
                                           '()))
                               _%args267495%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '())))))
                              (declare (not safe))
                              (gxc#xform-wrap-source
                               __tmp270814
                               _%stx267473%_))
                            (let ((__tmp270816
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%self267477%_
                                      '1
                                      '#f
                                      '#f)))
                                  (__tmp270815
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%klass267500%_
                                      '5
                                      '#f
                                      '#f))))
                              (declare (not safe))
                              (gxc#raise-compile-error
                               '"illegal struct constructor application; arity mismatch"
                               _%stx267473%_
                               __tmp270816
                               __tmp270815)))
                        (let ((_%$obj267536%_
                               (let ((__tmp270817
                                      (let ()
                                        (declare (not safe))
                                        (##gensym '__obj))))
                                 (declare (not safe))
                                 (make-symbol__0 __tmp270817))))
                          (let _%lp267538%_ ((_%rest267540%_ _%args267495%_)
                                             (_%initializers267541%_ '()))
                            (let* ((_%__stx270247270248%_ _%rest267540%_)
                                   (_%$%g267545267566%_
                                    (lambda ()
                                      (let ()
                                        (declare (not safe))
                                        (gx#raise-syntax-error
                                         '#f
                                         '"Bad syntax; invalid match target"
                                         _%__stx270247270248%_)))))
                              (let ((_%__kont270249270250%_
                                     (lambda (_%$%g267547267620%_
                                              _%$%g267548267621%_
                                              _%$%g267549267622%_)
                                       (let* ((_%slot267649%_
                                               (let ((__tmp270818
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%g267549267622%_))))
                                                 (declare (not safe))
                                                 (keyword->symbol
                                                  __tmp270818)))
                                              (_%off267651%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gxc#!class-slot->field-offset
                                                  _%klass267500%_
                                                  _%slot267649%_))))
                                         (if _%off267651%_
                                             (_%lp267538%_
                                              _%$%g267547267620%_
                                              (cons (cons _%off267651%_
                                                          _%$%g267548267621%_)
                                                    _%initializers267541%_))
                                             (let ((__tmp270819
                                                    (let ()
                                                      (declare (not safe))
                                                      (##unchecked-structure-ref
                                                       _%self267477%_
                                                       '1
                                                       '#f
                                                       '#f))))
                                               (declare (not safe))
                                               (gxc#raise-compile-error
                                                '"unknown slot"
                                                _%stx267473%_
                                                __tmp270819
                                                _%slot267649%_))))))
                                    (_%__kont270251270252%_
                                     (lambda ()
                                       (let ((__tmp270820
                                              (cons '%#let-values
                                                    (cons (cons (cons (cons _%$obj267536%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    '())
                              (cons _%inline-make-object267497%_ '()))
                        '())
                  (cons (cons '%#begin
                              (let ((__tmp270822
                                     (let ((__tmp270823
                                            (lambda (_%i267580%_ _%r267581%_)
                                              (cons (cons '%#struct-unchecked-set!
                                                          (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%self267477%_
                                       '1
                                       '#f
                                       '#f))
                                    '()))
                        (cons (cons '%#quote (cons (car _%i267580%_) '()))
                              (cons (cons '%#ref (cons _%$obj267536%_ '()))
                                    (cons (cdr _%i267580%_) '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    _%r267581%_))))
                                       (declare (not safe))
                                       (foldl__0
                                        __tmp270823
                                        '()
                                        _%initializers267541%_)))
                                    (__tmp270821
                                     (cons (cons '%#ref
                                                 (cons _%$obj267536%_ '()))
                                           '())))
                                (declare (not safe))
                                (##append __tmp270822 __tmp270821)))
                        '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         (declare (not safe))
                                         (gxc#xform-wrap-source
                                          __tmp270820
                                          _%stx267473%_))))
                                    (_%__kont270253270254%_
                                     (lambda ()
                                       (let ((__tmp270824
                                              (cons '%#let-values
                                                    (cons (cons (cons (cons _%$obj267536%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    '())
                              (cons _%inline-make-object267497%_ '()))
                        '())
                  (cons (cons '%#begin
                              (cons (cons '%#call
                                          (cons (cons '%#ref
                                                      (cons 'class-instance-init!
                                                            '()))
                                                (cons (cons '%#ref
                                                            (cons _%$obj267536%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              _%args267495%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (cons (cons '%#ref
                                                (cons _%$obj267536%_ '()))
                                          '())))
                        '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         (declare (not safe))
                                         (gxc#xform-wrap-source
                                          __tmp270824
                                          _%stx267473%_)))))
                                (let* ((_%$%g267543267583%_
                                        (lambda ()
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%__stx270247270248%_))
                                              (_%__kont270251270252%_)
                                              (_%__kont270253270254%_))))
                                       (_%__match270284270285%_
                                        (lambda (_%$%e267550267588%_
                                                 _%$%hd267551267591%_
                                                 _%$%tl267552267593%_
                                                 _%$%e267553267596%_
                                                 _%$%hd267554267599%_
                                                 _%$%tl267555267601%_
                                                 _%$%e267556267604%_
                                                 _%$%hd267557267607%_
                                                 _%$%tl267558267609%_
                                                 _%$%e267559267612%_
                                                 _%$%hd267560267615%_
                                                 _%$%tl267561267617%_)
                                          (let ((_%$%g267547267620%_
                                                 _%$%tl267561267617%_)
                                                (_%$%g267548267621%_
                                                 _%$%hd267560267615%_)
                                                (_%$%g267549267622%_
                                                 _%$%hd267557267607%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-keyword?
                                                   _%$%g267549267622%_))
                                                (_%__kont270249270250%_
                                                 _%$%g267547267620%_
                                                 _%$%g267548267621%_
                                                 _%$%g267549267622%_)
                                                (_%__kont270253270254%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%__stx270247270248%_))
                                      (let ((_%$%e267550267588%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%__stx270247270248%_))))
                                        (let ((_%$%tl267552267593%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e267550267588%_)))
                                              (_%$%hd267551267591%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e267550267588%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%hd267551267591%_))
                                              (let ((_%$%e267553267596%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd267551267591%_))))
                                                (let ((_%$%tl267555267601%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e267553267596%_)))
                                                      (_%$%hd267554267599%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e267553267596%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#identifier?
                                                         _%$%hd267554267599%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-eq?
                                                             '%#quote
                                                             _%$%hd267554267599%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl267555267601%_))
                      (let ((_%$%e267556267604%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl267555267601%_))))
                        (let ((_%$%tl267558267609%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e267556267604%_)))
                              (_%$%hd267557267607%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e267556267604%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl267558267609%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl267552267593%_))
                                  (let ((_%$%e267559267612%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl267552267593%_))))
                                    (let ((_%$%tl267561267617%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e267559267612%_)))
                                          (_%$%hd267560267615%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e267559267612%_))))
                                      (_%__match270284270285%_
                                       _%$%e267550267588%_
                                       _%$%hd267551267591%_
                                       _%$%tl267552267593%_
                                       _%$%e267553267596%_
                                       _%$%hd267554267599%_
                                       _%$%tl267555267601%_
                                       _%$%e267556267604%_
                                       _%$%hd267557267607%_
                                       _%$%tl267558267609%_
                                       _%$%e267559267612%_
                                       _%$%hd267560267615%_
                                       _%$%tl267561267617%_)))
                                  (_%__kont270253270254%_))
                              (_%__kont270253270254%_))))
                      (_%__kont270253270254%_))
                  (_%__kont270253270254%_))
              (_%__kont270253270254%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont270253270254%_))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g267543267583%_)))))))))))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!constructor::t
       'optimize-call
       gxc#!constructor::optimize-call
       '#f))
    (define gxc#!accessor::check-arguments
      (lambda (_%self267333%_ _%ctx267334%_ _%stx267335%_ _%args267336%_)
        (let ((_%self267339%_ _%self267333%_))
          (if (let ()
                (declare (not safe))
                (##unchecked-structure-ref _%self267339%_ '4 '#f '#f))
              (gxc#!procedure::check-arguments
               _%self267339%_
               _%ctx267334%_
               _%stx267335%_
               _%args267336%_)
              '#t))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!accessor::t
       'check-arguments
       gxc#!accessor::check-arguments
       '#f))
    (define gxc#!accessor::optimize-call
      (lambda (_%self267116%_ _%ctx267117%_ _%stx267118%_ _%args267119%_)
        (let* ((_%self267122%_ _%self267116%_)
               (_%arguments-ok?267132%_
                (let ((__method270746
                       (let ()
                         (declare (not safe))
                         (__method-ref _%self267122%_ 'check-arguments))))
                  (if __method270746
                      (let ()
                        (declare (not safe))
                        (__method270746
                         _%self267122%_
                         _%ctx267117%_
                         _%stx267118%_
                         _%args267119%_))
                      (begin
                        (let ()
                          (declare (not safe))
                          (error '"Missing method"
                                 _%self267122%_
                                 'check-arguments))
                        '#!void))))
               (_%$%g267134267144%_
                (lambda (_%$%g267135267141%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g267135267141%_))))
               (_%$%g267133267208%_
                (lambda (_%$%g267135267147%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g267135267147%_))
                      (let ((_%$%e267137267149%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g267135267147%_))))
                        (let ((_%$%hd267138267152%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e267137267149%_)))
                              (_%$%tl267139267154%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e267137267149%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl267139267154%_))
                              (let* ((_%klass267170%_
                                      (let ((__tmp270825
                                             (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%self267122%_
                                                '1
                                                '#f
                                                '#f))))
                                        (declare (not safe))
                                        (gxc#optimizer-resolve-class
                                         _%stx267118%_
                                         __tmp270825)))
                                     (_%field267172%_
                                      (let ((__tmp270826
                                             (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%self267122%_
                                                '3
                                                '#f
                                                '#f))))
                                        (declare (not safe))
                                        (gxc#!class-slot->field-offset
                                         _%klass267170%_
                                         __tmp270826)))
                                     (_%object267174%_
                                      (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%ctx267117%_
                                         _%$%hd267138267152%_)))
                                     (_%klass267177%_ _%klass267170%_))
                                (if (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%klass267177%_
                                       '8
                                       '#f
                                       '#f))
                                    (let ((__tmp270827
                                           (cons (if (or _%arguments-ok?267132%_
                                                         (not (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##unchecked-structure-ref
                         _%self267122%_
                         '4
                         '#f
                         '#f))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '%#struct-unchecked-ref
                                                     '%#struct-direct-ref)
                                                 (cons (cons '%#ref
                                                             (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (declare (not safe))
                             (##unchecked-structure-ref
                              _%self267122%_
                              '1
                              '#f
                              '#f))
                           '()))
               (cons (cons '%#quote (cons _%field267172%_ '()))
                     (cons _%object267174%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (declare (not safe))
                                      (gxc#xform-wrap-source
                                       __tmp270827
                                       _%stx267118%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           _%klass267177%_
                                           '7
                                           '#f
                                           '#f))
                                        (let ((__tmp270828
                                               (cons (if (or _%arguments-ok?267132%_
                                                             (not (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%self267122%_
                             '4
                             '#f
                             '#f))))
                 '%#struct-unchecked-ref
                 '%#struct-ref)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%self267122%_
                                  '1
                                  '#f
                                  '#f))
                               '()))
                   (cons (cons '%#quote (cons _%field267172%_ '()))
                         (cons _%object267174%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (declare (not safe))
                                          (gxc#xform-wrap-source
                                           __tmp270828
                                           _%stx267118%_))
                                        (let ((_%$e267196%_
                                               (let ((__tmp270829
                                                      (let ()
                                                        (declare (not safe))
                                                        (##unchecked-structure-ref
                                                         _%self267122%_
                                                         '3
                                                         '#f
                                                         '#f))))
                                                 (declare (not safe))
                                                 (gxc#!class-slot-find-struct
                                                  _%klass267177%_
                                                  __tmp270829))))
                                          (if _%$e267196%_
                                              (let ((__tmp270830
                                                     (cons (if (or _%arguments-ok?267132%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (not (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%self267122%_
                                   '4
                                   '#f
                                   '#f))))
                       '%#struct-unchecked-ref
                       '%#struct-ref)
                   (cons (cons '%#ref
                               (cons (let ()
                                       (declare (not safe))
                                       (##unchecked-structure-ref
                                        _%self267122%_
                                        '1
                                        '#f
                                        '#f))
                                     '()))
                         (cons (cons '%#quote (cons _%field267172%_ '()))
                               (cons _%object267174%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (declare (not safe))
                                                (gxc#xform-wrap-source
                                                 __tmp270830
                                                 _%stx267118%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (##unchecked-structure-ref
                                                     _%self267122%_
                                                     '4
                                                     '#f
                                                     '#f))
                                                  (let ((__tmp270831
                                                         (let ((_%$obj267205%_
                                                                (let ((__tmp270832
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (let ()
                                 (declare (not safe))
                                 (##gensym '__obj))))
                          (declare (not safe))
                          (make-symbol__0 __tmp270832))))
                   (cons '%#let-values
                         (cons (cons (cons (cons _%$obj267205%_ '())
                                           (cons _%object267174%_ '()))
                                     '())
                               (cons (cons '%#if
                                           (cons (cons '%#struct-direct-instance?
                                                       (cons (cons '%#quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons (let ()
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    _%klass267177%_
                                    '1
                                    '#f
                                    '#f))
                                 '()))
                     (cons (cons '%#ref (cons _%$obj267205%_ '())) '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons '%#struct-unchecked-ref
                                                             (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (cons (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%self267122%_
                                          '1
                                          '#f
                                          '#f))
                                       '()))
                           (cons (cons '%#quote (cons _%field267172%_ '()))
                                 (cons (cons '%#ref (cons _%$obj267205%_ '()))
                                       '()))))
               (cons (if _%arguments-ok?267132%_
                         (cons '%#call
                               (cons (cons '%#ref
                                           (cons 'unchecked-slot-ref '()))
                                     (cons (cons '%#ref
                                                 (cons _%$obj267205%_ '()))
                                           (cons (cons '%#quote
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##unchecked-structure-ref _%self267122%_ '3 '#f '#f))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '()))))
                         (cons '%#call
                               (cons (cons '%#ref (cons 'class-slot-ref '()))
                                     (cons (cons '%#ref
                                                 (cons (let ()
                                                         (declare (not safe))
                                                         (##unchecked-structure-ref
                                                          _%self267122%_
                                                          '1
                                                          '#f
                                                          '#f))
                                                       '()))
                                           (cons (cons '%#ref
                                                       (cons _%$obj267205%_
                                                             '()))
                                                 (cons (cons '%#quote
                                                             (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (declare (not safe))
                             (##unchecked-structure-ref
                              _%self267122%_
                              '3
                              '#f
                              '#f))
                           '()))
               '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                     '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (gxc#xform-wrap-source
                                                     __tmp270831
                                                     _%stx267118%_))
                                                  (let ((__tmp270833
                                                         (cons '%#call
                                                               (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   (cons 'unchecked-slot-ref '()))
                             (cons _%object267174%_
                                   (cons (cons '%#quote
                                               (cons (let ()
                                                       (declare (not safe))
                                                       (##unchecked-structure-ref
                                                        _%self267122%_
                                                        '3
                                                        '#f
                                                        '#f))
                                                     '()))
                                         '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (gxc#xform-wrap-source
                                                     __tmp270833
                                                     _%stx267118%_))))))))
                              (_%$%g267134267144%_ _%$%g267135267147%_))))
                      (_%$%g267134267144%_ _%$%g267135267147%_)))))
          (_%$%g267133267208%_ _%args267119%_))))
    (define gxc#!accessor::optimize-call::specialize
      (lambda (__klass269821 __method-table269822)
        (let ((__check-arguments269823
               (let ((__tmp270834
                      (lambda ()
                        (let ((__method269824
                               (let ()
                                 (declare (not safe))
                                 (symbolic-table-ref
                                  __method-table269822
                                  'check-arguments
                                  '#f))))
                          (if __method269824
                              __method269824
                              (let ()
                                (declare (not safe))
                                (error '"Missing method"
                                       'check-arguments)))))))
                 (declare (not safe))
                 (__make-promise __tmp270834)))
              (__slot269825
               (let ((__slot269826
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass269821 'slot))))
                 (if __slot269826
                     __slot269826
                     (let ()
                       (declare (not safe))
                       (error '"Unknown slot" 'slot))))))
          (lambda (_%self267116%_ _%ctx267117%_ _%stx267118%_ _%args267119%_)
            (let* ((_%self267122%_ _%self267116%_)
                   (_%arguments-ok?267132%_
                    ((force __check-arguments269823)
                     _%self267122%_
                     _%ctx267117%_
                     _%stx267118%_
                     _%args267119%_))
                   (_%$%g267134267144%_
                    (lambda (_%$%g267135267141%_)
                      (let ()
                        (declare (not safe))
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; invalid match target"
                         _%$%g267135267141%_))))
                   (_%$%g267133267208%_
                    (lambda (_%$%g267135267147%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%g267135267147%_))
                          (let ((_%$%e267137267149%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%g267135267147%_))))
                            (let ((_%$%hd267138267152%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e267137267149%_)))
                                  (_%$%tl267139267154%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e267137267149%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl267139267154%_))
                                  (let* ((_%klass267170%_
                                          (let ((__tmp270835
                                                 (let ()
                                                   (declare (not safe))
                                                   (##unchecked-structure-ref
                                                    _%self267122%_
                                                    '1
                                                    '#f
                                                    '#f))))
                                            (declare (not safe))
                                            (gxc#optimizer-resolve-class
                                             _%stx267118%_
                                             __tmp270835)))
                                         (_%field267172%_
                                          (let ((__tmp270836
                                                 (let ()
                                                   (declare (not safe))
                                                   (##unchecked-structure-ref
                                                    _%self267122%_
                                                    '3
                                                    '#f
                                                    '#f))))
                                            (declare (not safe))
                                            (gxc#!class-slot->field-offset
                                             _%klass267170%_
                                             __tmp270836)))
                                         (_%object267174%_
                                          (let ()
                                            (declare (not safe))
                                            (gxc#compile-e__1
                                             _%ctx267117%_
                                             _%$%hd267138267152%_)))
                                         (_%klass267177%_ _%klass267170%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           _%klass267177%_
                                           '8
                                           '#f
                                           '#f))
                                        (let ((__tmp270837
                                               (cons (if (or _%arguments-ok?267132%_
                                                             (not (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%self267122%_
                             '4
                             '#f
                             '#f))))
                 '%#struct-unchecked-ref
                 '%#struct-direct-ref)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%self267122%_
                                  '1
                                  '#f
                                  '#f))
                               '()))
                   (cons (cons '%#quote (cons _%field267172%_ '()))
                         (cons _%object267174%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (declare (not safe))
                                          (gxc#xform-wrap-source
                                           __tmp270837
                                           _%stx267118%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               _%klass267177%_
                                               '7
                                               '#f
                                               '#f))
                                            (let ((__tmp270838
                                                   (cons (if (or _%arguments-ok?267132%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 _%self267122%_
                                 '4
                                 '#f
                                 '#f))))
                     '%#struct-unchecked-ref
                     '%#struct-ref)
                 (cons (cons '%#ref
                             (cons (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%self267122%_
                                      '1
                                      '#f
                                      '#f))
                                   '()))
                       (cons (cons '%#quote (cons _%field267172%_ '()))
                             (cons _%object267174%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (gxc#xform-wrap-source
                                               __tmp270838
                                               _%stx267118%_))
                                            (let ((_%$e267196%_
                                                   (let ((__tmp270839
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%self267122%_
                                                             '3
                                                             '#f
                                                             '#f))))
                                                     (declare (not safe))
                                                     (gxc#!class-slot-find-struct
                                                      _%klass267177%_
                                                      __tmp270839))))
                                              (if _%$e267196%_
                                                  (let ((__tmp270840
                                                         (cons (if (or _%arguments-ok?267132%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (not (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%self267122%_
                                       '4
                                       '#f
                                       '#f))))
                           '%#struct-unchecked-ref
                           '%#struct-ref)
                       (cons (cons '%#ref
                                   (cons (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%self267122%_
                                            '1
                                            '#f
                                            '#f))
                                         '()))
                             (cons (cons '%#quote (cons _%field267172%_ '()))
                                   (cons _%object267174%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (gxc#xform-wrap-source
                                                     __tmp270840
                                                     _%stx267118%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (##unchecked-structure-ref
                                                         _%self267122%_
                                                         '4
                                                         '#f
                                                         '#f))
                                                      (let ((__tmp270841
                                                             (let ((_%$obj267205%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (let ((__tmp270842
                                   (let ()
                                     (declare (not safe))
                                     (##gensym '__obj))))
                              (declare (not safe))
                              (make-symbol__0 __tmp270842))))
                       (cons '%#let-values
                             (cons (cons (cons (cons _%$obj267205%_ '())
                                               (cons _%object267174%_ '()))
                                         '())
                                   (cons (cons '%#if
                                               (cons (cons '%#struct-direct-instance?
                                                           (cons (cons '%#quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (cons (let ()
                                       (declare (not safe))
                                       (##unchecked-structure-ref
                                        _%klass267177%_
                                        '1
                                        '#f
                                        '#f))
                                     '()))
                         (cons (cons '%#ref (cons _%$obj267205%_ '())) '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#struct-unchecked-ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (cons '%#ref
                                     (cons (let ()
                                             (declare (not safe))
                                             (##unchecked-structure-ref
                                              _%self267122%_
                                              '1
                                              '#f
                                              '#f))
                                           '()))
                               (cons (cons '%#quote (cons _%field267172%_ '()))
                                     (cons (cons '%#ref
                                                 (cons _%$obj267205%_ '()))
                                           '()))))
                   (cons (if _%arguments-ok?267132%_
                             (cons '%#call
                                   (cons (cons '%#ref
                                               (cons 'unchecked-slot-ref '()))
                                         (cons (cons '%#ref
                                                     (cons _%$obj267205%_ '()))
                                               (cons (cons '%#quote
                                                           (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (declare (not safe))
                           (##unchecked-structure-ref
                            _%self267122%_
                            __slot269825
                            '#f
                            '#f))
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '()))))
                             (cons '%#call
                                   (cons (cons '%#ref
                                               (cons 'class-slot-ref '()))
                                         (cons (cons '%#ref
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (##unchecked-structure-ref
                                                              _%self267122%_
                                                              '1
                                                              '#f
                                                              '#f))
                                                           '()))
                                               (cons (cons '%#ref
                                                           (cons _%$obj267205%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%self267122%_
                                  '3
                                  '#f
                                  '#f))
                               '()))
                   '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                         '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         '()))))))
                (declare (not safe))
                (gxc#xform-wrap-source __tmp270841 _%stx267118%_))
              (let ((__tmp270843
                     (cons '%#call
                           (cons (cons '%#ref (cons 'unchecked-slot-ref '()))
                                 (cons _%object267174%_
                                       (cons (cons '%#quote
                                                   (cons (let ()
                                                           (declare (not safe))
                                                           (##unchecked-structure-ref
                                                            _%self267122%_
                                                            '3
                                                            '#f
                                                            '#f))
                                                         '()))
                                             '()))))))
                (declare (not safe))
                (gxc#xform-wrap-source __tmp270843 _%stx267118%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  (_%$%g267134267144%_ _%$%g267135267147%_))))
                          (_%$%g267134267144%_ _%$%g267135267147%_)))))
              (_%$%g267133267208%_ _%args267119%_))))))
    (let ()
      (declare (not safe))
      (bind-specializer!
       gxc#!accessor::optimize-call
       gxc#!accessor::optimize-call::specialize))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!accessor::t
       'optimize-call
       gxc#!accessor::optimize-call
       '#f))
    (define gxc#!mutator::optimize-call
      (lambda (_%self266880%_ _%ctx266881%_ _%stx266882%_ _%args266883%_)
        (let* ((_%self266886%_ _%self266880%_)
               (_%arguments-ok?266896%_
                (let ((__method270747
                       (let ()
                         (declare (not safe))
                         (__method-ref _%self266886%_ 'check-arguments))))
                  (if __method270747
                      (let ()
                        (declare (not safe))
                        (__method270747
                         _%self266886%_
                         _%ctx266881%_
                         _%stx266882%_
                         _%args266883%_))
                      (begin
                        (let ()
                          (declare (not safe))
                          (error '"Missing method"
                                 _%self266886%_
                                 'check-arguments))
                        '#!void))))
               (_%$%g266898266912%_
                (lambda (_%$%g266899266909%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g266899266909%_))))
               (_%$%g266897266991%_
                (lambda (_%$%g266899266915%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g266899266915%_))
                      (let ((_%$%e266902266917%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g266899266915%_))))
                        (let ((_%$%hd266903266920%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e266902266917%_)))
                              (_%$%tl266904266922%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e266902266917%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl266904266922%_))
                              (let ((_%$%e266905266925%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl266904266922%_))))
                                (let ((_%$%hd266906266928%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e266905266925%_)))
                                      (_%$%tl266907266930%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e266905266925%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl266907266930%_))
                                      (let* ((_%klass266950%_
                                              (let ((__tmp270844
                                                     (let ()
                                                       (declare (not safe))
                                                       (##unchecked-structure-ref
                                                        _%self266886%_
                                                        '1
                                                        '#f
                                                        '#f))))
                                                (declare (not safe))
                                                (gxc#optimizer-resolve-class
                                                 _%stx266882%_
                                                 __tmp270844)))
                                             (_%field266952%_
                                              (let ((__tmp270845
                                                     (let ()
                                                       (declare (not safe))
                                                       (##unchecked-structure-ref
                                                        _%self266886%_
                                                        '3
                                                        '#f
                                                        '#f))))
                                                (declare (not safe))
                                                (gxc#!class-slot->field-offset
                                                 _%klass266950%_
                                                 __tmp270845)))
                                             (_%object266954%_
                                              (let ()
                                                (declare (not safe))
                                                (gxc#compile-e__1
                                                 _%ctx266881%_
                                                 _%$%hd266903266920%_)))
                                             (_%value266956%_
                                              (let ()
                                                (declare (not safe))
                                                (gxc#compile-e__1
                                                 _%ctx266881%_
                                                 _%$%hd266906266928%_)))
                                             (_%klass266959%_ _%klass266950%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               _%klass266959%_
                                               '8
                                               '#f
                                               '#f))
                                            (let ((__tmp270846
                                                   (cons (if (or _%arguments-ok?266896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 _%self266886%_
                                 '4
                                 '#f
                                 '#f))))
                     '%#struct-unchecked-set!
                     '%#struct-direct-set!)
                 (cons (cons '%#ref
                             (cons (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%self266886%_
                                      '1
                                      '#f
                                      '#f))
                                   '()))
                       (cons (cons '%#quote (cons _%field266952%_ '()))
                             (cons _%object266954%_
                                   (cons _%value266956%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (gxc#xform-wrap-source
                                               __tmp270846
                                               _%stx266882%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   _%klass266959%_
                                                   '7
                                                   '#f
                                                   '#f))
                                                (let ((__tmp270847
                                                       (cons (if (or _%arguments-ok?266896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (not (let ()
                                    (declare (not safe))
                                    (##unchecked-structure-ref
                                     _%self266886%_
                                     '4
                                     '#f
                                     '#f))))
                         '%#struct-unchecked-set!
                         '%#struct-set!)
                     (cons (cons '%#ref
                                 (cons (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%self266886%_
                                          '1
                                          '#f
                                          '#f))
                                       '()))
                           (cons (cons '%#quote (cons _%field266952%_ '()))
                                 (cons _%object266954%_
                                       (cons _%value266956%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gxc#xform-wrap-source
                                                   __tmp270847
                                                   _%stx266882%_))
                                                (let ((_%$e266979%_
                                                       (let ((__tmp270848
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##unchecked-structure-ref
                         _%self266886%_
                         '3
                         '#f
                         '#f))))
                 (declare (not safe))
                 (gxc#!class-slot-find-struct _%klass266959%_ __tmp270848))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if _%$e266979%_
                                                      (let ((__tmp270849
                                                             (cons (if (or _%arguments-ok?266896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   (not (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           _%self266886%_
                                           '3
                                           '#f
                                           '#f))))
                               '%#struct-unchecked-set!
                               '%#struct-set!)
                           (cons (cons '%#ref
                                       (cons (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%self266886%_
                                                '1
                                                '#f
                                                '#f))
                                             '()))
                                 (cons (cons '%#quote
                                             (cons _%field266952%_ '()))
                                       (cons _%object266954%_
                                             (cons _%value266956%_ '())))))))
                (declare (not safe))
                (gxc#xform-wrap-source __tmp270849 _%stx266882%_))
              (if (let ()
                    (declare (not safe))
                    (##unchecked-structure-ref _%self266886%_ '4 '#f '#f))
                  (let ((__tmp270850
                         (let ((_%$obj266988%_
                                (let ((__tmp270851
                                       (let ()
                                         (declare (not safe))
                                         (##gensym '__obj))))
                                  (declare (not safe))
                                  (make-symbol__0 __tmp270851))))
                           (cons '%#let-values
                                 (cons (cons (cons (cons _%$obj266988%_ '())
                                                   (cons _%object266954%_ '()))
                                             '())
                                       (cons (cons '%#if
                                                   (cons (cons '%#struct-direct-instance?
                                                               (cons (cons '%#quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   (cons (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%klass266959%_
                                            '1
                                            '#f
                                            '#f))
                                         '()))
                             (cons (cons '%#ref (cons _%$obj266988%_ '()))
                                   '())))
                 (cons (cons '%#struct-unchecked-set!
                             (cons (cons '%#ref
                                         (cons (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%self266886%_
                                                  '1
                                                  '#f
                                                  '#f))
                                               '()))
                                   (cons (cons '%#quote
                                               (cons _%field266952%_ '()))
                                         (cons (cons '%#ref
                                                     (cons _%$obj266988%_ '()))
                                               (cons _%value266956%_ '())))))
                       (cons (if _%arguments-ok?266896%_
                                 (cons '%#call
                                       (cons (cons '%#ref
                                                   (cons 'unchecked-slot-set!
                                                         '()))
                                             (cons (cons '%#ref
                                                         (cons _%$obj266988%_
                                                               '()))
                                                   (cons (cons '%#quote
                                                               (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%self266886%_
                                '3
                                '#f
                                '#f))
                             '()))
                 (cons _%value266956%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                 (cons '%#call
                                       (cons (cons '%#ref
                                                   (cons 'class-slot-set! '()))
                                             (cons (cons '%#ref
                                                         (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##unchecked-structure-ref _%self266886%_ '1 '#f '#f))
                       '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (cons (cons '%#ref
                                                               (cons _%$obj266988%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '()))
                 (cons (cons '%#quote
                             (cons (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%self266886%_
                                      '3
                                      '#f
                                      '#f))
                                   '()))
                       (cons _%value266956%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                             '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             '()))))))
                    (declare (not safe))
                    (gxc#xform-wrap-source __tmp270850 _%stx266882%_))
                  (let ((__tmp270852
                         (cons '%#call
                               (cons (cons '%#ref
                                           (cons 'unchecked-slot-set! '()))
                                     (cons _%object266954%_
                                           (cons (cons '%#quote
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##unchecked-structure-ref _%self266886%_ '3 '#f '#f))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons _%value266956%_
                                                       '())))))))
                    (declare (not safe))
                    (gxc#xform-wrap-source __tmp270852 _%stx266882%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (_%$%g266898266912%_
                                       _%$%g266899266915%_))))
                              (_%$%g266898266912%_ _%$%g266899266915%_))))
                      (_%$%g266898266912%_ _%$%g266899266915%_)))))
          (_%$%g266897266991%_ _%args266883%_))))
    (define gxc#!mutator::optimize-call::specialize
      (lambda (__klass269827 __method-table269828)
        (let ((__check-arguments269829
               (let ((__tmp270853
                      (lambda ()
                        (let ((__method269830
                               (let ()
                                 (declare (not safe))
                                 (symbolic-table-ref
                                  __method-table269828
                                  'check-arguments
                                  '#f))))
                          (if __method269830
                              __method269830
                              (let ()
                                (declare (not safe))
                                (error '"Missing method"
                                       'check-arguments)))))))
                 (declare (not safe))
                 (__make-promise __tmp270853))))
          (lambda (_%self266880%_ _%ctx266881%_ _%stx266882%_ _%args266883%_)
            (let* ((_%self266886%_ _%self266880%_)
                   (_%arguments-ok?266896%_
                    ((force __check-arguments269829)
                     _%self266886%_
                     _%ctx266881%_
                     _%stx266882%_
                     _%args266883%_))
                   (_%$%g266898266912%_
                    (lambda (_%$%g266899266909%_)
                      (let ()
                        (declare (not safe))
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; invalid match target"
                         _%$%g266899266909%_))))
                   (_%$%g266897266991%_
                    (lambda (_%$%g266899266915%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%g266899266915%_))
                          (let ((_%$%e266902266917%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%g266899266915%_))))
                            (let ((_%$%hd266903266920%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e266902266917%_)))
                                  (_%$%tl266904266922%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e266902266917%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl266904266922%_))
                                  (let ((_%$%e266905266925%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl266904266922%_))))
                                    (let ((_%$%hd266906266928%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e266905266925%_)))
                                          (_%$%tl266907266930%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e266905266925%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl266907266930%_))
                                          (let* ((_%klass266950%_
                                                  (let ((__tmp270854
                                                         (let ()
                                                           (declare (not safe))
                                                           (##unchecked-structure-ref
                                                            _%self266886%_
                                                            '1
                                                            '#f
                                                            '#f))))
                                                    (declare (not safe))
                                                    (gxc#optimizer-resolve-class
                                                     _%stx266882%_
                                                     __tmp270854)))
                                                 (_%field266952%_
                                                  (let ((__tmp270855
                                                         (let ()
                                                           (declare (not safe))
                                                           (##unchecked-structure-ref
                                                            _%self266886%_
                                                            '3
                                                            '#f
                                                            '#f))))
                                                    (declare (not safe))
                                                    (gxc#!class-slot->field-offset
                                                     _%klass266950%_
                                                     __tmp270855)))
                                                 (_%object266954%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%ctx266881%_
                                                     _%$%hd266903266920%_)))
                                                 (_%value266956%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%ctx266881%_
                                                     _%$%hd266906266928%_)))
                                                 (_%klass266959%_
                                                  _%klass266950%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   _%klass266959%_
                                                   '8
                                                   '#f
                                                   '#f))
                                                (let ((__tmp270856
                                                       (cons (if (or _%arguments-ok?266896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (not (let ()
                                    (declare (not safe))
                                    (##unchecked-structure-ref
                                     _%self266886%_
                                     '4
                                     '#f
                                     '#f))))
                         '%#struct-unchecked-set!
                         '%#struct-direct-set!)
                     (cons (cons '%#ref
                                 (cons (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%self266886%_
                                          '1
                                          '#f
                                          '#f))
                                       '()))
                           (cons (cons '%#quote (cons _%field266952%_ '()))
                                 (cons _%object266954%_
                                       (cons _%value266956%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gxc#xform-wrap-source
                                                   __tmp270856
                                                   _%stx266882%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##unchecked-structure-ref
                                                       _%klass266959%_
                                                       '7
                                                       '#f
                                                       '#f))
                                                    (let ((__tmp270857
                                                           (cons (if (or _%arguments-ok?266896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (not (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-ref
                                         _%self266886%_
                                         '4
                                         '#f
                                         '#f))))
                             '%#struct-unchecked-set!
                             '%#struct-set!)
                         (cons (cons '%#ref
                                     (cons (let ()
                                             (declare (not safe))
                                             (##unchecked-structure-ref
                                              _%self266886%_
                                              '1
                                              '#f
                                              '#f))
                                           '()))
                               (cons (cons '%#quote (cons _%field266952%_ '()))
                                     (cons _%object266954%_
                                           (cons _%value266956%_ '())))))))
              (declare (not safe))
              (gxc#xform-wrap-source __tmp270857 _%stx266882%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ((_%$e266979%_
                                                           (let ((__tmp270858
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%self266886%_
                             '3
                             '#f
                             '#f))))
                     (declare (not safe))
                     (gxc#!class-slot-find-struct
                      _%klass266959%_
                      __tmp270858))))
              (if _%$e266979%_
                  (let ((__tmp270859
                         (cons (if (or _%arguments-ok?266896%_
                                       (not (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               _%self266886%_
                                               '3
                                               '#f
                                               '#f))))
                                   '%#struct-unchecked-set!
                                   '%#struct-set!)
                               (cons (cons '%#ref
                                           (cons (let ()
                                                   (declare (not safe))
                                                   (##unchecked-structure-ref
                                                    _%self266886%_
                                                    '1
                                                    '#f
                                                    '#f))
                                                 '()))
                                     (cons (cons '%#quote
                                                 (cons _%field266952%_ '()))
                                           (cons _%object266954%_
                                                 (cons _%value266956%_
                                                       '())))))))
                    (declare (not safe))
                    (gxc#xform-wrap-source __tmp270859 _%stx266882%_))
                  (if (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self266886%_ '4 '#f '#f))
                      (let ((__tmp270860
                             (let ((_%$obj266988%_
                                    (let ((__tmp270861
                                           (let ()
                                             (declare (not safe))
                                             (##gensym '__obj))))
                                      (declare (not safe))
                                      (make-symbol__0 __tmp270861))))
                               (cons '%#let-values
                                     (cons (cons (cons (cons _%$obj266988%_
                                                             '())
                                                       (cons _%object266954%_
                                                             '()))
                                                 '())
                                           (cons (cons '%#if
                                                       (cons (cons '%#struct-direct-instance?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons (cons '%#quote
                                       (cons (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%klass266959%_
                                                '1
                                                '#f
                                                '#f))
                                             '()))
                                 (cons (cons '%#ref (cons _%$obj266988%_ '()))
                                       '())))
                     (cons (cons '%#struct-unchecked-set!
                                 (cons (cons '%#ref
                                             (cons (let ()
                                                     (declare (not safe))
                                                     (##unchecked-structure-ref
                                                      _%self266886%_
                                                      '1
                                                      '#f
                                                      '#f))
                                                   '()))
                                       (cons (cons '%#quote
                                                   (cons _%field266952%_ '()))
                                             (cons (cons '%#ref
                                                         (cons _%$obj266988%_
                                                               '()))
                                                   (cons _%value266956%_
                                                         '())))))
                           (cons (if _%arguments-ok?266896%_
                                     (cons '%#call
                                           (cons (cons '%#ref
                                                       (cons 'unchecked-slot-set!
                                                             '()))
                                                 (cons (cons '%#ref
                                                             (cons _%$obj266988%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '()))
               (cons (cons '%#quote
                           (cons (let ()
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    _%self266886%_
                                    '3
                                    '#f
                                    '#f))
                                 '()))
                     (cons _%value266956%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (cons '%#call
                                           (cons (cons '%#ref
                                                       (cons 'class-slot-set!
                                                             '()))
                                                 (cons (cons '%#ref
                                                             (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (declare (not safe))
                             (##unchecked-structure-ref
                              _%self266886%_
                              '1
                              '#f
                              '#f))
                           '()))
               (cons (cons '%#ref (cons _%$obj266988%_ '()))
                     (cons (cons '%#quote
                                 (cons (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%self266886%_
                                          '3
                                          '#f
                                          '#f))
                                       '()))
                           (cons _%value266956%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                 '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '()))))))
                        (declare (not safe))
                        (gxc#xform-wrap-source __tmp270860 _%stx266882%_))
                      (let ((__tmp270862
                             (cons '%#call
                                   (cons (cons '%#ref
                                               (cons 'unchecked-slot-set! '()))
                                         (cons _%object266954%_
                                               (cons (cons '%#quote
                                                           (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (declare (not safe))
                           (##unchecked-structure-ref
                            _%self266886%_
                            '3
                            '#f
                            '#f))
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons _%value266956%_
                                                           '())))))))
                        (declare (not safe))
                        (gxc#xform-wrap-source
                         __tmp270862
                         _%stx266882%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%g266898266912%_
                                           _%$%g266899266915%_))))
                                  (_%$%g266898266912%_ _%$%g266899266915%_))))
                          (_%$%g266898266912%_ _%$%g266899266915%_)))))
              (_%$%g266897266991%_ _%args266883%_))))))
    (let ()
      (declare (not safe))
      (bind-specializer!
       gxc#!mutator::optimize-call
       gxc#!mutator::optimize-call::specialize))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!mutator::t
       'optimize-call
       gxc#!mutator::optimize-call
       '#f))
    (define gxc#!lambda::optimize-call
      (lambda (_%self266696%_ _%ctx266697%_ _%stx266698%_ _%args266699%_)
        (let* ((_%self266702%_ _%self266696%_)
               (_%$%self266711266721%_ _%self266702%_)
               (_%$%E266713266724%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (error '"No clause matching"
                           _%$%self266711266721%_
                           '((!lambda _ _ arity dispatch inline))))
                  '#!void))
               (_%$%K266714266734%_
                (lambda (_%inline266727%_ _%dispatch266728%_ _%arity266729%_)
                  (if (let ()
                        (declare (not safe))
                        (gxc#!lambda-arity-match?
                         _%self266702%_
                         _%args266699%_))
                      '#!void
                      (let ()
                        (declare (not safe))
                        (gxc#raise-compile-error
                         '"Illegal lambda application; arity mismatch"
                         _%stx266698%_
                         _%arity266729%_)))
                  (if _%inline266727%_
                      (let ()
                        (let ()
                          (declare (not safe))
                          (gxc#verbose '"inline lambda"))
                        (let ((__tmp270863 (_%inline266727%_ _%stx266698%_)))
                          (declare (not safe))
                          (gxc#xform-wrap-apply
                           __tmp270863
                           _%stx266698%_
                           _%ctx266697%_)))
                      (if (and _%dispatch266728%_
                               (let ()
                                 (declare (not safe))
                                 (gxc#symbol-in-local-scope?
                                  _%dispatch266728%_)))
                          (let ()
                            (let ()
                              (declare (not safe))
                              (gxc#verbose
                               '"dispatch lambda => "
                               _%dispatch266728%_))
                            (let ((__tmp270864
                                   (cons '%#call
                                         (cons (cons '%#ref
                                                     (cons _%dispatch266728%_
                                                           '()))
                                               _%args266699%_))))
                              (declare (not safe))
                              (gxc#xform-wrap-apply
                               __tmp270864
                               _%stx266698%_
                               _%ctx266697%_)))
                          (gxc#!procedure::optimize-call
                           _%self266702%_
                           _%ctx266697%_
                           _%stx266698%_
                           _%args266699%_)))))
               (_%$%e266715266737%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266711266721%_
                   '1
                   '#f
                   '#f)))
               (_%$%e266716266740%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266711266721%_
                   '2
                   '#f
                   '#f)))
               (_%$%e266717266743%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266711266721%_
                   '3
                   '#f
                   '#f)))
               (_%arity266746%_ _%$%e266717266743%_)
               (_%$%e266718266748%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266711266721%_
                   '4
                   '#f
                   '#f)))
               (_%dispatch266751%_ _%$%e266718266748%_)
               (_%$%e266719266753%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266711266721%_
                   '5
                   '#f
                   '#f)))
               (_%inline266756%_ _%$%e266719266753%_))
          (_%$%K266714266734%_
           _%inline266756%_
           _%dispatch266751%_
           _%arity266746%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!lambda::t
       'optimize-call
       gxc#!lambda::optimize-call
       '#f))
    (define gxc#!case-lambda::optimize-call
      (lambda (_%self266548%_ _%ctx266549%_ _%stx266550%_ _%args266551%_)
        (let* ((_%self266554%_ _%self266548%_)
               (_%$e266568%_
                (let ((__tmp270866
                       (lambda (_%$%g266563266565%_)
                         (let ()
                           (declare (not safe))
                           (gxc#!lambda-arity-match?
                            _%$%g266563266565%_
                            _%args266551%_))))
                      (__tmp270865
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%self266554%_
                          '3
                          '#f
                          '#f))))
                  (declare (not safe))
                  (__find __tmp270866 __tmp270865))))
          (if _%$e266568%_
              (let ((__method270748
                     (let ()
                       (declare (not safe))
                       (__method-ref _%$e266568%_ 'optimize-call))))
                (if __method270748
                    (let ()
                      (declare (not safe))
                      (__method270748
                       _%$e266568%_
                       _%ctx266549%_
                       _%stx266550%_
                       _%args266551%_))
                    (begin
                      (let ()
                        (declare (not safe))
                        (error '"Missing method" _%$e266568%_ 'optimize-call))
                      '#!void)))
              (let ((__tmp270867
                     (map gxc#!lambda-arity
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%self266554%_
                             '3
                             '#f
                             '#f)))))
                (declare (not safe))
                (gxc#raise-compile-error
                 '"Illegal case-lambda application; arity mismatch"
                 _%stx266550%_
                 __tmp270867))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!case-lambda::t
       'optimize-call
       gxc#!case-lambda::optimize-call
       '#f))
    (define gxc#!kw-lambda::optimize-call
      (lambda (_%self266289%_ _%ctx266290%_ _%stx266291%_ _%args266292%_)
        (let* ((_%self266295%_ _%self266289%_)
               (_%$%self266304266313%_ _%self266295%_)
               (_%$%E266306266316%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (error '"No clause matching"
                           _%$%self266304266313%_
                           '((!kw-lambda _ _ table dispatch))))
                  '#!void))
               (_%$%K266307266407%_
                (lambda (_%dispatch266319%_ _%table266320%_)
                  (if (let ()
                        (declare (not safe))
                        (gxc#symbol-in-local-scope? _%dispatch266319%_))
                      (let* ((_%$%g266321266331%_
                              (let ()
                                (declare (not safe))
                                (gxc#optimizer-lookup-type
                                 _%dispatch266319%_)))
                             (_%$%else266323266339%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gxc#verbose
                                   '"unknown keyword dispatch lambda "
                                   _%dispatch266319%_))
                                (let ()
                                  (declare (not safe))
                                  (gxc#xform-call%
                                   _%ctx266290%_
                                   _%stx266291%_))))
                             (_%$%K266325266388%_
                              (lambda (_%main266342%_ _%keys266343%_)
                                (let ((_g270868_
                                       (gxc#!kw-lambda-split-args
                                        _%stx266291%_
                                        _%args266292%_)))
                                  (begin
                                    (let ((_g270869_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g270868_)
                                                 (##values-length _g270868_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g270869_ 2)))
                                          (error "Context expects 2 values"
                                                 _g270869_)))
                                    (let ((_%pargs266345%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g270868_ 0)))
                                          (_%kwargs266346%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g270868_ 1))))
                                      (begin
                                        (let ()
                                          (declare (not safe))
                                          (gxc#verbose
                                           '"dispatch kw-lambda => "
                                           _%main266342%_))
                                        (if _%table266320%_
                                            (let ((_%xargs266354%_
                                                   (map (lambda (_%key266348%_)
                                                          (let ((_%$e266350%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (agetq__0 _%key266348%_ _%kwargs266346%_))))
                    (if _%$e266350%_ _%$e266350%_ '(%#ref absent-value))))
                _%keys266343%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (for-each
                                               (lambda (_%kw266356%_)
                                                 (if (memq (car _%kw266356%_)
                                                           _%keys266343%_)
                                                     '#!void
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#raise-compile-error
                                                        '"Illegal keyword lambda application; unexpected keyword"
                                                        _%stx266291%_
                                                        _%keys266343%_
                                                        _%kw266356%_))))
                                               _%kwargs266346%_)
                                              (let ((__tmp270870
                                                     (cons '%#call
                                                           (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (cons _%main266342%_ '()))
                         (cons (cons '%#quote (cons '#f '()))
                               (append _%xargs266354%_ _%pargs266345%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (declare (not safe))
                                                (gxc#xform-wrap-apply
                                                 __tmp270870
                                                 _%stx266291%_
                                                 _%ctx266290%_)))
                                            (let* ((_%kwt266358%_
                                                    (let ((__tmp270871
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##gensym
                                                              '__kwt))))
                                                      (declare (not safe))
                                                      (make-symbol__0
                                                       __tmp270871)))
                                                   (_%kwvars266362%_
                                                    (map (lambda (_%_266360%_)
                                                           (let ((__tmp270872
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let () (declare (not safe)) (##gensym '__kw))))
                     (declare (not safe))
                     (make-symbol__0 __tmp270872)))
                 _%kwargs266346%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%kwbind266367%_
                                                    (map (lambda (_%kw266364%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%kwvar266365%_)
                   (cons (cons _%kwvar266365%_ '())
                         (cons (cdr _%kw266364%_) '())))
                 _%kwargs266346%_
                 _%kwvars266362%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%kwset266372%_
                                                    (map (lambda (_%kw266369%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%kwvar266370%_)
                   (cons '%#call
                         (cons '(%#ref symbolic-table-set!)
                               (cons (cons '%#ref (cons _%kwt266358%_ '()))
                                     (cons (cons '%#quote
                                                 (cons (car _%kw266369%_) '()))
                                           (cons (cons '%#ref
                                                       (cons _%kwvar266370%_
                                                             '()))
                                                 '()))))))
                 _%kwargs266346%_
                 _%kwvars266362%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%xkwargs266377%_
                                                    (map (lambda (_%kw266374%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%kwvar266375%_)
                   (cons (car _%kw266374%_)
                         (cons '%#ref (cons _%kwvar266375%_ '()))))
                 _%kwargs266346%_
                 _%kwvars266362%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%xargs266385%_
                                                    (map (lambda (_%key266379%_)
                                                           (let ((_%$e266381%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (agetq__0 _%key266379%_ _%xkwargs266377%_))))
                     (if _%$e266381%_ _%$e266381%_ '(%#ref absent-value))))
                 _%keys266343%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (__tmp270873
                                                    (cons '%#let-values
                                                          (cons _%kwbind266367%_
                                                                (cons (cons '%#let-values
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    (cons (cons (cons (cons _%kwt266358%_ '())
                                                      (cons (let ((__tmp270874
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons '%#call
                                 (cons '(%#ref make-symbolic-table)
                                       (cons (cons '%#quote
                                                   (cons (length _%kwargs266346%_)
                                                         '()))
                                             (cons '(%#quote 0) '()))))))
                      (declare (not safe))
                      (gxc#xform-wrap-source __tmp270874 _%stx266291%_))
                    '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '())
                                          (cons (cons '%#begin
                                                      (let ((__tmp270875
                                                             (cons (let ((__tmp270876
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (cons '%#call
                                        (cons (cons '%#ref
                                                    (cons _%main266342%_ '()))
                                              (cons (cons '%#ref
                                                          (cons _%kwt266358%_
                                                                '()))
                                                    (append _%xargs266385%_
                                                            _%pargs266345%_))))))
                             (declare (not safe))
                             (gxc#xform-wrap-source __tmp270876 _%stx266291%_))
                           '())))
                (declare (not safe))
                (##append _%kwset266372%_ __tmp270875)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '())))
                              '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (gxc#xform-wrap-apply
                                               __tmp270873
                                               _%stx266291%_
                                               _%ctx266290%_))))))))))
                        (if (let ()
                              (declare (not safe))
                              (##structure-instance-of?
                               _%$%g266321266331%_
                               'gxc#!kw-lambda-primary::t))
                            (let* ((_%$%e266326266391%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%g266321266331%_
                                       '1
                                       '#f
                                       '#f)))
                                   (_%$%e266327266394%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%g266321266331%_
                                       '2
                                       '#f
                                       '#f)))
                                   (_%$%e266328266397%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%g266321266331%_
                                       '3
                                       '#f
                                       '#f)))
                                   (_%keys266400%_ _%$%e266328266397%_)
                                   (_%$%e266329266402%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%g266321266331%_
                                       '4
                                       '#f
                                       '#f)))
                                   (_%main266405%_ _%$%e266329266402%_))
                              (_%$%K266325266388%_
                               _%main266405%_
                               _%keys266400%_))
                            (_%$%else266323266339%_)))
                      (let ()
                        (declare (not safe))
                        (gxc#xform-call% _%ctx266290%_ _%stx266291%_)))))
               (_%$%e266308266410%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266304266313%_
                   '1
                   '#f
                   '#f)))
               (_%$%e266309266413%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266304266313%_
                   '2
                   '#f
                   '#f)))
               (_%$%e266310266416%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266304266313%_
                   '3
                   '#f
                   '#f)))
               (_%table266419%_ _%$%e266310266416%_)
               (_%$%e266311266421%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self266304266313%_
                   '4
                   '#f
                   '#f)))
               (_%dispatch266424%_ _%$%e266311266421%_))
          (_%$%K266307266407%_ _%dispatch266424%_ _%table266419%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!kw-lambda::t
       'optimize-call
       gxc#!kw-lambda::optimize-call
       '#f))
    (define gxc#!kw-lambda-split-args
      (lambda (_%stx265902%_ _%args265903%_)
        (let _%lp265905%_ ((_%rest265907%_ _%args265903%_)
                           (_%pargs265908%_ '())
                           (_%kwargs265909%_ '()))
          (let* ((_%__stx270289270290%_ _%rest265907%_)
                 (_%$%g265915265967%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%__stx270289270290%_)))))
            (let ((_%__kont270291270292%_
                   (lambda (_%$%g265917266146%_ _%$%g265918266147%_)
                     (_%lp265905%_
                      _%$%g265917266146%_
                      (cons _%$%g265918266147%_ _%pargs265908%_)
                      _%kwargs265909%_)))
                  (_%__kont270293270294%_
                   (lambda (_%$%g265932266092%_)
                     (values (let ()
                               (declare (not safe))
                               (foldl__0
                                cons
                                _%$%g265932266092%_
                                _%pargs265908%_))
                             (reverse _%kwargs265909%_))))
                  (_%__kont270295270296%_
                   (lambda (_%$%g265943266039%_
                            _%$%g265944266040%_
                            _%$%g265945266041%_)
                     (let ((_%kw266058%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%g265945266041%_))))
                       (if (assq _%kw266058%_ _%kwargs265909%_)
                           (let ()
                             (declare (not safe))
                             (gxc#raise-compile-error
                              '"Illegal keyword lambda application; duplicate keyword"
                              _%stx265902%_
                              _%kw266058%_))
                           (_%lp265905%_
                            _%$%g265943266039%_
                            _%pargs265908%_
                            (cons (cons _%kw266058%_ _%$%g265944266040%_)
                                  _%kwargs265909%_))))))
                  (_%__kont270297270298%_
                   (lambda (_%$%g265958265987%_ _%$%g265959265988%_)
                     (_%lp265905%_
                      _%$%g265958265987%_
                      (cons _%$%g265959265988%_ _%pargs265908%_)
                      _%kwargs265909%_)))
                  (_%__kont270299270300%_
                   (lambda ()
                     (values (reverse _%pargs265908%_)
                             (reverse _%kwargs265909%_)))))
              (let ((_%__match270396270397%_
                     (lambda (_%$%e265946266007%_
                              _%$%hd265947266010%_
                              _%$%tl265948266012%_
                              _%$%e265949266015%_
                              _%$%hd265950266018%_
                              _%$%tl265951266020%_
                              _%$%e265952266023%_
                              _%$%hd265953266026%_
                              _%$%tl265954266028%_
                              _%$%e265955266031%_
                              _%$%hd265956266034%_
                              _%$%tl265957266036%_)
                       (let ((_%$%g265943266039%_ _%$%tl265957266036%_)
                             (_%$%g265944266040%_ _%$%hd265956266034%_)
                             (_%$%g265945266041%_ _%$%hd265953266026%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-keyword? _%$%g265945266041%_))
                             (_%__kont270295270296%_
                              _%$%g265943266039%_
                              _%$%g265944266040%_
                              _%$%g265945266041%_)
                             (_%__kont270297270298%_
                              _%$%tl265948266012%_
                              _%$%hd265947266010%_))))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%__stx270289270290%_))
                    (let ((_%$%e265919266111%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%__stx270289270290%_))))
                      (let ((_%$%tl265921266116%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e265919266111%_)))
                            (_%$%hd265920266114%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e265919266111%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%hd265920266114%_))
                            (let ((_%$%e265922266119%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%hd265920266114%_))))
                              (let ((_%$%tl265924266124%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e265922266119%_)))
                                    (_%$%hd265923266122%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e265922266119%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#identifier? _%$%hd265923266122%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-eq?
                                           '%#quote
                                           _%$%hd265923266122%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl265924266124%_))
                                            (let ((_%$%e265925266127%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl265924266124%_))))
                                              (let ((_%$%tl265927266132%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e265925266127%_)))
                                                    (_%$%hd265926266130%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e265925266127%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-datum?
                                                       _%$%hd265926266130%_))
                                                    (let ((_%$%e265928266135%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%hd265926266130%_))))
                                                      (if (equal? _%$%e265928266135%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '#!key)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl265927266132%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl265921266116%_))
                          (let ((_%$%e265929266138%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl265921266116%_))))
                            (let ((_%$%tl265931266143%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e265929266138%_)))
                                  (_%$%hd265930266141%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e265929266138%_))))
                              (_%__kont270291270292%_
                               _%$%tl265931266143%_
                               _%$%hd265930266141%_)))
                          (_%__kont270297270298%_
                           _%$%tl265921266116%_
                           _%$%hd265920266114%_))
                      (_%__kont270297270298%_
                       _%$%tl265921266116%_
                       _%$%hd265920266114%_))
                  (if (equal? _%$%e265928266135%_ '#!rest)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl265927266132%_))
                          (_%__kont270293270294%_ _%$%tl265921266116%_)
                          (_%__kont270297270298%_
                           _%$%tl265921266116%_
                           _%$%hd265920266114%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl265927266132%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl265921266116%_))
                              (let ((_%$%e265955266031%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl265921266116%_))))
                                (let ((_%$%tl265957266036%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e265955266031%_)))
                                      (_%$%hd265956266034%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e265955266031%_))))
                                  (_%__match270396270397%_
                                   _%$%e265919266111%_
                                   _%$%hd265920266114%_
                                   _%$%tl265921266116%_
                                   _%$%e265922266119%_
                                   _%$%hd265923266122%_
                                   _%$%tl265924266124%_
                                   _%$%e265925266127%_
                                   _%$%hd265926266130%_
                                   _%$%tl265927266132%_
                                   _%$%e265955266031%_
                                   _%$%hd265956266034%_
                                   _%$%tl265957266036%_)))
                              (_%__kont270297270298%_
                               _%$%tl265921266116%_
                               _%$%hd265920266114%_))
                          (_%__kont270297270298%_
                           _%$%tl265921266116%_
                           _%$%hd265920266114%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl265927266132%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl265921266116%_))
                                                            (let ((_%$%e265955266031%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl265921266116%_))))
                      (let ((_%$%tl265957266036%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e265955266031%_)))
                            (_%$%hd265956266034%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e265955266031%_))))
                        (_%__match270396270397%_
                         _%$%e265919266111%_
                         _%$%hd265920266114%_
                         _%$%tl265921266116%_
                         _%$%e265922266119%_
                         _%$%hd265923266122%_
                         _%$%tl265924266124%_
                         _%$%e265925266127%_
                         _%$%hd265926266130%_
                         _%$%tl265927266132%_
                         _%$%e265955266031%_
                         _%$%hd265956266034%_
                         _%$%tl265957266036%_)))
                    (_%__kont270297270298%_
                     _%$%tl265921266116%_
                     _%$%hd265920266114%_))
                (_%__kont270297270298%_
                 _%$%tl265921266116%_
                 _%$%hd265920266114%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%__kont270297270298%_
                                             _%$%tl265921266116%_
                                             _%$%hd265920266114%_))
                                        (_%__kont270297270298%_
                                         _%$%tl265921266116%_
                                         _%$%hd265920266114%_))
                                    (_%__kont270297270298%_
                                     _%$%tl265921266116%_
                                     _%$%hd265920266114%_))))
                            (_%__kont270297270298%_
                             _%$%tl265921266116%_
                             _%$%hd265920266114%_))))
                    (_%__kont270299270300%_))))))))
    (define gxc#!kw-lambda-primary::optimize-call
      (lambda (_%self265886%_ _%ctx265887%_ _%stx265888%_ _%args265889%_)
        (let ((_%self265892%_ _%self265886%_))
          (declare (not safe))
          (gxc#xform-call% _%ctx265887%_ _%stx265888%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!kw-lambda-primary::t
       'optimize-call
       gxc#!kw-lambda-primary::optimize-call
       '#f))
    (define gxc#apply-check-return-type-begin-annotation%
      (lambda (_%self265486%_ _%stx265487%_)
        (let* ((_%__stx270405270406%_ _%stx265487%_)
               (_%$%g265491265548%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx270405270406%_)))))
          (let ((_%__kont270407270408%_
                 (lambda (_%$%g265493265733%_ _%$%g265494265734%_)
                   (let ((_%type265752%_
                          (let ((__tmp270877
                                 (let ()
                                   (declare (not safe))
                                   (gxc#type-expression->datum
                                    _%$%g265494265734%_))))
                            (declare (not safe))
                            (gxc#optimizer-resolve-type-expression
                             _%stx265487%_
                             __tmp270877)))
                         (_%expr-type265753%_
                          (let ()
                            (declare (not safe))
                            (gxc#apply-basic-expression-type
                             _%$%g265493265733%_))))
                     (if (let ()
                           (declare (not safe))
                           (##structure-instance-of?
                            _%type265752%_
                            'gxc#!nullable-type::t))
                         (if (and _%expr-type265753%_
                                  (let ((__tmp270878
                                         (let ()
                                           (declare (not safe))
                                           (gxc#optimizer-resolve-class
                                            _%stx265487%_
                                            'false::t))))
                                    (declare (not safe))
                                    (gxc#!type-subtype?
                                     __tmp270878
                                     _%expr-type265753%_)))
                             '#!void
                             (gxc#check-expression-type!
                              _%stx265487%_
                              _%$%g265493265733%_
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 _%type265752%_
                                 '2
                                 '#f
                                 '#f))))
                         (let ((_%$e265756%_
                                (let ((__tmp270879
                                       (##structure-ref
                                        _%type265752%_
                                        '1
                                        gxc#!type::t
                                        '#f)))
                                  (declare (not safe))
                                  (##memq __tmp270879 '(t void)))))
                           (if _%$e265756%_
                               _%$e265756%_
                               (if (and _%expr-type265753%_
                                        (let ()
                                          (declare (not safe))
                                          (##structure-instance-of?
                                           _%expr-type265753%_
                                           'gxc#!nullable-type::t)))
                                   (gxc#check-return-type!
                                    _%stx265487%_
                                    _%$%g265493265733%_
                                    _%type265752%_)
                                   '#!void))))
                     (let ()
                       (declare (not safe))
                       (gxc#compile-e__1
                        _%self265486%_
                        _%$%g265493265733%_)))))
                (_%__kont270409270410%_
                 (lambda (_%$%g265510265652%_ _%$%g265511265653%_)
                   (let ((_%$e265680%_
                          (member 'return:
                                  (let ((__tmp270880
                                         (lambda (_%$%g265672265675%_
                                                  _%$%g265673265677%_)
                                           (cons _%$%g265672265675%_
                                                 _%$%g265673265677%_))))
                                    (declare (not safe))
                                    (foldr__0
                                     __tmp270880
                                     '()
                                     _%$%g265511265653%_))
                                  gx#stx-eq?)))
                     (if _%$e265680%_
                         (let ((_%type265685%_
                                (let ((__tmp270881
                                       (let ((__tmp270882 (cadr _%$e265680%_)))
                                         (declare (not safe))
                                         (gxc#type-expression->datum
                                          __tmp270882))))
                                  (declare (not safe))
                                  (gxc#optimizer-resolve-type-expression
                                   _%stx265487%_
                                   __tmp270881))))
                           (gxc#check-return-type!
                            _%stx265487%_
                            _%$%g265510265652%_
                            _%type265685%_)
                           (let ()
                             (declare (not safe))
                             (gxc#compile-e__1
                              _%self265486%_
                              _%$%g265510265652%_)))
                         (let ()
                           (declare (not safe))
                           (gxc#compile-e__1
                            _%self265486%_
                            _%$%g265510265652%_))))))
                (_%__kont270413270414%_
                 (lambda (_%$%g265533265577%_ _%$%g265534265578%_)
                   (let ()
                     (declare (not safe))
                     (gxc#compile-e__1 _%self265486%_ _%$%g265533265577%_)))))
            (let ((_%__match270482270483%_
                   (lambda (_%$%e265512265598%_
                            _%$%hd265513265601%_
                            _%$%tl265514265603%_
                            _%$%e265515265606%_
                            _%$%hd265516265609%_
                            _%$%tl265517265611%_
                            _%$%e265518265614%_
                            _%$%hd265519265617%_
                            _%$%tl265520265619%_
                            _%__splice270411270412%_
                            _%$%target265521265622%_
                            _%$%tl265523265624%_)
                     (letrec ((_%$%loop265524265627%_
                               (lambda (_%$%hd265522265630%_
                                        _%$%signature265528265632%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%hd265522265630%_))
                                     (let ((_%$%e265525265634%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%$%hd265522265630%_))))
                                       (let ((_%$%lp-tl265527265639%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e265525265634%_)))
                                             (_%$%lp-hd265526265637%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e265525265634%_))))
                                         (_%$%loop265524265627%_
                                          _%$%lp-tl265527265639%_
                                          (cons _%$%lp-hd265526265637%_
                                                _%$%signature265528265632%_))))
                                     (let ((_%$%signature265529265642%_
                                            (reverse _%$%signature265528265632%_)))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-pair?
                                              _%$%tl265517265611%_))
                                           (let ((_%$%e265530265644%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%tl265517265611%_))))
                                             (let ((_%$%tl265532265649%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e265530265644%_)))
                                                   (_%$%hd265531265647%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e265530265644%_))))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-null?
                                                      _%$%tl265532265649%_))
                                                   (_%__kont270409270410%_
                                                    _%$%hd265531265647%_
                                                    _%$%signature265529265642%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (_%$%g265491265548%_)))))
                                           (let ()
                                             (declare (not safe))
                                             (_%$%g265491265548%_))))))))
                       (_%$%loop265524265627%_
                        _%$%target265521265622%_
                        '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx270405270406%_))
                  (let ((_%$%e265495265693%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx270405270406%_))))
                    (let ((_%$%tl265497265698%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e265495265693%_)))
                          (_%$%hd265496265696%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e265495265693%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl265497265698%_))
                          (let ((_%$%e265498265701%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl265497265698%_))))
                            (let ((_%$%tl265500265706%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e265498265701%_)))
                                  (_%$%hd265499265704%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e265498265701%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd265499265704%_))
                                  (let ((_%$%e265501265709%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd265499265704%_))))
                                    (let ((_%$%tl265503265714%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e265501265709%_)))
                                          (_%$%hd265502265712%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e265501265709%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd265502265712%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '@type.return
                                                 _%$%hd265502265712%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl265503265714%_))
                                                  (let ((_%$%e265504265717%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl265503265714%_))))
                                                    (let ((_%$%tl265506265722%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e265504265717%_)))
                                                          (_%$%hd265505265720%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e265504265717%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl265506265722%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl265500265706%_))
                      (let ((_%$%e265507265725%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl265500265706%_))))
                        (let ((_%$%tl265509265730%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e265507265725%_)))
                              (_%$%hd265508265728%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e265507265725%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl265509265730%_))
                              (_%__kont270407270408%_
                               _%$%hd265508265728%_
                               _%$%hd265505265720%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g265491265548%_)))))
                      (let () (declare (not safe)) (_%$%g265491265548%_)))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl265500265706%_))
                      (let ((_%$%e265541265569%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl265500265706%_))))
                        (let ((_%$%tl265543265574%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e265541265569%_)))
                              (_%$%hd265542265572%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e265541265569%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl265543265574%_))
                              (_%__kont270413270414%_
                               _%$%hd265542265572%_
                               _%$%hd265499265704%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g265491265548%_)))))
                      (let () (declare (not safe)) (_%$%g265491265548%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl265500265706%_))
                                                      (let ((_%$%e265541265569%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl265500265706%_))))
                (let ((_%$%tl265543265574%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e265541265569%_)))
                      (_%$%hd265542265572%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e265541265569%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl265543265574%_))
                      (_%__kont270413270414%_
                       _%$%hd265542265572%_
                       _%$%hd265499265704%_)
                      (let () (declare (not safe)) (_%$%g265491265548%_)))))
              (let () (declare (not safe)) (_%$%g265491265548%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-eq?
                                                     '@type.signature
                                                     _%$%hd265502265712%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair/null?
                                                         _%$%tl265503265714%_))
                                                      (let ((_%__splice270411270412%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-split-splice->vector
                        _%$%tl265503265714%_
                        '0))))
                (let ((_%$%tl265523265624%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice270411270412%_ '1)))
                      (_%$%target265521265622%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice270411270412%_ '0))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl265523265624%_))
                      (_%__match270482270483%_
                       _%$%e265495265693%_
                       _%$%hd265496265696%_
                       _%$%tl265497265698%_
                       _%$%e265498265701%_
                       _%$%hd265499265704%_
                       _%$%tl265500265706%_
                       _%$%e265501265709%_
                       _%$%hd265502265712%_
                       _%$%tl265503265714%_
                       _%__splice270411270412%_
                       _%$%target265521265622%_
                       _%$%tl265523265624%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl265500265706%_))
                          (let ((_%$%e265541265569%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl265500265706%_))))
                            (let ((_%$%tl265543265574%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e265541265569%_)))
                                  (_%$%hd265542265572%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e265541265569%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl265543265574%_))
                                  (_%__kont270413270414%_
                                   _%$%hd265542265572%_
                                   _%$%hd265499265704%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g265491265548%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g265491265548%_))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%$%tl265500265706%_))
                  (let ((_%$%e265541265569%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%tl265500265706%_))))
                    (let ((_%$%tl265543265574%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e265541265569%_)))
                          (_%$%hd265542265572%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e265541265569%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl265543265574%_))
                          (_%__kont270413270414%_
                           _%$%hd265542265572%_
                           _%$%hd265499265704%_)
                          (let ()
                            (declare (not safe))
                            (_%$%g265491265548%_)))))
                  (let () (declare (not safe)) (_%$%g265491265548%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl265500265706%_))
                                                      (let ((_%$%e265541265569%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl265500265706%_))))
                (let ((_%$%tl265543265574%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e265541265569%_)))
                      (_%$%hd265542265572%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e265541265569%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl265543265574%_))
                      (_%__kont270413270414%_
                       _%$%hd265542265572%_
                       _%$%hd265499265704%_)
                      (let () (declare (not safe)) (_%$%g265491265548%_)))))
              (let () (declare (not safe)) (_%$%g265491265548%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl265500265706%_))
                                              (let ((_%$%e265541265569%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl265500265706%_))))
                                                (let ((_%$%tl265543265574%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e265541265569%_)))
                                                      (_%$%hd265542265572%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e265541265569%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl265543265574%_))
                                                      (_%__kont270413270414%_
                                                       _%$%hd265542265572%_
                                                       _%$%hd265499265704%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g265491265548%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g265491265548%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl265500265706%_))
                                      (let ((_%$%e265541265569%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl265500265706%_))))
                                        (let ((_%$%tl265543265574%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e265541265569%_)))
                                              (_%$%hd265542265572%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e265541265569%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl265543265574%_))
                                              (_%__kont270413270414%_
                                               _%$%hd265542265572%_
                                               _%$%hd265499265704%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g265491265548%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g265491265548%_))))))
                          (let ()
                            (declare (not safe))
                            (_%$%g265491265548%_)))))
                  (let () (declare (not safe)) (_%$%g265491265548%_))))))))
    (define gxc#check-return-type!
      (lambda (_%stx265461%_ _%expr265462%_ _%type265463%_)
        (let ((_%$e265465%_ (not _%type265463%_)))
          (if _%$e265465%_
              _%$e265465%_
              (let ((_%$e265468%_
                     (eq? (##structure-ref _%type265463%_ '1 gxc#!type::t '#f)
                          't)))
                (if _%$e265468%_
                    _%$e265468%_
                    (let ((_%$e265471%_
                           (eq? (##structure-ref
                                 _%type265463%_
                                 '1
                                 gxc#!type::t
                                 '#f)
                                'void)))
                      (if _%$e265471%_
                          _%$e265471%_
                          (let ((_%expr-type265475%_
                                 (let ()
                                   (declare (not safe))
                                   (gxc#apply-basic-expression-type
                                    _%expr265462%_))))
                            (if _%expr-type265475%_
                                (if (eq? 't
                                         (##structure-ref
                                          _%expr-type265475%_
                                          '1
                                          gxc#!type::t
                                          '#f))
                                    (let ()
                                      (declare (not safe))
                                      (gxc#raise-compile-error
                                       '"cannot verify procedure return type; unspecific type"
                                       _%stx265461%_
                                       _%type265463%_
                                       _%expr-type265475%_))
                                    (let ((_%$e265479%_
                                           (let ()
                                             (declare (not safe))
                                             (##structure-instance-of?
                                              _%expr-type265475%_
                                              'gxc#!abort::t))))
                                      (if _%$e265479%_
                                          _%$e265479%_
                                          (let ((_%$e265482%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gxc#!type-subtype?
                                                    _%expr-type265475%_
                                                    _%type265463%_))))
                                            (if _%$e265482%_
                                                _%$e265482%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gxc#raise-compile-error
                                                   '"procedure return type does not match signature"
                                                   _%stx265461%_
                                                   _%type265463%_
                                                   _%expr-type265475%_)))))))
                                (let ()
                                  (declare (not safe))
                                  (gxc#raise-compile-error
                                   '"cannot verify procedure return type; no type information"
                                   _%stx265461%_
                                   _%type265463%_))))))))))))
    (define gxc#optimize-if%
      (lambda (_%self265068%_ _%stx265069%_)
        (gxc#check-contract-violation!
         _%stx265069%_
         (let* ((_%__stx270531270532%_ _%stx265069%_)
                (_%$%g265073265146%_
                 (lambda ()
                   (let ()
                     (declare (not safe))
                     (gx#raise-syntax-error
                      '#f
                      '"Bad syntax; invalid match target"
                      _%__stx270531270532%_)))))
           (let ((_%__kont270533270534%_
                  (lambda (_%$%g265075265435%_
                           _%$%g265076265436%_
                           _%$%g265077265437%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-e _%$%g265077265437%_))
                        (let ()
                          (declare (not safe))
                          (gxc#compile-e__1
                           _%self265068%_
                           _%$%g265076265436%_))
                        (let ()
                          (declare (not safe))
                          (gxc#compile-e__1
                           _%self265068%_
                           _%$%g265075265435%_)))))
                 (_%__kont270535270536%_
                  (lambda (_%$%g265096265351%_
                           _%$%g265097265352%_
                           _%$%g265098265353%_
                           _%$%g265099265354%_)
                    (gxc#optimize-if%
                     _%self265068%_
                     (let ((__tmp270883
                            (cons (let ()
                                    (declare (not safe))
                                    (gx#datum->syntax__0 '#f '%#if))
                                  (cons _%$%g265098265353%_
                                        (cons _%$%g265096265351%_
                                              (cons _%$%g265097265352%_
                                                    '()))))))
                       (declare (not safe))
                       (gxc#xform-wrap-source __tmp270883 _%stx265069%_)))))
                 (_%__kont270537270538%_
                  (lambda (_%$%g265127265183%_
                           _%$%g265128265184%_
                           _%$%g265129265185%_)
                    (let ((_g270884_
                           (let ()
                             (declare (not safe))
                             (gxc#expression-path-types _%$%g265129265185%_))))
                      (begin
                        (let ((_g270885_
                               (let ()
                                 (declare (not safe))
                                 (if (##values? _g270884_)
                                     (##values-length _g270884_)
                                     1))))
                          (if (not (let ()
                                     (declare (not safe))
                                     (##fx= _g270885_ 2)))
                              (error "Context expects 2 values" _g270885_)))
                        (let ((_%true-path265203%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g270884_ 0)))
                              (_%false-path265204%_
                               (let ()
                                 (declare (not safe))
                                 (##values-ref _g270884_ 1))))
                          (let ((_%test265210%_
                                 (let ()
                                   (declare (not safe))
                                   (gxc#compile-e__1
                                    _%self265068%_
                                    _%$%g265129265185%_)))
                                (_%K265211%_
                                 (let ((__tmp270886
                                        (lambda ()
                                          (let ((__tmp270887
                                                 (lambda ()
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#compile-e__1
                                                      _%self265068%_
                                                      _%$%g265128265184%_)))))
                                            (declare (not safe))
                                            (call-with-parameters__1
                                             __tmp270887
                                             gxc#current-compile-path-type
                                             _%true-path265203%_)))))
                                   (declare (not safe))
                                   (__make-promise __tmp270886)))
                                (_%E265212%_
                                 (let ((__tmp270888
                                        (lambda ()
                                          (let ((__tmp270889
                                                 (lambda ()
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#compile-e__1
                                                      _%self265068%_
                                                      _%$%g265127265183%_)))))
                                            (declare (not safe))
                                            (call-with-parameters__1
                                             __tmp270889
                                             gxc#current-compile-path-type
                                             _%false-path265204%_)))))
                                   (declare (not safe))
                                   (__make-promise __tmp270888))))
                            (let* ((_%__stx270505270506%_ _%test265210%_)
                                   (_%$%g265215265228%_
                                    (lambda ()
                                      (let ()
                                        (declare (not safe))
                                        (gx#raise-syntax-error
                                         '#f
                                         '"Bad syntax; invalid match target"
                                         _%__stx270505270506%_)))))
                              (let ((_%__kont270507270508%_
                                     (lambda (_%$%g265217265256%_)
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%g265217265256%_))
                                           (force _%K265211%_)
                                           (force _%E265212%_))))
                                    (_%__kont270509270510%_
                                     (lambda ()
                                       (let ((__tmp270890
                                              (cons '%#if
                                                    (cons _%test265210%_
                                                          (cons (force _%K265211%_)
                                                                (cons (force _%E265212%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         (declare (not safe))
                                         (gxc#xform-wrap-source
                                          __tmp270890
                                          _%stx265069%_)))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%__stx270505270506%_))
                                    (let ((_%$%e265218265240%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e
                                              _%__stx270505270506%_))))
                                      (let ((_%$%tl265220265245%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e265218265240%_)))
                                            (_%$%hd265219265243%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e265218265240%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#identifier?
                                               _%$%hd265219265243%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-eq?
                                                   '%#quote
                                                   _%$%hd265219265243%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl265220265245%_))
                                                    (let ((_%$%e265221265248%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%tl265220265245%_))))
                                                      (let ((_%$%tl265223265253%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e265221265248%_)))
                    (_%$%hd265222265251%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e265221265248%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl265223265253%_))
                    (_%__kont270507270508%_ _%$%hd265222265251%_)
                    (_%__kont270509270510%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont270509270510%_))
                                                (_%__kont270509270510%_))
                                            (_%__kont270509270510%_))))
                                    (_%__kont270509270510%_)))))))))))
             (let ((_%__match270650270651%_
                    (lambda (_%$%e265100265279%_
                             _%$%hd265101265282%_
                             _%$%tl265102265284%_
                             _%$%e265103265287%_
                             _%$%hd265104265290%_
                             _%$%tl265105265292%_
                             _%$%e265106265295%_
                             _%$%hd265107265298%_
                             _%$%tl265108265300%_
                             _%$%e265109265303%_
                             _%$%hd265110265306%_
                             _%$%tl265111265308%_
                             _%$%e265112265311%_
                             _%$%hd265113265314%_
                             _%$%tl265114265316%_
                             _%$%e265115265319%_
                             _%$%hd265116265322%_
                             _%$%tl265117265324%_
                             _%$%e265118265327%_
                             _%$%hd265119265330%_
                             _%$%tl265120265332%_
                             _%$%e265121265335%_
                             _%$%hd265122265338%_
                             _%$%tl265123265340%_
                             _%$%e265124265343%_
                             _%$%hd265125265346%_
                             _%$%tl265126265348%_)
                      (let ((_%$%g265096265351%_ _%$%hd265125265346%_)
                            (_%$%g265097265352%_ _%$%hd265122265338%_)
                            (_%$%g265098265353%_ _%$%hd265119265330%_)
                            (_%$%g265099265354%_ _%$%hd265116265322%_))
                        (if (let ()
                              (declare (not safe))
                              (gxc#runtime-identifier=?
                               _%$%g265099265354%_
                               'not))
                            (_%__kont270535270536%_
                             _%$%g265096265351%_
                             _%$%g265097265352%_
                             _%$%g265098265353%_
                             _%$%g265099265354%_)
                            (_%__kont270537270538%_
                             _%$%hd265125265346%_
                             _%$%hd265122265338%_
                             _%$%hd265104265290%_))))))
               (if (let ()
                     (declare (not safe))
                     (gx#stx-pair? _%__stx270531270532%_))
                   (let ((_%$%e265078265387%_
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%__stx270531270532%_))))
                     (let ((_%$%tl265080265392%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e265078265387%_)))
                           (_%$%hd265079265390%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e265078265387%_))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%tl265080265392%_))
                           (let ((_%$%e265081265395%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%tl265080265392%_))))
                             (let ((_%$%tl265083265400%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e265081265395%_)))
                                   (_%$%hd265082265398%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e265081265395%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%hd265082265398%_))
                                   (let ((_%$%e265084265403%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%hd265082265398%_))))
                                     (let ((_%$%tl265086265408%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e265084265403%_)))
                                           (_%$%hd265085265406%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e265084265403%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#identifier?
                                              _%$%hd265085265406%_))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-eq?
                                                  '%#quote
                                                  _%$%hd265085265406%_))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%tl265086265408%_))
                                                   (let ((_%$%e265087265411%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%tl265086265408%_))))
                                                     (let ((_%$%tl265089265416%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e265087265411%_)))
                                                           (_%$%hd265088265414%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e265087265411%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-null?
                                                              _%$%tl265089265416%_))
                                                           (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265083265400%_))
                       (let ((_%$%e265090265419%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265083265400%_))))
                         (let ((_%$%tl265092265424%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265090265419%_)))
                               (_%$%hd265091265422%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265090265419%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%tl265092265424%_))
                               (let ((_%$%e265093265427%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%tl265092265424%_))))
                                 (let ((_%$%tl265095265432%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e265093265427%_)))
                                       (_%$%hd265094265430%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e265093265427%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-null? _%$%tl265095265432%_))
                                       (_%__kont270533270534%_
                                        _%$%hd265094265430%_
                                        _%$%hd265091265422%_
                                        _%$%hd265088265414%_)
                                       (let ()
                                         (declare (not safe))
                                         (_%$%g265073265146%_)))))
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_)))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265083265400%_))
                       (let ((_%$%e265136265167%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265083265400%_))))
                         (let ((_%$%tl265138265172%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265136265167%_)))
                               (_%$%hd265137265170%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265136265167%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%tl265138265172%_))
                               (let ((_%$%e265139265175%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%tl265138265172%_))))
                                 (let ((_%$%tl265141265180%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e265139265175%_)))
                                       (_%$%hd265140265178%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e265139265175%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-null? _%$%tl265141265180%_))
                                       (_%__kont270537270538%_
                                        _%$%hd265140265178%_
                                        _%$%hd265137265170%_
                                        _%$%hd265082265398%_)
                                       (let ()
                                         (declare (not safe))
                                         (_%$%g265073265146%_)))))
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl265083265400%_))
                                                       (let ((_%$%e265136265167%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl265083265400%_))))
                 (let ((_%$%tl265138265172%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e265136265167%_)))
                       (_%$%hd265137265170%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e265136265167%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265138265172%_))
                       (let ((_%$%e265139265175%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265138265172%_))))
                         (let ((_%$%tl265141265180%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265139265175%_)))
                               (_%$%hd265140265178%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265139265175%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-null? _%$%tl265141265180%_))
                               (_%__kont270537270538%_
                                _%$%hd265140265178%_
                                _%$%hd265137265170%_
                                _%$%hd265082265398%_)
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_)))))
               (let () (declare (not safe)) (_%$%g265073265146%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-eq?
                                                      '%#call
                                                      _%$%hd265085265406%_))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl265086265408%_))
                                                       (let ((_%$%e265109265303%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl265086265408%_))))
                 (let ((_%$%tl265111265308%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e265109265303%_)))
                       (_%$%hd265110265306%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e265109265303%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%hd265110265306%_))
                       (let ((_%$%e265112265311%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%hd265110265306%_))))
                         (let ((_%$%tl265114265316%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265112265311%_)))
                               (_%$%hd265113265314%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265112265311%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#identifier? _%$%hd265113265314%_))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-eq? '%#ref _%$%hd265113265314%_))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-pair? _%$%tl265114265316%_))
                                       (let ((_%$%e265115265319%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-e
                                                 _%$%tl265114265316%_))))
                                         (let ((_%$%tl265117265324%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e265115265319%_)))
                                               (_%$%hd265116265322%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e265115265319%_))))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-null?
                                                  _%$%tl265117265324%_))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%tl265111265308%_))
                                                   (let ((_%$%e265118265327%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%tl265111265308%_))))
                                                     (let ((_%$%tl265120265332%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e265118265327%_)))
                                                           (_%$%hd265119265330%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e265118265327%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-null?
                                                              _%$%tl265120265332%_))
                                                           (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265083265400%_))
                       (let ((_%$%e265121265335%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265083265400%_))))
                         (let ((_%$%tl265123265340%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265121265335%_)))
                               (_%$%hd265122265338%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265121265335%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%tl265123265340%_))
                               (let ((_%$%e265124265343%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%tl265123265340%_))))
                                 (let ((_%$%tl265126265348%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e265124265343%_)))
                                       (_%$%hd265125265346%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e265124265343%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-null? _%$%tl265126265348%_))
                                       (_%__match270650270651%_
                                        _%$%e265078265387%_
                                        _%$%hd265079265390%_
                                        _%$%tl265080265392%_
                                        _%$%e265081265395%_
                                        _%$%hd265082265398%_
                                        _%$%tl265083265400%_
                                        _%$%e265084265403%_
                                        _%$%hd265085265406%_
                                        _%$%tl265086265408%_
                                        _%$%e265109265303%_
                                        _%$%hd265110265306%_
                                        _%$%tl265111265308%_
                                        _%$%e265112265311%_
                                        _%$%hd265113265314%_
                                        _%$%tl265114265316%_
                                        _%$%e265115265319%_
                                        _%$%hd265116265322%_
                                        _%$%tl265117265324%_
                                        _%$%e265118265327%_
                                        _%$%hd265119265330%_
                                        _%$%tl265120265332%_
                                        _%$%e265121265335%_
                                        _%$%hd265122265338%_
                                        _%$%tl265123265340%_
                                        _%$%e265124265343%_
                                        _%$%hd265125265346%_
                                        _%$%tl265126265348%_)
                                       (let ()
                                         (declare (not safe))
                                         (_%$%g265073265146%_)))))
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_)))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265083265400%_))
                       (let ((_%$%e265136265167%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265083265400%_))))
                         (let ((_%$%tl265138265172%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265136265167%_)))
                               (_%$%hd265137265170%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265136265167%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%tl265138265172%_))
                               (let ((_%$%e265139265175%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%tl265138265172%_))))
                                 (let ((_%$%tl265141265180%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e265139265175%_)))
                                       (_%$%hd265140265178%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e265139265175%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-null? _%$%tl265141265180%_))
                                       (_%__kont270537270538%_
                                        _%$%hd265140265178%_
                                        _%$%hd265137265170%_
                                        _%$%hd265082265398%_)
                                       (let ()
                                         (declare (not safe))
                                         (_%$%g265073265146%_)))))
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl265083265400%_))
                                                       (let ((_%$%e265136265167%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl265083265400%_))))
                 (let ((_%$%tl265138265172%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e265136265167%_)))
                       (_%$%hd265137265170%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e265136265167%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265138265172%_))
                       (let ((_%$%e265139265175%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265138265172%_))))
                         (let ((_%$%tl265141265180%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265139265175%_)))
                               (_%$%hd265140265178%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265139265175%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-null? _%$%tl265141265180%_))
                               (_%__kont270537270538%_
                                _%$%hd265140265178%_
                                _%$%hd265137265170%_
                                _%$%hd265082265398%_)
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_)))))
               (let () (declare (not safe)) (_%$%g265073265146%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%tl265083265400%_))
                                                   (let ((_%$%e265136265167%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%tl265083265400%_))))
                                                     (let ((_%$%tl265138265172%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e265136265167%_)))
                                                           (_%$%hd265137265170%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e265136265167%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-pair?
                                                              _%$%tl265138265172%_))
                                                           (let ((_%$%e265139265175%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%tl265138265172%_))))
                     (let ((_%$%tl265141265180%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e265139265175%_)))
                           (_%$%hd265140265178%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e265139265175%_))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-null? _%$%tl265141265180%_))
                           (_%__kont270537270538%_
                            _%$%hd265140265178%_
                            _%$%hd265137265170%_
                            _%$%hd265082265398%_)
                           (let ()
                             (declare (not safe))
                             (_%$%g265073265146%_)))))
                   (let () (declare (not safe)) (_%$%g265073265146%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (let ()
                                                     (declare (not safe))
                                                     (_%$%g265073265146%_))))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-pair?
                                              _%$%tl265083265400%_))
                                           (let ((_%$%e265136265167%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%tl265083265400%_))))
                                             (let ((_%$%tl265138265172%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e265136265167%_)))
                                                   (_%$%hd265137265170%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e265136265167%_))))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%tl265138265172%_))
                                                   (let ((_%$%e265139265175%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%tl265138265172%_))))
                                                     (let ((_%$%tl265141265180%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e265139265175%_)))
                                                           (_%$%hd265140265178%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e265139265175%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-null?
                                                              _%$%tl265141265180%_))
                                                           (_%__kont270537270538%_
                                                            _%$%hd265140265178%_
                                                            _%$%hd265137265170%_
                                                            _%$%hd265082265398%_)
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (_%$%g265073265146%_)))))
                                                   (let ()
                                                     (declare (not safe))
                                                     (_%$%g265073265146%_)))))
                                           (let ()
                                             (declare (not safe))
                                             (_%$%g265073265146%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-pair? _%$%tl265083265400%_))
                                       (let ((_%$%e265136265167%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-e
                                                 _%$%tl265083265400%_))))
                                         (let ((_%$%tl265138265172%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e265136265167%_)))
                                               (_%$%hd265137265170%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e265136265167%_))))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%tl265138265172%_))
                                               (let ((_%$%e265139265175%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%tl265138265172%_))))
                                                 (let ((_%$%tl265141265180%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e265139265175%_)))
                                                       (_%$%hd265140265178%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e265139265175%_))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-null?
                                                          _%$%tl265141265180%_))
                                                       (_%__kont270537270538%_
                                                        _%$%hd265140265178%_
                                                        _%$%hd265137265170%_
                                                        _%$%hd265082265398%_)
                                                       (let ()
                                                         (declare (not safe))
                                                         (_%$%g265073265146%_)))))
                                               (let ()
                                                 (declare (not safe))
                                                 (_%$%g265073265146%_)))))
                                       (let ()
                                         (declare (not safe))
                                         (_%$%g265073265146%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%tl265083265400%_))
                                   (let ((_%$%e265136265167%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%tl265083265400%_))))
                                     (let ((_%$%tl265138265172%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e265136265167%_)))
                                           (_%$%hd265137265170%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e265136265167%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-pair?
                                              _%$%tl265138265172%_))
                                           (let ((_%$%e265139265175%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%tl265138265172%_))))
                                             (let ((_%$%tl265141265180%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e265139265175%_)))
                                                   (_%$%hd265140265178%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e265139265175%_))))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-null?
                                                      _%$%tl265141265180%_))
                                                   (_%__kont270537270538%_
                                                    _%$%hd265140265178%_
                                                    _%$%hd265137265170%_
                                                    _%$%hd265082265398%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (_%$%g265073265146%_)))))
                                           (let ()
                                             (declare (not safe))
                                             (_%$%g265073265146%_)))))
                                   (let ()
                                     (declare (not safe))
                                     (_%$%g265073265146%_))))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%tl265083265400%_))
                           (let ((_%$%e265136265167%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%tl265083265400%_))))
                             (let ((_%$%tl265138265172%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e265136265167%_)))
                                   (_%$%hd265137265170%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e265136265167%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%tl265138265172%_))
                                   (let ((_%$%e265139265175%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%tl265138265172%_))))
                                     (let ((_%$%tl265141265180%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e265139265175%_)))
                                           (_%$%hd265140265178%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e265139265175%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-null?
                                              _%$%tl265141265180%_))
                                           (_%__kont270537270538%_
                                            _%$%hd265140265178%_
                                            _%$%hd265137265170%_
                                            _%$%hd265082265398%_)
                                           (let ()
                                             (declare (not safe))
                                             (_%$%g265073265146%_)))))
                                   (let ()
                                     (declare (not safe))
                                     (_%$%g265073265146%_)))))
                           (let ()
                             (declare (not safe))
                             (_%$%g265073265146%_))))))
               (if (let ()
                     (declare (not safe))
                     (gx#stx-pair? _%$%tl265083265400%_))
                   (let ((_%$%e265136265167%_
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%tl265083265400%_))))
                     (let ((_%$%tl265138265172%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e265136265167%_)))
                           (_%$%hd265137265170%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e265136265167%_))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%tl265138265172%_))
                           (let ((_%$%e265139265175%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%tl265138265172%_))))
                             (let ((_%$%tl265141265180%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e265139265175%_)))
                                   (_%$%hd265140265178%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e265139265175%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-null? _%$%tl265141265180%_))
                                   (_%__kont270537270538%_
                                    _%$%hd265140265178%_
                                    _%$%hd265137265170%_
                                    _%$%hd265082265398%_)
                                   (let ()
                                     (declare (not safe))
                                     (_%$%g265073265146%_)))))
                           (let ()
                             (declare (not safe))
                             (_%$%g265073265146%_)))))
                   (let () (declare (not safe)) (_%$%g265073265146%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl265083265400%_))
                                                       (let ((_%$%e265136265167%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl265083265400%_))))
                 (let ((_%$%tl265138265172%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e265136265167%_)))
                       (_%$%hd265137265170%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e265136265167%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl265138265172%_))
                       (let ((_%$%e265139265175%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl265138265172%_))))
                         (let ((_%$%tl265141265180%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e265139265175%_)))
                               (_%$%hd265140265178%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e265139265175%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-null? _%$%tl265141265180%_))
                               (_%__kont270537270538%_
                                _%$%hd265140265178%_
                                _%$%hd265137265170%_
                                _%$%hd265082265398%_)
                               (let ()
                                 (declare (not safe))
                                 (_%$%g265073265146%_)))))
                       (let () (declare (not safe)) (_%$%g265073265146%_)))))
               (let () (declare (not safe)) (_%$%g265073265146%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%tl265083265400%_))
                                               (let ((_%$%e265136265167%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%tl265083265400%_))))
                                                 (let ((_%$%tl265138265172%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e265136265167%_)))
                                                       (_%$%hd265137265170%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e265136265167%_))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl265138265172%_))
                                                       (let ((_%$%e265139265175%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl265138265172%_))))
                 (let ((_%$%tl265141265180%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e265139265175%_)))
                       (_%$%hd265140265178%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e265139265175%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-null? _%$%tl265141265180%_))
                       (_%__kont270537270538%_
                        _%$%hd265140265178%_
                        _%$%hd265137265170%_
                        _%$%hd265082265398%_)
                       (let () (declare (not safe)) (_%$%g265073265146%_)))))
               (let () (declare (not safe)) (_%$%g265073265146%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (let ()
                                                 (declare (not safe))
                                                 (_%$%g265073265146%_))))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-pair? _%$%tl265083265400%_))
                                       (let ((_%$%e265136265167%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-e
                                                 _%$%tl265083265400%_))))
                                         (let ((_%$%tl265138265172%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e265136265167%_)))
                                               (_%$%hd265137265170%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e265136265167%_))))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%tl265138265172%_))
                                               (let ((_%$%e265139265175%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%tl265138265172%_))))
                                                 (let ((_%$%tl265141265180%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e265139265175%_)))
                                                       (_%$%hd265140265178%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e265139265175%_))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-null?
                                                          _%$%tl265141265180%_))
                                                       (_%__kont270537270538%_
                                                        _%$%hd265140265178%_
                                                        _%$%hd265137265170%_
                                                        _%$%hd265082265398%_)
                                                       (let ()
                                                         (declare (not safe))
                                                         (_%$%g265073265146%_)))))
                                               (let ()
                                                 (declare (not safe))
                                                 (_%$%g265073265146%_)))))
                                       (let ()
                                         (declare (not safe))
                                         (_%$%g265073265146%_))))))
                           (let ()
                             (declare (not safe))
                             (_%$%g265073265146%_)))))
                   (let () (declare (not safe)) (_%$%g265073265146%_)))))))))
    (define gxc#check-contract-violation!
      (lambda (_%stx264936%_ _%expr264937%_)
        (let* ((_%__stx270679270680%_ _%expr264937%_)
               (_%$%g264940264970%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx270679270680%_)))))
          (let ((_%__kont270681270682%_
                 (lambda (_%$%g264942265038%_
                          _%$%g264943265039%_
                          _%$%g264944265040%_)
                   (let ()
                     (declare (not safe))
                     (gxc#raise-compile-error
                      '"contract violation"
                      _%stx264936%_
                      _%$%g264944265040%_
                      _%$%g264943265039%_
                      _%$%g264942265038%_))))
                (_%__kont270683270684%_ (lambda () _%expr264937%_)))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx270679270680%_))
                (let ((_%$%e264945264982%_
                       (let ()
                         (declare (not safe))
                         (gx#stx-e _%__stx270679270680%_))))
                  (let ((_%$%tl264947264987%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e264945264982%_)))
                        (_%$%hd264946264985%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e264945264982%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#identifier? _%$%hd264946264985%_))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-eq?
                               '%#begin-annotation
                               _%$%hd264946264985%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl264947264987%_))
                                (let ((_%$%e264948264990%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl264947264987%_))))
                                  (let ((_%$%tl264950264995%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e264948264990%_)))
                                        (_%$%hd264949264993%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e264948264990%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%hd264949264993%_))
                                        (let ((_%$%e264951264998%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd264949264993%_))))
                                          (let ((_%$%tl264953265003%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e264951264998%_)))
                                                (_%$%hd264952265001%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e264951264998%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#identifier?
                                                   _%$%hd264952265001%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-eq?
                                                       '@contract-violation
                                                       _%$%hd264952265001%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl264953265003%_))
                                                        (let ((_%$%e264954265006%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl264953265003%_))))
                  (let ((_%$%tl264956265011%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e264954265006%_)))
                        (_%$%hd264955265009%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e264954265006%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl264956265011%_))
                        (let ((_%$%e264957265014%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl264956265011%_))))
                          (let ((_%$%tl264959265019%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e264957265014%_)))
                                (_%$%hd264958265017%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e264957265014%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl264959265019%_))
                                (let ((_%$%e264960265022%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl264959265019%_))))
                                  (let ((_%$%tl264962265027%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e264960265022%_)))
                                        (_%$%hd264961265025%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e264960265022%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl264962265027%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl264950264995%_))
                                            (let ((_%$%e264963265030%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl264950264995%_))))
                                              (let ((_%$%tl264965265035%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e264963265030%_)))
                                                    (_%$%hd264964265033%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e264963265030%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl264965265035%_))
                                                    (_%__kont270681270682%_
                                                     _%$%hd264961265025%_
                                                     _%$%hd264958265017%_
                                                     _%$%hd264955265009%_)
                                                    (_%__kont270683270684%_))))
                                            (_%__kont270683270684%_))
                                        (_%__kont270683270684%_))))
                                (_%__kont270683270684%_))))
                        (_%__kont270683270684%_))))
                (_%__kont270683270684%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont270683270684%_))
                                                (_%__kont270683270684%_))))
                                        (_%__kont270683270684%_))))
                                (_%__kont270683270684%_))
                            (_%__kont270683270684%_))
                        (_%__kont270683270684%_))))
                (_%__kont270683270684%_))))))))
