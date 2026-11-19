(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/core/contract~ClassMeta::timestamp 1795039807)
  (begin
    (define gerbil/core/contract~ClassMeta#!class-precedence-list
      (lambda (_%klass63933%_)
        (let ((_%$e63935%_
               (let ((__obj107233 _%klass63933%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-direct-instance-of?
                        __obj107233
                        'gerbil/core#class-type-info::t))
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref __obj107233 '7 '#f '#f))
                     (class-slot-ref
                      gerbil/core/mop~MOP-2#class-type-info::t
                      __obj107233
                      'precedence-list)))))
          (if _%$e63935%_
              _%$e63935%_
              (let ((_g107292_
                     (c4-linearize
                      '()
                      (let ((__obj107234 _%klass63933%_))
                        (if (let ()
                              (declare (not safe))
                              (##structure-direct-instance-of?
                               __obj107234
                               'gerbil/core#class-type-info::t))
                            (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               __obj107234
                               '5
                               '#f
                               '#f))
                            (class-slot-ref
                             gerbil/core/mop~MOP-2#class-type-info::t
                             __obj107234
                             'super)))
                      'get-precedence-list:
                      (lambda (_%klass-id63939%_)
                        (cons _%klass-id63939%_
                              (gerbil/core/contract~ClassMeta#!class-precedence-list
                               (gx#syntax-local-value _%klass-id63939%_))))
                      'struct:
                      (lambda (_%klass-id63941%_)
                        (let ((__obj107235
                               (gx#syntax-local-value _%klass-id63941%_)))
                          (if (let ()
                                (declare (not safe))
                                (##structure-direct-instance-of?
                                 __obj107235
                                 'gerbil/core#class-type-info::t))
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 __obj107235
                                 '9
                                 '#f
                                 '#f))
                              (class-slot-ref
                               gerbil/core/mop~MOP-2#class-type-info::t
                               __obj107235
                               'struct?))))
                      'eq:
                      gx#free-identifier=?
                      'get-name:
                      gx#stx-e)))
                (begin
                  (let ((_g107293_
                         (let ()
                           (declare (not safe))
                           (if (##values? _g107292_)
                               (##values-length _g107292_)
                               1))))
                    (if (not (let () (declare (not safe)) (##fx= _g107293_ 2)))
                        (error "Context expects 2 values" _g107293_)))
                  (let ((_%precedence-list63943%_
                         (let ()
                           (declare (not safe))
                           (##values-ref _g107292_ 0)))
                        (_%base-struct63944%_
                         (let ()
                           (declare (not safe))
                           (##values-ref _g107292_ 1))))
                    (let ((_%precedence-list63988%_
                           (if (let ((__tmp107294
                                      (let ((__obj107236 _%klass63933%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (##structure-direct-instance-of?
                                               __obj107236
                                               'gerbil/core#class-type-info::t))
                                            (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               __obj107236
                                               '2
                                               '#f
                                               '#f))
                                            (class-slot-ref
                                             gerbil/core/mop~MOP-2#class-type-info::t
                                             __obj107236
                                             'id)))))
                                 (declare (not safe))
                                 (##memq __tmp107294 '(t object class)))
                               _%precedence-list63943%_
                               (if (member ':object
                                           _%precedence-list63943%_
                                           gx#free-identifier=?)
                                   _%precedence-list63943%_
                                   (if (let ((__obj107237 _%klass63933%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (##structure-direct-instance-of?
                                                __obj107237
                                                'gerbil/core#class-type-info::t))
                                             (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                __obj107237
                                                '11
                                                '#f
                                                '#f))
                                             (class-slot-ref
                                              gerbil/core/mop~MOP-2#class-type-info::t
                                              __obj107237
                                              'system?)))
                                       (if (member ':t
                                                   _%precedence-list63943%_
                                                   gx#free-identifier=?)
                                           _%precedence-list63943%_
                                           (let ((__tmp107295
                                                  (cons (gx#core-quote-syntax
                                                         ':t)
                                                        '())))
                                             (declare (not safe))
                                             (##append
                                              _%precedence-list63943%_
                                              __tmp107295)))
                                       (let _%loop63950%_ ((_%tail63952%_
                                                            _%precedence-list63943%_)
                                                           (_%head63953%_ '()))
                                         (let* ((_%$%tail6395463962%_
                                                 _%tail63952%_)
                                                (_%$%else6395663970%_
                                                 (lambda ()
                                                   (foldl cons
                                                          (cons (gx#core-quote-syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         ':object)
                        (cons (gx#core-quote-syntax ':t) '()))
                  _%head63953%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%K6395863976%_
                                                 (lambda (_%rest63973%_
                                                          _%hd63974%_)
                                                   (if (gx#free-identifier=?
                                                        _%hd63974%_
                                                        ':t)
                                                       (foldl cons
                                                              (cons (gx#core-quote-syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             ':object)
                            _%tail63952%_)
                      _%head63953%_)
               (_%loop63950%_
                _%rest63973%_
                (cons _%hd63974%_ _%head63953%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (if (pair? _%$%tail6395463962%_)
                                               (let ((_%$%hd6395963979%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%tail6395463962%_)))
                                                     (_%$%tl6396063981%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%tail6395463962%_))))
                                                 (let* ((_%hd63984%_
                                                         _%$%hd6395963979%_)
                                                        (_%rest63986%_
                                                         _%$%tl6396063981%_))
                                                   (_%$%K6395863976%_
                                                    _%rest63986%_
                                                    _%hd63984%_)))
                                               (_%$%else6395663970%_)))))))))
                      (let ((__obj107238 _%klass63933%_))
                        (if (let ()
                              (declare (not safe))
                              (##structure-direct-instance-of?
                               __obj107238
                               'gerbil/core#class-type-info::t))
                            (let ()
                              (declare (not safe))
                              (##unchecked-structure-set!
                               __obj107238
                               _%precedence-list63988%_
                               '7
                               '#f
                               '#f))
                            (class-slot-set!
                             gerbil/core/mop~MOP-2#class-type-info::t
                             __obj107238
                             'precedence-list
                             _%precedence-list63988%_)))
                      _%precedence-list63988%_))))))))
    (define gerbil/core/contract~ClassMeta#class-type-info::precedence-list
      gerbil/core/contract~ClassMeta#!class-precedence-list)
    (bind-method!
     gerbil/core/mop~MOP-2#class-type-info::t
     'precedence-list
     gerbil/core/contract~ClassMeta#class-type-info::precedence-list
     '#f)
    (define gerbil/core/contract~ClassMeta#meta-object-method-ref
      (lambda (_%meta63803%_ _%method63804%_)
        (let ((_%$%tab6380563807%_
               (let ((__obj107241 _%meta63803%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-direct-instance-of?
                        __obj107241
                        'gerbil/core#meta-object::t))
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref __obj107241 '1 '#f '#f))
                     (class-slot-ref
                      gerbil/core/mop~MOP-2#meta-object::t
                      __obj107241
                      'methods)))))
          (if _%$%tab6380563807%_
              (let ((_%tab63809%_ _%$%tab6380563807%_))
                (hash-get _%tab63809%_ _%method63804%_))
              '#f))))
    (define gerbil/core/contract~ClassMeta#get-meta-object-method
      (lambda (_%meta63797%_ _%method63798%_)
        (let ((_%$e63800%_
               (gerbil/core/contract~ClassMeta#meta-object-method-ref
                _%meta63797%_
                _%method63798%_)))
          (if _%$e63800%_
              _%$e63800%_
              (gerbil/core/contract~ClassMeta#get-meta-object-method-mixin
               _%meta63797%_
               _%method63798%_)))))
    (define gerbil/core/contract~ClassMeta#get-meta-object-method-mixin
      (lambda (_%meta63746%_ _%method63747%_)
        (let ((_%$e63749%_ (method-ref _%meta63746%_ 'precedence-list)))
          (if _%$e63749%_
              (let _%loop63754%_ ((_%rest63756%_ (_%$e63749%_ _%meta63746%_)))
                (let* ((_%$%rest6375763765%_ _%rest63756%_)
                       (_%$%else6375963773%_ (lambda () '#f))
                       (_%$%K6376163784%_
                        (lambda (_%rest63776%_ _%klass63777%_)
                          (let* ((_%meta63779%_
                                  (gx#syntax-local-value _%klass63777%_))
                                 (_%$e63781%_
                                  (if (let ()
                                        (declare (not safe))
                                        (class-instance?
                                         gerbil/core/mop~MOP-2#meta-object::t
                                         _%meta63779%_))
                                      (gerbil/core/contract~ClassMeta#meta-object-method-ref
                                       _%meta63779%_
                                       _%method63747%_)
                                      '#f)))
                            (if _%$e63781%_
                                _%$e63781%_
                                (_%loop63754%_ _%rest63776%_))))))
                  (if (pair? _%$%rest6375763765%_)
                      (let ((_%$%hd6376263787%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%rest6375763765%_)))
                            (_%$%tl6376363789%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%rest6375763765%_))))
                        (let* ((_%klass63792%_ _%$%hd6376263787%_)
                               (_%rest63794%_ _%$%tl6376363789%_))
                          (_%$%K6376163784%_ _%rest63794%_ _%klass63792%_)))
                      (_%$%else6375963773%_))))
              '#f))))
    (define gerbil/core/contract~ClassMeta#call-meta-object
      (lambda (_%meta63736%_ _%method63737%_ . _%args63738%_)
        (let ((_%$e63740%_
               (gerbil/core/contract~ClassMeta#get-meta-object-method
                _%meta63736%_
                _%method63737%_)))
          (if _%$e63740%_
              (apply _%$e63740%_ _%meta63736%_ _%args63738%_)
              (error '"missing meta object method"
                     'meta-object:
                     _%meta63736%_
                     'method:
                     'method)))))))
