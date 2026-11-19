(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/core/contract~InterfaceInfo::timestamp 1795039807)
  (begin
    (define gerbil/core/contract~InterfaceInfo#_g107287_
      (##structure
       gx#syntax-quote::t
       'cast
       #f
       (gx#current-expander-context)
       '()))
    (begin
      (define gerbil/core/contract~InterfaceInfo#interface-info::t
        (make-class-type
         'gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-info
         (list gerbil/core/mop~MOP-2#runtime-type-info::t)
         '(namespace
           interface-mixin
           interface-methods
           interface-precedence-list
           interface-descriptor
           instance-constructor
           instance-try-constructor
           instance-predicate
           instance-satisfies-predicate
           implementation-methods
           unchecked-implementation-methods
           implementation-macros
           unchecked-implementation-macros)
         '()
         '#f))
      (define gerbil/core/contract~InterfaceInfo#interface-info?
        (make-class-predicate
         gerbil/core/contract~InterfaceInfo#interface-info::t))
      (define gerbil/core/contract~InterfaceInfo#make-interface-info
        (lambda _%$args53816%_
          (apply make-instance
                 gerbil/core/contract~InterfaceInfo#interface-info::t
                 _%$args53816%_)))
      (define gerbil/core/contract~InterfaceInfo#interface-info-namespace
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'namespace))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-mixin
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-mixin))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-methods
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-methods))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-precedence-list
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-precedence-list))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-descriptor
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-descriptor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-constructor
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-constructor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-try-constructor
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-try-constructor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-predicate
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-predicate))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-satisfies-predicate
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-satisfies-predicate))
      (define gerbil/core/contract~InterfaceInfo#interface-info-implementation-methods
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#interface-info-unchecked-implementation-methods
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#interface-info-implementation-macros
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#interface-info-unchecked-implementation-macros
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#interface-info-id
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'id))
      (define gerbil/core/contract~InterfaceInfo#interface-info-name
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'name))
      (define gerbil/core/contract~InterfaceInfo#interface-info-type-descriptor
        (make-class-slot-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'type-descriptor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-namespace-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'namespace))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-mixin-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-mixin))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-methods-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-methods))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-precedence-list-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-precedence-list))
      (define gerbil/core/contract~InterfaceInfo#interface-info-interface-descriptor-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-descriptor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-constructor-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-constructor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-try-constructor-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-try-constructor))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-predicate-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-predicate))
      (define gerbil/core/contract~InterfaceInfo#interface-info-instance-satisfies-predicate-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-satisfies-predicate))
      (define gerbil/core/contract~InterfaceInfo#interface-info-implementation-methods-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#interface-info-unchecked-implementation-methods-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#interface-info-implementation-macros-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#interface-info-unchecked-implementation-macros-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#interface-info-id-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'id))
      (define gerbil/core/contract~InterfaceInfo#interface-info-name-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'name))
      (define gerbil/core/contract~InterfaceInfo#interface-info-type-descriptor-set!
        (make-class-slot-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'type-descriptor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-namespace
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'namespace))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-mixin
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-mixin))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-methods
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-methods))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-precedence-list
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-precedence-list))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-descriptor
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-descriptor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-constructor
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-constructor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-try-constructor
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-try-constructor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-predicate
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-predicate))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-satisfies-predicate
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-satisfies-predicate))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-implementation-methods
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-unchecked-implementation-methods
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-implementation-macros
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-unchecked-implementation-macros
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-id
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'id))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-name
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'name))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-type-descriptor
        (make-class-slot-unchecked-accessor
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'type-descriptor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-namespace-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'namespace))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-mixin-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-mixin))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-methods-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-methods))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-precedence-list-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-precedence-list))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-interface-descriptor-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'interface-descriptor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-constructor-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-constructor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-try-constructor-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-try-constructor))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-predicate-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-predicate))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-instance-satisfies-predicate-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'instance-satisfies-predicate))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-implementation-methods-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-unchecked-implementation-methods-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-methods))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-implementation-macros-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-unchecked-implementation-macros-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'unchecked-implementation-macros))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-id-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'id))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-name-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'name))
      (define gerbil/core/contract~InterfaceInfo#&interface-info-type-descriptor-set!
        (make-class-slot-unchecked-mutator
         gerbil/core/contract~InterfaceInfo#interface-info::t
         'type-descriptor))
      (define gerbil/core/contract~InterfaceInfo#interface-info::apply-macro-expander
        (let* ((_%$%g5365053657%_
                (lambda (_%$%g5365153654%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5365153654%_)))
               (_%$%g5364953813%_
                (lambda (_%$%g5365153660%_)
                  (lambda (_%self53671%_ _%stx53672%_)
                    (let* ((_%__stx100082100083%_ _%stx53672%_)
                           (_%$%g5367553688%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid match target"
                               _%__stx100082100083%_))))
                      (let ((_%__kont100084100085%_
                             (lambda (_%$%g5367753746%_)
                               (let* ((_%$%g5375753771%_
                                       (lambda (_%$%g5375853768%_)
                                         (gx#raise-syntax-error
                                          '#f
                                          '"Bad syntax; invalid match target"
                                          _%$%g5375853768%_)))
                                      (_%$%g5375653807%_
                                       (lambda (_%$%g5375853774%_)
                                         (if (gx#stx-pair? _%$%g5375853774%_)
                                             (let ((_%$%e5376153776%_
                                                    (gx#syntax-e
                                                     _%$%g5375853774%_)))
                                               (let ((_%$%hd5376253779%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e5376153776%_)))
                                                     (_%$%tl5376353781%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e5376153776%_))))
                                                 (if (gx#stx-pair?
                                                      _%$%tl5376353781%_)
                                                     (let ((_%$%e5376453784%_
                                                            (gx#syntax-e
                                                             _%$%tl5376353781%_)))
                                                       (let ((_%$%hd5376553787%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%e5376453784%_)))
                     (_%$%tl5376653789%_
                      (let () (declare (not safe)) (##cdr _%$%e5376453784%_))))
                 (if (gx#stx-null? _%$%tl5376653789%_)
                     (cons (gx#datum->syntax '#f 'begin-annotation)
                           (cons (cons (gx#datum->syntax '#f '@type)
                                       (cons _%$%hd5376553787%_ '()))
                                 (cons (cons _%$%g5365153660%_
                                             (cons _%$%hd5376253779%_
                                                   (cons _%$%g5367753746%_
                                                         '())))
                                       '())))
                     (_%$%g5375753771%_ _%$%g5375853774%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g5375753771%_
                                                      _%$%g5375853774%_))))
                                             (_%$%g5375753771%_
                                              _%$%g5375853774%_)))))
                                 (_%$%g5375653807%_
                                  (list (let ((__obj107186 _%self53671%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (##structure-direct-instance-of?
                                                 __obj107186
                                                 'gerbil/core/contract~InterfaceInfo#interface-info::t))
                                              (let ()
                                                (declare (not safe))
                                                (##unchecked-structure-ref
                                                 __obj107186
                                                 '8
                                                 '#f
                                                 '#f))
                                              (class-slot-ref
                                               gerbil/core/contract~InterfaceInfo#interface-info::t
                                               __obj107186
                                               'interface-descriptor)))
                                        (let ((__obj107187 _%self53671%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (##structure-direct-instance-of?
                                                 __obj107187
                                                 'gerbil/core#runtime-type-info::t))
                                              (let ()
                                                (declare (not safe))
                                                (##unchecked-structure-ref
                                                 __obj107187
                                                 '3
                                                 '#f
                                                 '#f))
                                              (class-slot-ref
                                               gerbil/core/mop~MOP-2#runtime-type-info::t
                                               __obj107187
                                               'type-descriptor))))))))
                            (_%__kont100086100087%_
                             (lambda ()
                               (let* ((_%$%g5369553702%_
                                       (lambda (_%$%g5369653699%_)
                                         (gx#raise-syntax-error
                                          '#f
                                          '"Bad syntax; invalid match target"
                                          _%$%g5369653699%_)))
                                      (_%$%g5369453722%_
                                       (lambda (_%$%g5369653705%_)
                                         _%$%g5369653705%_)))
                                 (_%$%g5369453722%_
                                  (let ((__obj107188 _%self53671%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##structure-direct-instance-of?
                                           __obj107188
                                           'gerbil/core/contract~InterfaceInfo#interface-info::t))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           __obj107188
                                           '8
                                           '#f
                                           '#f))
                                        (class-slot-ref
                                         gerbil/core/contract~InterfaceInfo#interface-info::t
                                         __obj107188
                                         'interface-descriptor))))))))
                        (let ((_%$%g5367453725%_
                               (lambda ()
                                 (if (gx#identifier? _%stx53672%_)
                                     (_%__kont100086100087%_)
                                     (_%$%g5367553688%_)))))
                          (if (gx#stx-pair? _%__stx100082100083%_)
                              (let ((_%$%e5367853730%_
                                     (gx#syntax-e _%__stx100082100083%_)))
                                (let ((_%$%tl5368053735%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5367853730%_)))
                                      (_%$%hd5367953733%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5367853730%_))))
                                  (if (gx#stx-pair? _%$%tl5368053735%_)
                                      (let ((_%$%e5368153738%_
                                             (gx#syntax-e _%$%tl5368053735%_)))
                                        (let ((_%$%tl5368353743%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5368153738%_)))
                                              (_%$%hd5368253741%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5368153738%_))))
                                          (if (gx#stx-null? _%$%tl5368353743%_)
                                              (_%__kont100084100085%_
                                               _%$%hd5368253741%_)
                                              (_%$%g5367453725%_))))
                                      (_%$%g5367453725%_))))
                              (_%$%g5367453725%_)))))))))
          (_%$%g5364953813%_ gerbil/core/contract~InterfaceInfo#_g107287_)))
      (bind-method!
       gerbil/core/contract~InterfaceInfo#interface-info::t
       'apply-macro-expander
       gerbil/core/contract~InterfaceInfo#interface-info::apply-macro-expander
       '#f)
      (define gerbil/core/contract~InterfaceInfo#interface-identifier->precedence-list
        (lambda (_%id53526%_)
          (cons _%id53526%_
                (let ((__obj107189 (gx#syntax-local-value _%id53526%_)))
                  (if (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         __obj107189
                         'gerbil/core/contract~InterfaceInfo#interface-info::t))
                      (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref __obj107189 '7 '#f '#f))
                      (class-slot-ref
                       gerbil/core/contract~InterfaceInfo#interface-info::t
                       __obj107189
                       'interface-precedence-list))))))
      (define gerbil/core/contract~InterfaceInfo#interface-mixin->precedence-list
        (lambda (_%lst53521%_)
          (let ((_g107288_
                 (c4-linearize
                  '()
                  _%lst53521%_
                  'get-precedence-list:
                  gerbil/core/contract~InterfaceInfo#interface-identifier->precedence-list
                  'struct:
                  false
                  'eq:
                  gx#free-identifier=?
                  'get-name:
                  gx#stx-e)))
            (begin
              (let ((_g107289_
                     (let ()
                       (declare (not safe))
                       (if (##values? _g107288_)
                           (##values-length _g107288_)
                           1))))
                (if (not (let () (declare (not safe)) (##fx= _g107289_ 2)))
                    (error "Context expects 2 values" _g107289_)))
              (let ((_%linearized53523%_
                     (let () (declare (not safe)) (##values-ref _g107288_ 0)))
                    (_%_53524%_
                     (let () (declare (not safe)) (##values-ref _g107288_ 1))))
                _%linearized53523%_)))))
      (define gerbil/core/contract~InterfaceInfo#interface-info-method-signature
        (lambda (_%info53511%_ _%method53512%_)
          (let ((_%$%sig5351353517%_
                 (find (lambda (_%sig53515%_)
                         (eq? _%method53512%_ (car _%sig53515%_)))
                       (let ((__obj107190 _%info53511%_))
                         (if (let ()
                               (declare (not safe))
                               (##structure-direct-instance-of?
                                __obj107190
                                'gerbil/core/contract~InterfaceInfo#interface-info::t))
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                __obj107190
                                '6
                                '#f
                                '#f))
                             (class-slot-ref
                              gerbil/core/contract~InterfaceInfo#interface-info::t
                              __obj107190
                              'interface-methods))))))
            (if _%$%sig5351353517%_
                (let ((_%sig53519%_ _%$%sig5351353517%_)) (cdr _%sig53519%_))
                '#f))))
      (define gerbil/core/contract~InterfaceInfo#interface-info-method-offset
        (lambda (_%info53468%_ _%method53469%_)
          (let ((_%methods53471%_
                 (let ((__obj107191 _%info53468%_))
                   (if (let ()
                         (declare (not safe))
                         (##structure-direct-instance-of?
                          __obj107191
                          'gerbil/core/contract~InterfaceInfo#interface-info::t))
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref __obj107191 '6 '#f '#f))
                       (class-slot-ref
                        gerbil/core/contract~InterfaceInfo#interface-info::t
                        __obj107191
                        'interface-methods)))))
            (let _%loop53473%_ ((_%rest53475%_ _%methods53471%_)
                                (_%index53476%_ '2))
              (let* ((_%$%rest5347753485%_ _%rest53475%_)
                     (_%$%else5347953493%_ (lambda () '#f))
                     (_%$%K5348153499%_
                      (lambda (_%rest53496%_ _%method-sig53497%_)
                        (if (eq? _%method53469%_ (car _%method-sig53497%_))
                            _%index53476%_
                            (_%loop53473%_
                             _%rest53496%_
                             (let ()
                               (declare (not safe))
                               (##fx+ _%index53476%_ '1)))))))
                (if (pair? _%$%rest5347753485%_)
                    (let ((_%$%hd5348253502%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest5347753485%_)))
                          (_%$%tl5348353504%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest5347753485%_))))
                      (let* ((_%method-sig53507%_ _%$%hd5348253502%_)
                             (_%rest53509%_ _%$%tl5348353504%_))
                        (_%$%K5348153499%_ _%rest53509%_ _%method-sig53507%_)))
                    (_%$%else5347953493%_)))))))
      (define gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__%
        (lambda (_%stx53450%_ _%is?53451%_)
          (if (gx#identifier? _%stx53450%_)
              (let ((_%$%e5345253454%_
                     (gx#syntax-local-value _%stx53450%_ false)))
                (if _%$%e5345253454%_
                    (let ((_%e53456%_ _%$%e5345253454%_))
                      (if (let ()
                            (declare (not safe))
                            (class-instance?
                             gerbil/core/contract~InterfaceInfo#interface-info::t
                             _%e53456%_))
                          (_%is?53451%_ _%e53456%_)
                          '#f))
                    '#f))
              '#f)))
      (define gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__0
        (lambda (_%stx53461%_)
          (let ((_%is?53463%_ true))
            (gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__%
             _%stx53461%_
             _%is?53463%_))))
      (define gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?
        (lambda _g107290_
          (let ((_g107291_ (let () (declare (not safe)) (##length _g107290_))))
            (cond ((let () (declare (not safe)) (##fx= _g107291_ 1))
                   (apply gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__0
                          _g107290_))
                  ((let () (declare (not safe)) (##fx= _g107291_ 2))
                   (apply gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?__%
                          _g107290_))
                  (else
                   (##raise-wrong-number-of-arguments-exception
                    gerbil/core/contract~InterfaceInfo#syntax-local-interface-info?
                    _g107290_)))))))))
