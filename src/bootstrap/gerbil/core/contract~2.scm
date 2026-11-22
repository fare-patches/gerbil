(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gerbil/core/contract~TypeReference[1]#_g107372_|
    (##structure
     gx#syntax-quote::t
     'Maybe
     #f
     (gx#current-expander-context)
     '()))
  (begin
    (define |gerbil/core/contract~TypeReference[:0:]#Maybe|
      (lambda (_%$stx53823%_)
        (let ((_%$%g5382653833%_
               (lambda (_%$%g5382753829%_)
                 (gx#raise-syntax-error
                  '#f
                  '"Bad syntax; invalid match target"
                  _%$%g5382753829%_))))
          (_%$%g5382653833%_ _%$stx53823%_))))
    (define |gerbil/core/contract~TypeReference[1]#type-reference::t|
      (make-class-type
       'gerbil/core/contract~TypeReference#type-reference::t
       'type-reference
       (list)
       '(identifier)
       '()
       '#f))
    (define |gerbil/core/contract~TypeReference[1]#type-reference?|
      (make-class-predicate
       |gerbil/core/contract~TypeReference[1]#type-reference::t|))
    (define |gerbil/core/contract~TypeReference[1]#make-type-reference|
      (lambda _%$args54055%_
        (apply make-instance
               |gerbil/core/contract~TypeReference[1]#type-reference::t|
               _%$args54055%_)))
    (define |gerbil/core/contract~TypeReference[1]#type-reference-identifier|
      (make-class-slot-accessor
       |gerbil/core/contract~TypeReference[1]#type-reference::t|
       'identifier))
    (define |gerbil/core/contract~TypeReference[1]#type-reference-identifier-set!|
      (make-class-slot-mutator
       |gerbil/core/contract~TypeReference[1]#type-reference::t|
       'identifier))
    (define |gerbil/core/contract~TypeReference[1]#&type-reference-identifier|
      (make-class-slot-unchecked-accessor
       |gerbil/core/contract~TypeReference[1]#type-reference::t|
       'identifier))
    (define |gerbil/core/contract~TypeReference[1]#&type-reference-identifier-set!|
      (make-class-slot-unchecked-mutator
       |gerbil/core/contract~TypeReference[1]#type-reference::t|
       'identifier))
    (define |gerbil/core/contract~TypeReference[1]#type-identifier?|
      (lambda (_%id54037%_)
        (if (gx#identifier? _%id54037%_)
            (let ((_%$%t5403954041%_
                   (gx#syntax-local-value _%id54037%_ false)))
              (if _%$%t5403954041%_
                  (let* ((_%t54044%_ _%$%t5403954041%_)
                         (_%$e54047%_
                          (let ()
                            (declare (not safe))
                            (class-instance?
                             gerbil/core/mop~MOP-2#class-type-info::t
                             _%t54044%_))))
                    (if _%$e54047%_
                        _%$e54047%_
                        (let ((_%$e54051%_
                               (let ()
                                 (declare (not safe))
                                 (class-instance?
                                  gerbil/core/contract~InterfaceInfo#interface-info::t
                                  _%t54044%_))))
                          (if _%$e54051%_
                              _%$e54051%_
                              (let ()
                                (declare (not safe))
                                (class-instance?
                                 |gerbil/core/contract~TypeReference[1]#type-reference::t|
                                 _%t54044%_))))))
                  '#f))
            '#f)))
    (define |gerbil/core/contract~TypeReference[1]#resolve-type|
      (lambda (_%stx54017%_ _%id54019%_)
        (let _%loop54021%_ ((_%t54024%_
                             (gx#syntax-local-value _%id54019%_ false)))
          (if (let ()
                (declare (not safe))
                (class-instance?
                 gerbil/core/mop~MOP-2#class-type-info::t
                 _%t54024%_))
              _%t54024%_
              (if (let ()
                    (declare (not safe))
                    (class-instance?
                     gerbil/core/contract~InterfaceInfo#interface-info::t
                     _%t54024%_))
                  _%t54024%_
                  (if (let ()
                        (declare (not safe))
                        (class-instance?
                         |gerbil/core/contract~TypeReference[1]#type-reference::t|
                         _%t54024%_))
                      (_%loop54021%_
                       (gx#syntax-local-value
                        (let ((__obj107193 _%t54024%_))
                          (if (let ()
                                (declare (not safe))
                                (##structure-direct-instance-of?
                                 __obj107193
                                 'gerbil/core/contract~TypeReference#type-reference::t))
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 __obj107193
                                 '1
                                 '#f
                                 '#f))
                              (unchecked-slot-ref __obj107193 'identifier)))
                        false))
                      (if _%t54024%_
                          (gx#raise-syntax-error
                           '#f
                           '"unexpected type; expected class, interface or type reference"
                           _%stx54017%_
                           _%id54019%_
                           _%t54024%_)
                          (gx#raise-syntax-error
                           '#f
                           '"unresolved type"
                           _%stx54017%_
                           _%id54019%_))))))))
    (define |gerbil/core/contract~TypeReference[1]#resolve-type->identifier|
      (lambda (_%stx53993%_ _%id53995%_)
        (let _%loop53997%_ ((_%id54000%_ _%id53995%_)
                            (_%t54002%_
                             (gx#syntax-local-value _%id53995%_ false)))
          (if (let ()
                (declare (not safe))
                (class-instance?
                 gerbil/core/mop~MOP-2#class-type-info::t
                 _%t54002%_))
              _%id54000%_
              (if (let ()
                    (declare (not safe))
                    (class-instance?
                     gerbil/core/contract~InterfaceInfo#interface-info::t
                     _%t54002%_))
                  _%id54000%_
                  (if (let ()
                        (declare (not safe))
                        (class-instance?
                         |gerbil/core/contract~TypeReference[1]#type-reference::t|
                         _%t54002%_))
                      (let ((_%id54010%_
                             (let ((__obj107194 _%t54002%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-direct-instance-of?
                                      __obj107194
                                      'gerbil/core/contract~TypeReference#type-reference::t))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      __obj107194
                                      '1
                                      '#f
                                      '#f))
                                   (unchecked-slot-ref
                                    __obj107194
                                    'identifier)))))
                        (_%loop53997%_
                         _%id54010%_
                         (gx#syntax-local-value _%id54010%_ false)))
                      (if _%t54002%_
                          (gx#raise-syntax-error
                           '#f
                           '"unexpected type; expected class, interface or type reference"
                           _%stx53993%_
                           _%id54000%_
                           _%t54002%_)
                          (gx#raise-syntax-error
                           '#f
                           '"unresolved type"
                           _%stx53993%_
                           _%id54000%_))))))))
    (define |gerbil/core/contract~TypeReference[1]#resolve-type->type-descriptor|
      (lambda (_%stx53980%_ _%id53982%_)
        (let ((_%t53984%_
               (|gerbil/core/contract~TypeReference[1]#resolve-type|
                _%stx53980%_
                _%id53982%_)))
          (if (let ()
                (declare (not safe))
                (class-instance?
                 gerbil/core/mop~MOP-2#class-type-info::t
                 _%t53984%_))
              (let ((__obj107196 _%t53984%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-direct-instance-of?
                       __obj107196
                       'gerbil/core#class-type-info::t))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-ref __obj107196 '4 '#f '#f))
                    (unchecked-slot-ref __obj107196 'type-descriptor)))
              (if (let ()
                    (declare (not safe))
                    (class-instance?
                     gerbil/core/contract~InterfaceInfo#interface-info::t
                     _%t53984%_))
                  (let ((__obj107195 _%t53984%_))
                    (if (let ()
                          (declare (not safe))
                          (##structure-direct-instance-of?
                           __obj107195
                           'gerbil/core#runtime-type-info::t))
                        (let ()
                          (declare (not safe))
                          (##unchecked-structure-ref __obj107195 '3 '#f '#f))
                        (unchecked-slot-ref __obj107195 'type-descriptor)))
                  (gx#raise-syntax-error
                   '#f
                   '"unexpected type; expected class, interface or type reference"
                   _%stx53980%_
                   _%id53982%_
                   _%t53984%_))))))
    (define |gerbil/core/contract~TypeReference[1]#resolve-return-type|
      (lambda (_%stx53851%_ _%type53853%_)
        (let _%loop53855%_ ((_%type53858%_ _%type53853%_)
                            (_%maybe?53860%_ '#f))
          (let* ((_%__stx100106100107%_ _%type53858%_)
                 (_%$%g5386553883%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx100106100107%_))))
            (let ((_%__kont100109100110%_
                   (lambda (_%$%g5386753962%_)
                     (_%loop53855%_ _%$%g5386753962%_ '#t)))
                  (_%__kont100111100112%_
                   (lambda ()
                     (gx#raise-syntax-error
                      '#f
                      '"invalid Maybe return type; expected (Maybe Type)"
                      _%stx53851%_
                      _%type53858%_)))
                  (_%__kont100113100114%_
                   (lambda (_%$%g5387753901%_)
                     (if (|gerbil/core/contract~TypeReference[1]#type-identifier?|
                          _%$%g5387753901%_)
                         (values _%$%g5387753901%_ _%maybe?53860%_)
                         (gx#raise-syntax-error
                          '#f
                          '"invalid return type; expected class, interface or type reference"
                          _%stx53851%_
                          _%type53858%_))))
                  (_%__kont100115100116%_
                   (lambda ()
                     (gx#raise-syntax-error
                      '#f
                      '"invalid return type; expected type identifier or (Maybe Type)"
                      _%stx53851%_
                      _%type53858%_))))
              (let ((_%$%g5386353914%_
                     (lambda ()
                       (let ((_%$%g5387753901%_ _%__stx100106100107%_))
                         (if (gx#identifier? _%$%g5387753901%_)
                             (_%__kont100113100114%_ _%$%g5387753901%_)
                             (_%__kont100115100116%_))))))
                (if (gx#stx-pair? _%__stx100106100107%_)
                    (let ((_%$%e5386853942%_
                           (gx#syntax-e _%__stx100106100107%_)))
                      (let ((_%$%tl5387053949%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e5386853942%_)))
                            (_%$%hd5386953946%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e5386853942%_))))
                        (if (gx#identifier? _%$%hd5386953946%_)
                            (if (gx#free-identifier=?
                                 |gerbil/core/contract~TypeReference[1]#_g107372_|
                                 _%$%hd5386953946%_)
                                (if (gx#stx-pair? _%$%tl5387053949%_)
                                    (let ((_%$%e5387153952%_
                                           (gx#syntax-e _%$%tl5387053949%_)))
                                      (let ((_%$%tl5387353959%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e5387153952%_)))
                                            (_%$%hd5387253956%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e5387153952%_))))
                                        (if (gx#stx-null? _%$%tl5387353959%_)
                                            (_%__kont100109100110%_
                                             _%$%hd5387253956%_)
                                            (_%__kont100111100112%_))))
                                    (_%__kont100111100112%_))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g5386353914%_)))
                            (let ()
                              (declare (not safe))
                              (_%$%g5386353914%_)))))
                    (let () (declare (not safe)) (_%$%g5386353914%_)))))))))
    (define |gerbil/core/contract~TypeReference[1]#resolve-return-type->type-descriptor|
      (lambda (_%stx53838%_ _%type53840%_)
        (let ((_g107373_
               (|gerbil/core/contract~TypeReference[1]#resolve-return-type|
                _%stx53838%_
                _%type53840%_)))
          (begin
            (let ((_g107374_
                   (let ()
                     (declare (not safe))
                     (if (##values? _g107373_)
                         (##values-length _g107373_)
                         1))))
              (if (not (let () (declare (not safe)) (##fx= _g107374_ 2)))
                  (error "Context expects 2 values" _g107374_)))
            (let ((_%base53842%_
                   (let () (declare (not safe)) (##values-ref _g107373_ 0)))
                  (_%maybe?53844%_
                   (let () (declare (not safe)) (##values-ref _g107373_ 1))))
              (let ((_%descriptor53846%_
                     (|gerbil/core/contract~TypeReference[1]#resolve-type->type-descriptor|
                      _%stx53838%_
                      _%base53842%_)))
                (if _%maybe?53844%_
                    (cons 'nullable (cons _%descriptor53846%_ '()))
                    _%descriptor53846%_)))))))
    (define |gerbil/core/contract~TypeReference[:0:]#deftype|
      (lambda (_%$stx54060%_)
        (let* ((_%$%g5406454082%_
                (lambda (_%$%g5406554078%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%$%g5406554078%_)))
               (_%$%g5406354137%_
                (lambda (_%$%g5406554086%_)
                  (if (gx#stx-pair? _%$%g5406554086%_)
                      (let ((_%$%e5406854089%_
                             (gx#syntax-e _%$%g5406554086%_)))
                        (let ((_%$%hd5406954093%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e5406854089%_)))
                              (_%$%tl5407054096%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e5406854089%_))))
                          (if (gx#stx-pair? _%$%tl5407054096%_)
                              (let ((_%$%e5407154099%_
                                     (gx#syntax-e _%$%tl5407054096%_)))
                                (let ((_%$%hd5407254103%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e5407154099%_)))
                                      (_%$%tl5407354106%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e5407154099%_))))
                                  (if (gx#stx-pair? _%$%tl5407354106%_)
                                      (let ((_%$%e5407454109%_
                                             (gx#syntax-e _%$%tl5407354106%_)))
                                        (let ((_%$%hd5407554113%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e5407454109%_)))
                                              (_%$%tl5407654116%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e5407454109%_))))
                                          (if (gx#stx-null? _%$%tl5407654116%_)
                                              (if (and (gx#identifier?
                                                        _%$%hd5407254103%_)
                                                       (gx#identifier?
                                                        _%$%hd5407554113%_))
                                                  (cons (gx#datum->syntax
                                                         '#f
                                                         'defsyntax)
                                                        (cons _%$%hd5407254103%_
                                                              (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '#f
                                   'make-type-reference)
                                  (cons 'identifier:
                                        (cons (cons (gx#datum->syntax
                                                     '#f
                                                     'quote-syntax)
                                                    (cons _%$%hd5407554113%_
                                                          '()))
                                              '())))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g5406454082%_
                                                   _%$%g5406554086%_))
                                              (_%$%g5406454082%_
                                               _%$%g5406554086%_))))
                                      (_%$%g5406454082%_ _%$%g5406554086%_))))
                              (_%$%g5406454082%_ _%$%g5406554086%_))))
                      (_%$%g5406454082%_ _%$%g5406554086%_)))))
          (_%$%g5406354137%_ _%$stx54060%_))))))
