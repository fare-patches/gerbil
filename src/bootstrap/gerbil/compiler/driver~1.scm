(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(define |gxc[:0:]#with-driver-mutex|
  (lambda (_%$stx274310%_)
    (let* ((_%$%g274314274328%_
            (lambda (_%$%g274315274324%_)
              (let ()
                (declare (not safe))
                (gx#raise-syntax-error
                 '#f
                 '"Bad syntax; invalid match target"
                 _%$%g274315274324%_))))
           (_%$%g274313274370%_
            (lambda (_%$%g274315274332%_)
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%$%g274315274332%_))
                  (let ((_%$%e274317274335%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%$%g274315274332%_))))
                    (let ((_%$%hd274318274339%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e274317274335%_)))
                          (_%$%tl274319274342%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e274317274335%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl274319274342%_))
                          (let ((_%$%e274320274345%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%tl274319274342%_))))
                            (let ((_%$%hd274321274349%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e274320274345%_)))
                                  (_%$%tl274322274352%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e274320274345%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl274322274352%_))
                                  (cons (let ()
                                          (declare (not safe))
                                          (gx#datum->syntax__0 '#f 'with-lock))
                                        (cons (let ()
                                                (declare (not safe))
                                                (gx#datum->syntax__0
                                                 '#f
                                                 '+driver-mutex+))
                                              (cons (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#datum->syntax__0
                                                             '#f
                                                             'lambda))
                                                          (cons '()
                                                                (cons _%$%hd274321274349%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  (_%$%g274314274328%_ _%$%g274315274332%_))))
                          (_%$%g274314274328%_ _%$%g274315274332%_))))
                  (_%$%g274314274328%_ _%$%g274315274332%_)))))
      (_%$%g274313274370%_ _%$stx274310%_))))
