(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |[1]#_g129333_|
    (gx#core-deserialize-mark
     '(0
       ($%arg128437 . _%$%arg128437128508%_)
       ($%arg128436 . _%$%arg128436128494%_)
       (id . _%id128461%_)
       (arg . _%arg128524%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g129334_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g129333_|)))
  (define |[1]#_g129335_|
    (gx#core-deserialize-mark
     '(0 (new-value . _%new-value129191%_))
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g129336_|
    (##structure
     gx#syntax-quote::t
     '_%new-value129191%_
     #f
     (gx#current-expander-context)
     (list |[1]#_g129335_|)))
  (define |[1]#_g129338_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g129339_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g129338_|)))
  (define |[1]#_g129340_|
    (gx#core-deserialize-mark
     '(0
       ($%arg128558 . _%$%arg128558128628%_)
       (id . _%id128581%_)
       ($%arg128557 . _%$%arg128557128614%_)
       (arg . _%arg128644%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g129341_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g129340_|)))
  (define |[1]#_g129343_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g129344_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g129343_|)))
  (define |[1]#_g129345_|
    (gx#core-deserialize-mark
     '(0
       ($%arg128678 . _%$%arg128678128748%_)
       (id . _%id128701%_)
       ($%arg128677 . _%$%arg128677128734%_)
       (arg . _%arg128764%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g129346_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g129345_|)))
  (define |[1]#_g129348_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g129349_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g129348_|)))
  (define |[1]#_g129350_|
    (gx#core-deserialize-mark
     '(0
       (id . _%id128821%_)
       ($%arg128797 . _%$%arg128797128854%_)
       ($%arg128798 . _%$%arg128798128868%_)
       (arg . _%arg128884%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g129351_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g129350_|)))
  (define |[1]#_g129352_|
    (gx#core-deserialize-mark
     '(0 (new-value . _%new-value128941%_))
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g129353_|
    (##structure
     gx#syntax-quote::t
     '_%new-value128941%_
     #f
     (gx#current-expander-context)
     (list |[1]#_g129352_|)))
  (define |[1]#_g129355_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g129356_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g129355_|)))
  (begin
    (define |[:0:]#@build-manifest-set!|
      (lambda (_%$stx128418%_)
        (let* ((_%__stx129219129220%_ _%$stx128418%_)
               (_%$%g128423128444%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx129219129220%_))))
          (let ((_%__kont129222129223%_
                 (lambda (_%$%g128425128510%_)
                   (cons (gx#datum->syntax
                          |[1]#_g129334_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax
                                            |[1]#_g129336_|
                                            'new-value
                                            '#f
                                            '#f)
                                           '())
                                     (cons (let ((__tmp129337
                                                  (lambda (_%$%g128525128528%_
                                                           _%$%g128526128531%_)
                                                    (cons _%$%g128525128528%_
                                                          _%$%g128526128531%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp129337
                                              '()
                                              _%$%g128425128510%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g129339_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              |[1]#_g129336_|
                                                              'new-value
                                                              '#f
                                                              '#f)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':list) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__build-manifest-set!)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            |[1]#_g129336_|
                            'new-value
                            '#f
                            '#f)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont129226129227%_
                 (lambda (_%$%g128438128451%_)
                   (gx#datum->syntax '#f 'build-manifest-set!))))
            (let* ((_%$%g128422128463%_
                    (lambda ()
                      (let ((_%$%g128438128451%_ _%__stx129219129220%_))
                        (if (gx#identifier? _%$%g128438128451%_)
                            (_%__kont129226129227%_ _%$%g128438128451%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g128423128444%_))))))
                   (_%__match129242129243%_
                    (lambda (_%$%e128426128470%_
                             _%$%hd128427128474%_
                             _%$%tl128428128477%_
                             _%__splice129224129225%_
                             _%$%target128429128480%_
                             _%$%tl128431128483%_)
                      (letrec ((_%$%loop128432128486%_
                                (lambda (_%$%hd128430128490%_
                                         _%$%arg128436128493%_)
                                  (if (gx#stx-pair? _%$%hd128430128490%_)
                                      (let ((_%$%e128433128496%_
                                             (gx#syntax-e
                                              _%$%hd128430128490%_)))
                                        (let ((_%$%lp-tl128435128503%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e128433128496%_)))
                                              (_%$%lp-hd128434128500%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e128433128496%_))))
                                          (_%$%loop128432128486%_
                                           _%$%lp-tl128435128503%_
                                           (cons _%$%lp-hd128434128500%_
                                                 _%$%arg128436128493%_))))
                                      (let ((_%$%arg128437128506%_
                                             (reverse _%$%arg128436128493%_)))
                                        (_%__kont129222129223%_
                                         _%$%arg128437128506%_))))))
                        (_%$%loop128432128486%_
                         _%$%target128429128480%_
                         '())))))
              (if (gx#stx-pair? _%__stx129219129220%_)
                  (let ((_%$%e128426128470%_
                         (gx#syntax-e _%__stx129219129220%_)))
                    (let ((_%$%tl128428128477%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e128426128470%_)))
                          (_%$%hd128427128474%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e128426128470%_))))
                      (if (gx#stx-pair/null? _%$%tl128428128477%_)
                          (let ((_%__splice129224129225%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl128428128477%_
                                  '0)))
                            (let ((_%$%tl128431128483%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129224129225%_
                                      '1)))
                                  (_%$%target128429128480%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129224129225%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl128431128483%_)
                                  (_%__match129242129243%_
                                   _%$%e128426128470%_
                                   _%$%hd128427128474%_
                                   _%$%tl128428128477%_
                                   _%__splice129224129225%_
                                   _%$%target128429128480%_
                                   _%$%tl128431128483%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g128422128463%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g128422128463%_)))))
                  (let () (declare (not safe)) (_%$%g128422128463%_))))))))
    (define |[:0:]#@display-build-manifest|
      (lambda (_%$stx128539%_)
        (let* ((_%__stx129245129246%_ _%$stx128539%_)
               (_%$%g128544128565%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx129245129246%_))))
          (let ((_%__kont129248129249%_
                 (lambda (_%$%g128546128630%_)
                   (cons (gx#datum->syntax
                          |[1]#_g129341_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (cons (gx#datum->syntax
                                                  '#f
                                                  'manifest)
                                                 (cons (gx#datum->syntax
                                                        '#f
                                                        '__build-manifest)
                                                       '()))
                                           (cons (cons (gx#datum->syntax
                                                        '#f
                                                        'port)
                                                       (cons (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'current-output-port)
                           '())
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '()))
                                     (cons (let ((__tmp129342
                                                  (lambda (_%$%g128645128648%_
                                                           _%$%g128646128651%_)
                                                    (cons _%$%g128645128648%_
                                                          _%$%g128646128651%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp129342
                                              '()
                                              _%$%g128546128630%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g129344_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'manifest)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':list) '())))
               (cons (cons (gx#datum->syntax '#f 'port)
                           (cons (gx#datum->syntax '#f ':)
                                 (cons (gx#datum->syntax '#f ':port) '())))
                     '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__display-build-manifest)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'manifest)
                           (cons (gx#datum->syntax '#f 'port) '())))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont129252129253%_
                 (lambda (_%$%g128559128572%_)
                   (gx#datum->syntax '#f 'display-build-manifest))))
            (let* ((_%$%g128543128583%_
                    (lambda ()
                      (let ((_%$%g128559128572%_ _%__stx129245129246%_))
                        (if (gx#identifier? _%$%g128559128572%_)
                            (_%__kont129252129253%_ _%$%g128559128572%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g128544128565%_))))))
                   (_%__match129268129269%_
                    (lambda (_%$%e128547128590%_
                             _%$%hd128548128594%_
                             _%$%tl128549128597%_
                             _%__splice129250129251%_
                             _%$%target128550128600%_
                             _%$%tl128552128603%_)
                      (letrec ((_%$%loop128553128606%_
                                (lambda (_%$%hd128551128610%_
                                         _%$%arg128557128613%_)
                                  (if (gx#stx-pair? _%$%hd128551128610%_)
                                      (let ((_%$%e128554128616%_
                                             (gx#syntax-e
                                              _%$%hd128551128610%_)))
                                        (let ((_%$%lp-tl128556128623%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e128554128616%_)))
                                              (_%$%lp-hd128555128620%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e128554128616%_))))
                                          (_%$%loop128553128606%_
                                           _%$%lp-tl128556128623%_
                                           (cons _%$%lp-hd128555128620%_
                                                 _%$%arg128557128613%_))))
                                      (let ((_%$%arg128558128626%_
                                             (reverse _%$%arg128557128613%_)))
                                        (_%__kont129248129249%_
                                         _%$%arg128558128626%_))))))
                        (_%$%loop128553128606%_
                         _%$%target128550128600%_
                         '())))))
              (if (gx#stx-pair? _%__stx129245129246%_)
                  (let ((_%$%e128547128590%_
                         (gx#syntax-e _%__stx129245129246%_)))
                    (let ((_%$%tl128549128597%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e128547128590%_)))
                          (_%$%hd128548128594%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e128547128590%_))))
                      (if (gx#stx-pair/null? _%$%tl128549128597%_)
                          (let ((_%__splice129250129251%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl128549128597%_
                                  '0)))
                            (let ((_%$%tl128552128603%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129250129251%_
                                      '1)))
                                  (_%$%target128550128600%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129250129251%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl128552128603%_)
                                  (_%__match129268129269%_
                                   _%$%e128547128590%_
                                   _%$%hd128548128594%_
                                   _%$%tl128549128597%_
                                   _%__splice129250129251%_
                                   _%$%target128550128600%_
                                   _%$%tl128552128603%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g128543128583%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g128543128583%_)))))
                  (let () (declare (not safe)) (_%$%g128543128583%_))))))))
    (define |[:0:]#@build-manifest-string|
      (lambda (_%$stx128659%_)
        (let* ((_%__stx129271129272%_ _%$stx128659%_)
               (_%$%g128664128685%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx129271129272%_))))
          (let ((_%__kont129274129275%_
                 (lambda (_%$%g128666128750%_)
                   (cons (gx#datum->syntax
                          |[1]#_g129346_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (cons (gx#datum->syntax
                                                  '#f
                                                  'manifest)
                                                 (cons (gx#datum->syntax
                                                        '#f
                                                        '__build-manifest)
                                                       '()))
                                           '())
                                     (cons (let ((__tmp129347
                                                  (lambda (_%$%g128765128768%_
                                                           _%$%g128766128771%_)
                                                    (cons _%$%g128765128768%_
                                                          _%$%g128766128771%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp129347
                                              '()
                                              _%$%g128666128750%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g129349_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'manifest)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':list) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__build-manifest-string)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'manifest)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont129278129279%_
                 (lambda (_%$%g128679128692%_)
                   (gx#datum->syntax '#f 'build-manifest-string))))
            (let* ((_%$%g128663128703%_
                    (lambda ()
                      (let ((_%$%g128679128692%_ _%__stx129271129272%_))
                        (if (gx#identifier? _%$%g128679128692%_)
                            (_%__kont129278129279%_ _%$%g128679128692%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g128664128685%_))))))
                   (_%__match129294129295%_
                    (lambda (_%$%e128667128710%_
                             _%$%hd128668128714%_
                             _%$%tl128669128717%_
                             _%__splice129276129277%_
                             _%$%target128670128720%_
                             _%$%tl128672128723%_)
                      (letrec ((_%$%loop128673128726%_
                                (lambda (_%$%hd128671128730%_
                                         _%$%arg128677128733%_)
                                  (if (gx#stx-pair? _%$%hd128671128730%_)
                                      (let ((_%$%e128674128736%_
                                             (gx#syntax-e
                                              _%$%hd128671128730%_)))
                                        (let ((_%$%lp-tl128676128743%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e128674128736%_)))
                                              (_%$%lp-hd128675128740%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e128674128736%_))))
                                          (_%$%loop128673128726%_
                                           _%$%lp-tl128676128743%_
                                           (cons _%$%lp-hd128675128740%_
                                                 _%$%arg128677128733%_))))
                                      (let ((_%$%arg128678128746%_
                                             (reverse _%$%arg128677128733%_)))
                                        (_%__kont129274129275%_
                                         _%$%arg128678128746%_))))))
                        (_%$%loop128673128726%_
                         _%$%target128670128720%_
                         '())))))
              (if (gx#stx-pair? _%__stx129271129272%_)
                  (let ((_%$%e128667128710%_
                         (gx#syntax-e _%__stx129271129272%_)))
                    (let ((_%$%tl128669128717%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e128667128710%_)))
                          (_%$%hd128668128714%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e128667128710%_))))
                      (if (gx#stx-pair/null? _%$%tl128669128717%_)
                          (let ((_%__splice129276129277%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl128669128717%_
                                  '0)))
                            (let ((_%$%tl128672128723%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129276129277%_
                                      '1)))
                                  (_%$%target128670128720%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129276129277%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl128672128723%_)
                                  (_%__match129294129295%_
                                   _%$%e128667128710%_
                                   _%$%hd128668128714%_
                                   _%$%tl128669128717%_
                                   _%__splice129276129277%_
                                   _%$%target128670128720%_
                                   _%$%tl128672128723%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g128663128703%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g128663128703%_)))))
                  (let () (declare (not safe)) (_%$%g128663128703%_))))))))
    (define |[:0:]#@gerbil-greeting-set!|
      (lambda (_%$stx128779%_)
        (let* ((_%__stx129297129298%_ _%$stx128779%_)
               (_%$%g128784128805%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx129297129298%_))))
          (let ((_%__kont129300129301%_
                 (lambda (_%$%g128786128870%_)
                   (cons (gx#datum->syntax
                          |[1]#_g129351_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax
                                            |[1]#_g129353_|
                                            'new-value
                                            '#f
                                            '#f)
                                           '())
                                     (cons (let ((__tmp129354
                                                  (lambda (_%$%g128885128888%_
                                                           _%$%g128886128891%_)
                                                    (cons _%$%g128885128888%_
                                                          _%$%g128886128891%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp129354
                                              '()
                                              _%$%g128786128870%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g129356_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              |[1]#_g129353_|
                                                              'new-value
                                                              '#f
                                                              '#f)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':string) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__gerbil-greeting-set!)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            |[1]#_g129353_|
                            'new-value
                            '#f
                            '#f)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont129304129305%_
                 (lambda (_%$%g128799128812%_)
                   (gx#datum->syntax '#f 'gerbil-greeting-set!))))
            (let* ((_%$%g128783128823%_
                    (lambda ()
                      (let ((_%$%g128799128812%_ _%__stx129297129298%_))
                        (if (gx#identifier? _%$%g128799128812%_)
                            (_%__kont129304129305%_ _%$%g128799128812%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g128784128805%_))))))
                   (_%__match129320129321%_
                    (lambda (_%$%e128787128830%_
                             _%$%hd128788128834%_
                             _%$%tl128789128837%_
                             _%__splice129302129303%_
                             _%$%target128790128840%_
                             _%$%tl128792128843%_)
                      (letrec ((_%$%loop128793128846%_
                                (lambda (_%$%hd128791128850%_
                                         _%$%arg128797128853%_)
                                  (if (gx#stx-pair? _%$%hd128791128850%_)
                                      (let ((_%$%e128794128856%_
                                             (gx#syntax-e
                                              _%$%hd128791128850%_)))
                                        (let ((_%$%lp-tl128796128863%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e128794128856%_)))
                                              (_%$%lp-hd128795128860%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e128794128856%_))))
                                          (_%$%loop128793128846%_
                                           _%$%lp-tl128796128863%_
                                           (cons _%$%lp-hd128795128860%_
                                                 _%$%arg128797128853%_))))
                                      (let ((_%$%arg128798128866%_
                                             (reverse _%$%arg128797128853%_)))
                                        (_%__kont129300129301%_
                                         _%$%arg128798128866%_))))))
                        (_%$%loop128793128846%_
                         _%$%target128790128840%_
                         '())))))
              (if (gx#stx-pair? _%__stx129297129298%_)
                  (let ((_%$%e128787128830%_
                         (gx#syntax-e _%__stx129297129298%_)))
                    (let ((_%$%tl128789128837%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e128787128830%_)))
                          (_%$%hd128788128834%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e128787128830%_))))
                      (if (gx#stx-pair/null? _%$%tl128789128837%_)
                          (let ((_%__splice129302129303%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl128789128837%_
                                  '0)))
                            (let ((_%$%tl128792128843%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129302129303%_
                                      '1)))
                                  (_%$%target128790128840%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice129302129303%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl128792128843%_)
                                  (_%__match129320129321%_
                                   _%$%e128787128830%_
                                   _%$%hd128788128834%_
                                   _%$%tl128789128837%_
                                   _%__splice129302129303%_
                                   _%$%target128790128840%_
                                   _%$%tl128792128843%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g128783128823%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g128783128823%_)))))
                  (let () (declare (not safe)) (_%$%g128783128823%_))))))))))
