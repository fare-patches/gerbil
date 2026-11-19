(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gxc[1]#_g282910_|
    (##structure
     gx#syntax-quote::t
     '@list
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282917_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282919_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282921_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282923_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282925_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282937_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282939_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282941_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282943_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g282945_|
    (##structure
     gx#syntax-quote::t
     'quote
     #f
     (gx#current-expander-context)
     '()))
  (begin
    (define |gxc[:0:]#declare-type|
      (lambda (_%$stx276368%_)
        (let* ((_%$%g276372276390%_
                (lambda (_%$%g276373276386%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g276373276386%_))))
               (_%$%g276371276445%_
                (lambda (_%$%g276373276394%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g276373276394%_))
                      (let ((_%$%e276376276397%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g276373276394%_))))
                        (let ((_%$%hd276377276401%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e276376276397%_)))
                              (_%$%tl276378276404%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e276376276397%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl276378276404%_))
                              (let ((_%$%e276379276407%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl276378276404%_))))
                                (let ((_%$%hd276380276411%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e276379276407%_)))
                                      (_%$%tl276381276414%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e276379276407%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl276381276414%_))
                                      (let ((_%$%e276382276417%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl276381276414%_))))
                                        (let ((_%$%hd276383276421%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e276382276417%_)))
                                              (_%$%tl276384276424%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e276382276417%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl276384276424%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#identifier?
                                                     _%$%hd276380276411%_))
                                                  (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'optimizer-declare-type!))
                                                        (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (declare (not safe))
                              (gx#datum->syntax__0 '#f 'quote))
                            (cons _%$%hd276380276411%_ '()))
                      (cons _%$%hd276383276421%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g276372276390%_
                                                   _%$%g276373276394%_))
                                              (_%$%g276372276390%_
                                               _%$%g276373276394%_))))
                                      (_%$%g276372276390%_
                                       _%$%g276373276394%_))))
                              (_%$%g276372276390%_ _%$%g276373276394%_))))
                      (_%$%g276372276390%_ _%$%g276373276394%_)))))
          (_%$%g276371276445%_ _%$stx276368%_))))
    (define |gxc[:0:]#declare-class|
      (lambda (_%$stx276449%_)
        (let* ((_%$%g276453276471%_
                (lambda (_%$%g276454276467%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g276454276467%_))))
               (_%$%g276452276526%_
                (lambda (_%$%g276454276475%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g276454276475%_))
                      (let ((_%$%e276457276478%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g276454276475%_))))
                        (let ((_%$%hd276458276482%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e276457276478%_)))
                              (_%$%tl276459276485%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e276457276478%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl276459276485%_))
                              (let ((_%$%e276460276488%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl276459276485%_))))
                                (let ((_%$%hd276461276492%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e276460276488%_)))
                                      (_%$%tl276462276495%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e276460276488%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl276462276495%_))
                                      (let ((_%$%e276463276498%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl276462276495%_))))
                                        (let ((_%$%hd276464276502%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e276463276498%_)))
                                              (_%$%tl276465276505%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e276463276498%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl276465276505%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#identifier?
                                                     _%$%hd276461276492%_))
                                                  (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'optimizer-declare-class!))
                                                        (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (declare (not safe))
                              (gx#datum->syntax__0 '#f 'quote))
                            (cons _%$%hd276461276492%_ '()))
                      (cons _%$%hd276464276502%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g276453276471%_
                                                   _%$%g276454276475%_))
                                              (_%$%g276453276471%_
                                               _%$%g276454276475%_))))
                                      (_%$%g276453276471%_
                                       _%$%g276454276475%_))))
                              (_%$%g276453276471%_ _%$%g276454276475%_))))
                      (_%$%g276453276471%_ _%$%g276454276475%_)))))
          (_%$%g276452276526%_ _%$stx276449%_))))
    (define |gxc[:0:]#declare-type*|
      (lambda (_%$stx276530%_)
        (let* ((_%$%g276534276563%_
                (lambda (_%$%g276535276559%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g276535276559%_))))
               (_%$%g276533276659%_
                (lambda (_%$%g276535276567%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g276535276567%_))
                      (let ((_%$%e276538276570%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g276535276567%_))))
                        (let ((_%$%hd276539276574%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e276538276570%_)))
                              (_%$%tl276540276577%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e276538276570%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl276540276577%_))
                              (let ((_g282888_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl276540276577%_
                                        '0))))
                                (begin
                                  (let ((_g282889_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g282888_)
                                               (##values-length _g282888_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g282889_ 2)))
                                        (error "Context expects 2 values"
                                               _g282889_)))
                                  (let ((_%$%target276541276580%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282888_ 0)))
                                        (_%$%tl276543276583%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282888_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl276543276583%_))
                                        (letrec ((_%$%loop276544276586%_
                                                  (lambda (_%$%hd276542276590%_
                                                           _%$%type276548276593%_
                                                           _%$%symbol276549276594%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd276542276590%_))
                                                        (let ((_%$%e276545276596%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%hd276542276590%_))))
                  (let ((_%$%lp-hd276546276600%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e276545276596%_)))
                        (_%$%lp-tl276547276603%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e276545276596%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%lp-hd276546276600%_))
                        (let ((_%$%e276552276606%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%lp-hd276546276600%_))))
                          (let ((_%$%hd276553276610%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e276552276606%_)))
                                (_%$%tl276554276613%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e276552276606%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl276554276613%_))
                                (let ((_%$%e276555276616%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl276554276613%_))))
                                  (let ((_%$%hd276556276620%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e276555276616%_)))
                                        (_%$%tl276557276623%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e276555276616%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl276557276623%_))
                                        (_%$%loop276544276586%_
                                         _%$%lp-tl276547276603%_
                                         (cons _%$%hd276556276620%_
                                               _%$%type276548276593%_)
                                         (cons _%$%hd276553276610%_
                                               _%$%symbol276549276594%_))
                                        (_%$%g276534276563%_
                                         _%$%g276535276567%_))))
                                (_%$%g276534276563%_ _%$%g276535276567%_))))
                        (_%$%g276534276563%_ _%$%g276535276567%_))))
                (let ((_%$%type276550276626%_ (reverse _%$%type276548276593%_))
                      (_%$%symbol276551276628%_
                       (reverse _%$%symbol276549276594%_)))
                  (cons (let ()
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'begin))
                        (begin
                          (let ()
                            (declare (not safe))
                            (gx#syntax-check-splice-targets
                             _%$%type276550276626%_
                             _%$%symbol276551276628%_))
                          (let ((__tmp282890
                                 (lambda (_%$%g276647276651%_
                                          _%$%g276648276654%_
                                          _%$%g276649276656%_)
                                   (cons (cons (let ()
                                                 (declare (not safe))
                                                 (gx#datum->syntax__0
                                                  '#f
                                                  'declare-type))
                                               (cons _%$%g276648276654%_
                                                     (cons _%$%g276647276651%_
                                                           '())))
                                         _%$%g276649276656%_))))
                            (declare (not safe))
                            (foldr__1
                             __tmp282890
                             '()
                             _%$%type276550276626%_
                             _%$%symbol276551276628%_)))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop276544276586%_
                                           _%$%target276541276580%_
                                           '()
                                           '()))
                                        (_%$%g276534276563%_
                                         _%$%g276535276567%_)))))
                              (_%$%g276534276563%_ _%$%g276535276567%_))))
                      (_%$%g276534276563%_ _%$%g276535276567%_)))))
          (_%$%g276533276659%_ _%$stx276530%_))))
    (define |gxc[:0:]#declare-method|
      (lambda (_%$stx276664%_)
        (let* ((_%__stx282199282200%_ _%$stx276664%_)
               (_%$%g276669276711%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx282199282200%_)))))
          (let ((_%__kont282202282203%_
                 (lambda (_%$%g276671276839%_
                          _%$%g276672276841%_
                          _%$%g276673276842%_
                          _%$%g276674276843%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0
                            '#f
                            'optimizer-declare-method!))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%g276674276843%_ '()))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0 '#f 'quote))
                                           (cons _%$%g276673276842%_ '()))
                                     (cons (cons (let ()
                                                   (declare (not safe))
                                                   (gx#datum->syntax__0
                                                    '#f
                                                    'quote))
                                                 (cons _%$%g276672276841%_
                                                       '()))
                                           (cons _%$%g276671276839%_ '())))))))
                (_%__kont282204282205%_
                 (lambda (_%$%g276690276758%_
                          _%$%g276691276760%_
                          _%$%g276692276761%_
                          _%$%g276693276762%_)
                   (cons _%$%g276693276762%_
                         (cons _%$%g276692276761%_
                               (cons _%$%g276691276760%_
                                     (cons _%$%g276690276758%_
                                           (cons (let ()
                                                   (declare (not safe))
                                                   (gx#datum->syntax__0
                                                    '#f
                                                    'rebind?))
                                                 '()))))))))
            (let ((_%__match282238282239%_
                   (lambda (_%$%e276675276789%_
                            _%$%hd276676276793%_
                            _%$%tl276677276796%_
                            _%$%e276678276799%_
                            _%$%hd276679276803%_
                            _%$%tl276680276806%_
                            _%$%e276681276809%_
                            _%$%hd276682276813%_
                            _%$%tl276683276816%_
                            _%$%e276684276819%_
                            _%$%hd276685276823%_
                            _%$%tl276686276826%_
                            _%$%e276687276829%_
                            _%$%hd276688276833%_
                            _%$%tl276689276836%_)
                     (let ((_%$%g276671276839%_ _%$%hd276688276833%_)
                           (_%$%g276672276841%_ _%$%hd276685276823%_)
                           (_%$%g276673276842%_ _%$%hd276682276813%_)
                           (_%$%g276674276843%_ _%$%hd276679276803%_))
                       (if (and (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%g276674276843%_))
                                (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%g276673276842%_))
                                (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%g276672276841%_)))
                           (_%__kont282202282203%_
                            _%$%g276671276839%_
                            _%$%g276672276841%_
                            _%$%g276673276842%_
                            _%$%g276674276843%_)
                           (let ()
                             (declare (not safe))
                             (_%$%g276669276711%_)))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx282199282200%_))
                  (let ((_%$%e276675276789%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%__stx282199282200%_))))
                    (let ((_%$%tl276677276796%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e276675276789%_)))
                          (_%$%hd276676276793%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e276675276789%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl276677276796%_))
                          (let ((_%$%e276678276799%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%tl276677276796%_))))
                            (let ((_%$%tl276680276806%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e276678276799%_)))
                                  (_%$%hd276679276803%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e276678276799%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl276680276806%_))
                                  (let ((_%$%e276681276809%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#syntax-e
                                            _%$%tl276680276806%_))))
                                    (let ((_%$%tl276683276816%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e276681276809%_)))
                                          (_%$%hd276682276813%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e276681276809%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl276683276816%_))
                                          (let ((_%$%e276684276819%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#syntax-e
                                                    _%$%tl276683276816%_))))
                                            (let ((_%$%tl276686276826%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e276684276819%_)))
                                                  (_%$%hd276685276823%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e276684276819%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl276686276826%_))
                                                  (let ((_%$%e276687276829%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%tl276686276826%_))))
                                                    (let ((_%$%tl276689276836%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e276687276829%_)))
                                                          (_%$%hd276688276833%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e276687276829%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl276689276836%_))
                                                          (_%__match282238282239%_
                                                           _%$%e276675276789%_
                                                           _%$%hd276676276793%_
                                                           _%$%tl276677276796%_
                                                           _%$%e276678276799%_
                                                           _%$%hd276679276803%_
                                                           _%$%tl276680276806%_
                                                           _%$%e276681276809%_
                                                           _%$%hd276682276813%_
                                                           _%$%tl276683276816%_
                                                           _%$%e276684276819%_
                                                           _%$%hd276685276823%_
                                                           _%$%tl276686276826%_
                                                           _%$%e276687276829%_
                                                           _%$%hd276688276833%_
                                                           _%$%tl276689276836%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g276669276711%_)))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl276686276826%_))
                                                      (_%__kont282204282205%_
                                                       _%$%hd276685276823%_
                                                       _%$%hd276682276813%_
                                                       _%$%hd276679276803%_
                                                       _%$%hd276676276793%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g276669276711%_))))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g276669276711%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g276669276711%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g276669276711%_)))))
                  (let () (declare (not safe)) (_%$%g276669276711%_))))))))
    (define |gxc[:0:]#declare-method*|
      (lambda (_%$stx276868%_)
        (let* ((_%$%g276872276907%_
                (lambda (_%$%g276873276903%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g276873276903%_))))
               (_%$%g276871277020%_
                (lambda (_%$%g276873276911%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g276873276911%_))
                      (let ((_%$%e276877276914%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g276873276911%_))))
                        (let ((_%$%hd276878276918%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e276877276914%_)))
                              (_%$%tl276879276921%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e276877276914%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl276879276921%_))
                              (let ((_g282891_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl276879276921%_
                                        '0))))
                                (begin
                                  (let ((_g282892_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g282891_)
                                               (##values-length _g282891_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g282892_ 2)))
                                        (error "Context expects 2 values"
                                               _g282892_)))
                                  (let ((_%$%target276880276924%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282891_ 0)))
                                        (_%$%tl276882276927%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282891_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl276882276927%_))
                                        (letrec ((_%$%loop276883276930%_
                                                  (lambda (_%$%hd276881276934%_
                                                           _%$%symbol276887276937%_
                                                           _%$%method276888276938%_
                                                           _%$%type-t276889276939%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd276881276934%_))
                                                        (let ((_%$%e276884276941%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%hd276881276934%_))))
                  (let ((_%$%lp-hd276885276945%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e276884276941%_)))
                        (_%$%lp-tl276886276948%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e276884276941%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%lp-hd276885276945%_))
                        (let ((_%$%e276893276951%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%lp-hd276885276945%_))))
                          (let ((_%$%hd276894276955%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e276893276951%_)))
                                (_%$%tl276895276958%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e276893276951%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl276895276958%_))
                                (let ((_%$%e276896276961%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl276895276958%_))))
                                  (let ((_%$%hd276897276965%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e276896276961%_)))
                                        (_%$%tl276898276968%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e276896276961%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl276898276968%_))
                                        (let ((_%$%e276899276971%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-e
                                                  _%$%tl276898276968%_))))
                                          (let ((_%$%hd276900276975%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e276899276971%_)))
                                                (_%$%tl276901276978%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e276899276971%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl276901276978%_))
                                                (_%$%loop276883276930%_
                                                 _%$%lp-tl276886276948%_
                                                 (cons _%$%hd276900276975%_
                                                       _%$%symbol276887276937%_)
                                                 (cons _%$%hd276897276965%_
                                                       _%$%method276888276938%_)
                                                 (cons _%$%hd276894276955%_
                                                       _%$%type-t276889276939%_))
                                                (_%$%g276872276907%_
                                                 _%$%g276873276911%_))))
                                        (_%$%g276872276907%_
                                         _%$%g276873276911%_))))
                                (_%$%g276872276907%_ _%$%g276873276911%_))))
                        (_%$%g276872276907%_ _%$%g276873276911%_))))
                (let ((_%$%symbol276890276981%_
                       (reverse _%$%symbol276887276937%_))
                      (_%$%method276891276983%_
                       (reverse _%$%method276888276938%_))
                      (_%$%type-t276892276984%_
                       (reverse _%$%type-t276889276939%_)))
                  (cons (let ()
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'begin))
                        (begin
                          (let ()
                            (declare (not safe))
                            (gx#syntax-check-splice-targets
                             _%$%symbol276890276981%_
                             _%$%method276891276983%_
                             _%$%type-t276892276984%_))
                          (let ((__tmp282893
                                 (lambda (_%$%g277005277010%_
                                          _%$%g277006277013%_
                                          _%$%g277007277015%_
                                          _%$%g277008277017%_)
                                   (cons (cons (let ()
                                                 (declare (not safe))
                                                 (gx#datum->syntax__0
                                                  '#f
                                                  'declare-method))
                                               (cons _%$%g277007277015%_
                                                     (cons _%$%g277006277013%_
                                                           (cons _%$%g277005277010%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         _%$%g277008277017%_))))
                            (declare (not safe))
                            (__foldr*
                             __tmp282893
                             '()
                             _%$%symbol276890276981%_
                             _%$%method276891276983%_
                             _%$%type-t276892276984%_)))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop276883276930%_
                                           _%$%target276880276924%_
                                           '()
                                           '()
                                           '()))
                                        (_%$%g276872276907%_
                                         _%$%g276873276911%_)))))
                              (_%$%g276872276907%_ _%$%g276873276911%_))))
                      (_%$%g276872276907%_ _%$%g276873276911%_)))))
          (_%$%g276871277020%_ _%$stx276868%_))))
    (define |gxc[:0:]#declare-methods|
      (lambda (_%$stx277025%_)
        (let* ((_%$%g277029277062%_
                (lambda (_%$%g277030277058%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277030277058%_))))
               (_%$%g277028277172%_
                (lambda (_%$%g277030277066%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277030277066%_))
                      (let ((_%$%e277034277069%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277030277066%_))))
                        (let ((_%$%hd277035277073%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277034277069%_)))
                              (_%$%tl277036277076%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277034277069%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277036277076%_))
                              (let ((_%$%e277037277079%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277036277076%_))))
                                (let ((_%$%hd277038277083%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277037277079%_)))
                                      (_%$%tl277039277086%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277037277079%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl277039277086%_))
                                      (let ((_g282894_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%tl277039277086%_
                                                '0))))
                                        (begin
                                          (let ((_g282895_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g282894_)
                                                       (##values-length
                                                        _g282894_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g282895_ 2)))
                                                (error "Context expects 2 values"
                                                       _g282895_)))
                                          (let ((_%$%target277040277089%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g282894_ 0)))
                                                (_%$%tl277042277092%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g282894_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl277042277092%_))
                                                (letrec ((_%$%loop277043277095%_
                                                          (lambda (_%$%hd277041277099%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%symbol277047277102%_
                           _%$%method277048277103%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd277041277099%_))
                        (let ((_%$%e277044277105%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%hd277041277099%_))))
                          (let ((_%$%lp-hd277045277109%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e277044277105%_)))
                                (_%$%lp-tl277046277112%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e277044277105%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%lp-hd277045277109%_))
                                (let ((_%$%e277051277115%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e
                                          _%$%lp-hd277045277109%_))))
                                  (let ((_%$%hd277052277119%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e277051277115%_)))
                                        (_%$%tl277053277122%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e277051277115%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl277053277122%_))
                                        (let ((_%$%e277054277125%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-e
                                                  _%$%tl277053277122%_))))
                                          (let ((_%$%hd277055277129%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e277054277125%_)))
                                                (_%$%tl277056277132%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e277054277125%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl277056277132%_))
                                                (_%$%loop277043277095%_
                                                 _%$%lp-tl277046277112%_
                                                 (cons _%$%hd277055277129%_
                                                       _%$%symbol277047277102%_)
                                                 (cons _%$%hd277052277119%_
                                                       _%$%method277048277103%_))
                                                (_%$%g277029277062%_
                                                 _%$%g277030277066%_))))
                                        (_%$%g277029277062%_
                                         _%$%g277030277066%_))))
                                (_%$%g277029277062%_ _%$%g277030277066%_))))
                        (let ((_%$%symbol277049277135%_
                               (reverse _%$%symbol277047277102%_))
                              (_%$%method277050277137%_
                               (reverse _%$%method277048277103%_)))
                          (cons (let ()
                                  (declare (not safe))
                                  (gx#datum->syntax__0 '#f 'begin))
                                (begin
                                  (let ()
                                    (declare (not safe))
                                    (gx#syntax-check-splice-targets
                                     _%$%symbol277049277135%_
                                     _%$%method277050277137%_))
                                  (let ((__tmp282896
                                         (lambda (_%$%g277160277164%_
                                                  _%$%g277161277167%_
                                                  _%$%g277162277169%_)
                                           (cons (cons (let ()
                                                         (declare (not safe))
                                                         (gx#datum->syntax__0
                                                          '#f
                                                          'declare-method))
                                                       (cons _%$%hd277038277083%_
                                                             (cons _%$%g277161277167%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%$%g277160277164%_ '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 _%$%g277162277169%_))))
                                    (declare (not safe))
                                    (foldr__1
                                     __tmp282896
                                     '()
                                     _%$%symbol277049277135%_
                                     _%$%method277050277137%_)))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop277043277095%_
                                                   _%$%target277040277089%_
                                                   '()
                                                   '()))
                                                (_%$%g277029277062%_
                                                 _%$%g277030277066%_)))))
                                      (_%$%g277029277062%_
                                       _%$%g277030277066%_))))
                              (_%$%g277029277062%_ _%$%g277030277066%_))))
                      (_%$%g277029277062%_ _%$%g277030277066%_)))))
          (_%$%g277028277172%_ _%$stx277025%_))))
    (define |gxc[:0:]#@alias|
      (lambda (_%$stx277177%_)
        (let* ((_%$%g277181277195%_
                (lambda (_%$%g277182277191%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277182277191%_))))
               (_%$%g277180277236%_
                (lambda (_%$%g277182277199%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277182277199%_))
                      (let ((_%$%e277184277202%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277182277199%_))))
                        (let ((_%$%hd277185277206%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277184277202%_)))
                              (_%$%tl277186277209%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277184277202%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277186277209%_))
                              (let ((_%$%e277187277212%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277186277209%_))))
                                (let ((_%$%hd277188277216%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277187277212%_)))
                                      (_%$%tl277189277219%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277187277212%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl277189277219%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0
                                               '#f
                                               'make-!alias))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'quote))
                                                        (cons _%$%hd277188277216%_
                                                              '()))
                                                  '()))
                                      (_%$%g277181277195%_
                                       _%$%g277182277199%_))))
                              (_%$%g277181277195%_ _%$%g277182277199%_))))
                      (_%$%g277181277195%_ _%$%g277182277199%_)))))
          (_%$%g277180277236%_ _%$stx277177%_))))
    (define |gxc[:0:]#@class|
      (lambda (_%$stx277240%_)
        (let* ((_%$%g277244277298%_
                (lambda (_%$%g277245277294%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277245277294%_))))
               (_%$%g277243277479%_
                (lambda (_%$%g277245277302%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277245277302%_))
                      (let ((_%$%e277257277305%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277245277302%_))))
                        (let ((_%$%hd277258277309%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277257277305%_)))
                              (_%$%tl277259277312%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277257277305%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277259277312%_))
                              (let ((_%$%e277260277315%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277259277312%_))))
                                (let ((_%$%hd277261277319%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277260277315%_)))
                                      (_%$%tl277262277322%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277260277315%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl277262277322%_))
                                      (let ((_%$%e277263277325%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl277262277322%_))))
                                        (let ((_%$%hd277264277329%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e277263277325%_)))
                                              (_%$%tl277265277332%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e277263277325%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl277265277332%_))
                                              (let ((_%$%e277266277335%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl277265277332%_))))
                                                (let ((_%$%hd277267277339%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e277266277335%_)))
                                                      (_%$%tl277268277342%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e277266277335%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl277268277342%_))
                                                      (let ((_%$%e277269277345%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-e _%$%tl277268277342%_))))
                (let ((_%$%hd277270277349%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e277269277345%_)))
                      (_%$%tl277271277352%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e277269277345%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl277271277352%_))
                      (let ((_%$%e277272277355%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%tl277271277352%_))))
                        (let ((_%$%hd277273277359%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277272277355%_)))
                              (_%$%tl277274277362%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277272277355%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277274277362%_))
                              (let ((_%$%e277275277365%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277274277362%_))))
                                (let ((_%$%hd277276277369%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277275277365%_)))
                                      (_%$%tl277277277372%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277275277365%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl277277277372%_))
                                      (let ((_%$%e277278277375%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl277277277372%_))))
                                        (let ((_%$%hd277279277379%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e277278277375%_)))
                                              (_%$%tl277280277382%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e277278277375%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl277280277382%_))
                                              (let ((_%$%e277281277385%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl277280277382%_))))
                                                (let ((_%$%hd277282277389%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e277281277385%_)))
                                                      (_%$%tl277283277392%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e277281277385%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl277283277392%_))
                                                      (let ((_%$%e277284277395%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-e _%$%tl277283277392%_))))
                (let ((_%$%hd277285277399%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e277284277395%_)))
                      (_%$%tl277286277402%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e277284277395%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl277286277402%_))
                      (let ((_%$%e277287277405%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%tl277286277402%_))))
                        (let ((_%$%hd277288277409%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277287277405%_)))
                              (_%$%tl277289277412%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277287277405%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277289277412%_))
                              (let ((_%$%e277290277415%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277289277412%_))))
                                (let ((_%$%hd277291277419%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277290277415%_)))
                                      (_%$%tl277292277422%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277290277415%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl277292277422%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0
                                               '#f
                                               'make-!class))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'quote))
                                                        (cons _%$%hd277261277319%_
                                                              '()))
                                                  (cons (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f 'quote))
                      (cons _%$%hd277264277329%_ '()))
                (cons (cons (let ()
                              (declare (not safe))
                              (gx#datum->syntax__0 '#f 'quote))
                            (cons _%$%hd277267277339%_ '()))
                      (cons (cons (let ()
                                    (declare (not safe))
                                    (gx#datum->syntax__0 '#f 'quote))
                                  (cons _%$%hd277270277349%_ '()))
                            (cons (cons (let ()
                                          (declare (not safe))
                                          (gx#datum->syntax__0 '#f 'quote))
                                        (cons _%$%hd277273277359%_ '()))
                                  (cons (cons (let ()
                                                (declare (not safe))
                                                (gx#datum->syntax__0
                                                 '#f
                                                 'quote))
                                              (cons _%$%hd277276277369%_ '()))
                                        (cons _%$%hd277279277379%_
                                              (cons _%$%hd277282277389%_
                                                    (cons _%$%hd277285277399%_
                                                          (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'quote))
                              (cons _%$%hd277288277409%_ '()))
                        (cons (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f 'quote))
                                    (cons _%$%hd277291277419%_ '()))
                              '()))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (_%$%g277244277298%_
                                       _%$%g277245277302%_))))
                              (_%$%g277244277298%_ _%$%g277245277302%_))))
                      (_%$%g277244277298%_ _%$%g277245277302%_))))
              (_%$%g277244277298%_ _%$%g277245277302%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g277244277298%_
                                               _%$%g277245277302%_))))
                                      (_%$%g277244277298%_
                                       _%$%g277245277302%_))))
                              (_%$%g277244277298%_ _%$%g277245277302%_))))
                      (_%$%g277244277298%_ _%$%g277245277302%_))))
              (_%$%g277244277298%_ _%$%g277245277302%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g277244277298%_
                                               _%$%g277245277302%_))))
                                      (_%$%g277244277298%_
                                       _%$%g277245277302%_))))
                              (_%$%g277244277298%_ _%$%g277245277302%_))))
                      (_%$%g277244277298%_ _%$%g277245277302%_)))))
          (_%$%g277243277479%_ _%$stx277240%_))))
    (define |gxc[:0:]#@predicate|
      (lambda (_%$stx277483%_)
        (let* ((_%$%g277487277501%_
                (lambda (_%$%g277488277497%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277488277497%_))))
               (_%$%g277486277542%_
                (lambda (_%$%g277488277505%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277488277505%_))
                      (let ((_%$%e277490277508%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277488277505%_))))
                        (let ((_%$%hd277491277512%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277490277508%_)))
                              (_%$%tl277492277515%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277490277508%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277492277515%_))
                              (let ((_%$%e277493277518%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277492277515%_))))
                                (let ((_%$%hd277494277522%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277493277518%_)))
                                      (_%$%tl277495277525%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277493277518%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl277495277525%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0
                                               '#f
                                               'make-!predicate))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'quote))
                                                        (cons _%$%hd277494277522%_
                                                              '()))
                                                  '()))
                                      (_%$%g277487277501%_
                                       _%$%g277488277505%_))))
                              (_%$%g277487277501%_ _%$%g277488277505%_))))
                      (_%$%g277487277501%_ _%$%g277488277505%_)))))
          (_%$%g277486277542%_ _%$stx277483%_))))
    (define |gxc[:0:]#@constructor|
      (lambda (_%$stx277546%_)
        (let* ((_%$%g277550277564%_
                (lambda (_%$%g277551277560%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277551277560%_))))
               (_%$%g277549277605%_
                (lambda (_%$%g277551277568%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277551277568%_))
                      (let ((_%$%e277553277571%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277551277568%_))))
                        (let ((_%$%hd277554277575%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277553277571%_)))
                              (_%$%tl277555277578%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277553277571%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277555277578%_))
                              (let ((_%$%e277556277581%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277555277578%_))))
                                (let ((_%$%hd277557277585%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277556277581%_)))
                                      (_%$%tl277558277588%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277556277581%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl277558277588%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0
                                               '#f
                                               'make-!constructor))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'quote))
                                                        (cons _%$%hd277557277585%_
                                                              '()))
                                                  '()))
                                      (_%$%g277550277564%_
                                       _%$%g277551277568%_))))
                              (_%$%g277550277564%_ _%$%g277551277568%_))))
                      (_%$%g277550277564%_ _%$%g277551277568%_)))))
          (_%$%g277549277605%_ _%$stx277546%_))))
    (define |gxc[:0:]#@accessor|
      (lambda (_%$stx277609%_)
        (let* ((_%$%g277613277635%_
                (lambda (_%$%g277614277631%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277614277631%_))))
               (_%$%g277612277704%_
                (lambda (_%$%g277614277639%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277614277639%_))
                      (let ((_%$%e277618277642%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277614277639%_))))
                        (let ((_%$%hd277619277646%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277618277642%_)))
                              (_%$%tl277620277649%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277618277642%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277620277649%_))
                              (let ((_%$%e277621277652%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277620277649%_))))
                                (let ((_%$%hd277622277656%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277621277652%_)))
                                      (_%$%tl277623277659%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277621277652%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl277623277659%_))
                                      (let ((_%$%e277624277662%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl277623277659%_))))
                                        (let ((_%$%hd277625277666%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e277624277662%_)))
                                              (_%$%tl277626277669%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e277624277662%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl277626277669%_))
                                              (let ((_%$%e277627277672%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl277626277669%_))))
                                                (let ((_%$%hd277628277676%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e277627277672%_)))
                                                      (_%$%tl277629277679%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e277627277672%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl277629277679%_))
                                                      (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'make-!accessor))
                                                            (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (declare (not safe))
                                  (gx#datum->syntax__0 '#f 'quote))
                                (cons _%$%hd277622277656%_ '()))
                          (cons (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f 'quote))
                                      (cons _%$%hd277625277666%_ '()))
                                (cons _%$%hd277628277676%_ '()))))
              (_%$%g277613277635%_ _%$%g277614277639%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g277613277635%_
                                               _%$%g277614277639%_))))
                                      (_%$%g277613277635%_
                                       _%$%g277614277639%_))))
                              (_%$%g277613277635%_ _%$%g277614277639%_))))
                      (_%$%g277613277635%_ _%$%g277614277639%_)))))
          (_%$%g277612277704%_ _%$stx277609%_))))
    (define |gxc[:0:]#@mutator|
      (lambda (_%$stx277708%_)
        (let* ((_%$%g277712277734%_
                (lambda (_%$%g277713277730%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277713277730%_))))
               (_%$%g277711277803%_
                (lambda (_%$%g277713277738%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277713277738%_))
                      (let ((_%$%e277717277741%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277713277738%_))))
                        (let ((_%$%hd277718277745%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277717277741%_)))
                              (_%$%tl277719277748%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277717277741%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277719277748%_))
                              (let ((_%$%e277720277751%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277719277748%_))))
                                (let ((_%$%hd277721277755%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277720277751%_)))
                                      (_%$%tl277722277758%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277720277751%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl277722277758%_))
                                      (let ((_%$%e277723277761%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl277722277758%_))))
                                        (let ((_%$%hd277724277765%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e277723277761%_)))
                                              (_%$%tl277725277768%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e277723277761%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl277725277768%_))
                                              (let ((_%$%e277726277771%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl277725277768%_))))
                                                (let ((_%$%hd277727277775%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e277726277771%_)))
                                                      (_%$%tl277728277778%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e277726277771%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl277728277778%_))
                                                      (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'make-!mutator))
                                                            (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (declare (not safe))
                                  (gx#datum->syntax__0 '#f 'quote))
                                (cons _%$%hd277721277755%_ '()))
                          (cons (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f 'quote))
                                      (cons _%$%hd277724277765%_ '()))
                                (cons _%$%hd277727277775%_ '()))))
              (_%$%g277712277734%_ _%$%g277713277738%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g277712277734%_
                                               _%$%g277713277738%_))))
                                      (_%$%g277712277734%_
                                       _%$%g277713277738%_))))
                              (_%$%g277712277734%_ _%$%g277713277738%_))))
                      (_%$%g277712277734%_ _%$%g277713277738%_)))))
          (_%$%g277711277803%_ _%$stx277708%_))))
    (define |gxc[:0:]#@primitive-predicate|
      (lambda (_%$stx277807%_)
        (let* ((_%$%g277811277825%_
                (lambda (_%$%g277812277821%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277812277821%_))))
               (_%$%g277810277866%_
                (lambda (_%$%g277812277829%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277812277829%_))
                      (let ((_%$%e277814277832%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277812277829%_))))
                        (let ((_%$%hd277815277836%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277814277832%_)))
                              (_%$%tl277816277839%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277814277832%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277816277839%_))
                              (let ((_%$%e277817277842%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277816277839%_))))
                                (let ((_%$%hd277818277846%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277817277842%_)))
                                      (_%$%tl277819277849%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277817277842%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl277819277849%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0
                                               '#f
                                               'make-!primitive-predicate))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'quote))
                                                        (cons _%$%hd277818277846%_
                                                              '()))
                                                  '()))
                                      (_%$%g277811277825%_
                                       _%$%g277812277829%_))))
                              (_%$%g277811277825%_ _%$%g277812277829%_))))
                      (_%$%g277811277825%_ _%$%g277812277829%_)))))
          (_%$%g277810277866%_ _%$stx277807%_))))
    (define |gxc[:0:]#@interface|
      (lambda (_%$stx277870%_)
        (let* ((_%$%g277874277892%_
                (lambda (_%$%g277875277888%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g277875277888%_))))
               (_%$%g277873277947%_
                (lambda (_%$%g277875277896%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g277875277896%_))
                      (let ((_%$%e277878277899%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g277875277896%_))))
                        (let ((_%$%hd277879277903%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277878277899%_)))
                              (_%$%tl277880277906%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277878277899%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl277880277906%_))
                              (let ((_%$%e277881277909%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl277880277906%_))))
                                (let ((_%$%hd277882277913%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e277881277909%_)))
                                      (_%$%tl277883277916%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e277881277909%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl277883277916%_))
                                      (let ((_%$%e277884277919%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl277883277916%_))))
                                        (let ((_%$%hd277885277923%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e277884277919%_)))
                                              (_%$%tl277886277926%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e277884277919%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl277886277926%_))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'make-!interface))
                                                    (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'quote))
                        (cons _%$%hd277882277913%_ '()))
                  (cons (cons (let ()
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'quote))
                              (cons _%$%hd277885277923%_ '()))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g277874277892%_
                                               _%$%g277875277896%_))))
                                      (_%$%g277874277892%_
                                       _%$%g277875277896%_))))
                              (_%$%g277874277892%_ _%$%g277875277896%_))))
                      (_%$%g277874277892%_ _%$%g277875277896%_)))))
          (_%$%g277873277947%_ _%$stx277870%_))))
    (define |gxc[:0:]#@lambda|
      (lambda (_%$stx277951%_)
        (let* ((_%__stx282267282268%_ _%$stx277951%_)
               (_%$%g277958278019%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx282267282268%_)))))
          (let ((_%__kont282270282271%_
                 (lambda (_%$%g277960278257%_ _%$%g277961278259%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'make-!lambda))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%g277961278259%_ '()))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0 '#f 'quote))
                                           (cons _%$%g277960278257%_ '()))
                                     '())))))
                (_%__kont282272282273%_
                 (lambda (_%$%g277971278196%_
                          _%$%g277972278198%_
                          _%$%g277973278199%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'make-!lambda))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%g277973278199%_ '()))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0 '#f 'quote))
                                           (cons _%$%g277972278198%_ '()))
                                     (cons 'signature:
                                           (cons (cons (let ()
                                                         (declare (not safe))
                                                         (gx#datum->syntax__0
                                                          '#f
                                                          'apply))
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f 'make-!signature))
                     (cons (cons (let ()
                                   (declare (not safe))
                                   (gx#datum->syntax__0 '#f 'quote))
                                 (cons _%$%g277971278196%_ '()))
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '())))))))
                (_%__kont282274282275%_
                 (lambda (_%$%g277990278120%_ _%$%g277991278122%_)
                   (cons _%$%g277991278122%_
                         (cons _%$%g277990278120%_ (cons '#f '())))))
                (_%__kont282276282277%_
                 (lambda (_%$%g277998278070%_
                          _%$%g277999278072%_
                          _%$%g278000278073%_)
                   (cons _%$%g278000278073%_
                         (cons _%$%g277999278072%_
                               (cons '#f
                                     (cons 'signature:
                                           (cons _%$%g277998278070%_
                                                 '()))))))))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx282267282268%_))
                (let ((_%$%e277962278227%_
                       (let ()
                         (declare (not safe))
                         (gx#syntax-e _%__stx282267282268%_))))
                  (let ((_%$%tl277964278234%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e277962278227%_)))
                        (_%$%hd277963278231%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e277962278227%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl277964278234%_))
                        (let ((_%$%e277965278237%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl277964278234%_))))
                          (let ((_%$%tl277967278244%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e277965278237%_)))
                                (_%$%hd277966278241%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e277965278237%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl277967278244%_))
                                (let ((_%$%e277968278247%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl277967278244%_))))
                                  (let ((_%$%tl277970278254%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e277968278247%_)))
                                        (_%$%hd277969278251%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e277968278247%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl277970278254%_))
                                        (_%__kont282270282271%_
                                         _%$%hd277969278251%_
                                         _%$%hd277966278241%_)
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl277970278254%_))
                                            (let ((_%$%e277983278172%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-e
                                                      _%$%tl277970278254%_))))
                                              (let ((_%$%tl277985278179%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e277983278172%_)))
                                                    (_%$%hd277984278176%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e277983278172%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-datum?
                                                       _%$%hd277984278176%_))
                                                    (let ((_%$%e277986278182%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%hd277984278176%_))))
                                                      (if (equal? _%$%e277986278182%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          'signature:)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl277985278179%_))
                      (let ((_%$%e277987278186%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%tl277985278179%_))))
                        (let ((_%$%tl277989278193%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e277987278186%_)))
                              (_%$%hd277988278190%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e277987278186%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl277989278193%_))
                              (_%__kont282272282273%_
                               _%$%hd277988278190%_
                               _%$%hd277969278251%_
                               _%$%hd277966278241%_)
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-datum? _%$%hd277969278251%_))
                                  (let ((_%$%e278010278056%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd277969278251%_))))
                                    (declare (not safe))
                                    (_%$%g277958278019%_))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g277958278019%_))))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-datum? _%$%hd277969278251%_))
                          (let ((_%$%e278010278056%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%hd277969278251%_))))
                            (if (equal? _%$%e278010278056%_ 'signature:)
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl277985278179%_))
                                    (_%__kont282276282277%_
                                     _%$%hd277984278176%_
                                     _%$%hd277966278241%_
                                     _%$%hd277963278231%_)
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g277958278019%_)))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g277958278019%_))))
                          (let () (declare (not safe)) (_%$%g277958278019%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-datum? _%$%hd277969278251%_))
                      (let ((_%$%e278010278056%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%hd277969278251%_))))
                        (if (equal? _%$%e278010278056%_ 'signature:)
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl277985278179%_))
                                (_%__kont282276282277%_
                                 _%$%hd277984278176%_
                                 _%$%hd277966278241%_
                                 _%$%hd277963278231%_)
                                (let ()
                                  (declare (not safe))
                                  (_%$%g277958278019%_)))
                            (let ()
                              (declare (not safe))
                              (_%$%g277958278019%_))))
                      (let () (declare (not safe)) (_%$%g277958278019%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-datum?
                                                           _%$%hd277969278251%_))
                                                        (let ((_%$%e278010278056%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%hd277969278251%_))))
                  (if (equal? _%$%e278010278056%_ 'signature:)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl277985278179%_))
                          (_%__kont282276282277%_
                           _%$%hd277984278176%_
                           _%$%hd277966278241%_
                           _%$%hd277963278231%_)
                          (let () (declare (not safe)) (_%$%g277958278019%_)))
                      (let () (declare (not safe)) (_%$%g277958278019%_))))
                (let () (declare (not safe)) (_%$%g277958278019%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-datum?
                                                   _%$%hd277969278251%_))
                                                (let ((_%$%e278010278056%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%hd277969278251%_))))
                                                  (declare (not safe))
                                                  (_%$%g277958278019%_))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g277958278019%_)))))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl277967278244%_))
                                    (_%__kont282274282275%_
                                     _%$%hd277966278241%_
                                     _%$%hd277963278231%_)
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g277958278019%_))))))
                        (let () (declare (not safe)) (_%$%g277958278019%_)))))
                (let () (declare (not safe)) (_%$%g277958278019%_)))))))
    (define |gxc[:0:]#@case-lambda|
      (lambda (_%$stx278278%_)
        (let* ((_%$%g278282278311%_
                (lambda (_%$%g278283278307%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g278283278307%_))))
               (_%$%g278281278416%_
                (lambda (_%$%g278283278315%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g278283278315%_))
                      (let ((_%$%e278285278318%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g278283278315%_))))
                        (let ((_%$%hd278286278322%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e278285278318%_)))
                              (_%$%tl278287278325%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e278285278318%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl278287278325%_))
                              (let ((_g282897_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl278287278325%_
                                        '0))))
                                (begin
                                  (let ((_g282898_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g282897_)
                                               (##values-length _g282897_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g282898_ 2)))
                                        (error "Context expects 2 values"
                                               _g282898_)))
                                  (let ((_%$%target278288278328%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282897_ 0)))
                                        (_%$%tl278290278331%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282897_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl278290278331%_))
                                        (letrec ((_%$%loop278291278334%_
                                                  (lambda (_%$%hd278289278338%_
                                                           _%$%clause278295278341%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd278289278338%_))
                                                        (let ((_%$%e278292278343%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%hd278289278338%_))))
                  (let ((_%$%lp-hd278293278347%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e278292278343%_)))
                        (_%$%lp-tl278294278350%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e278292278343%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair/null? _%$%lp-hd278293278347%_))
                        (let ((_g282899_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-split-splice
                                  _%$%lp-hd278293278347%_
                                  '0))))
                          (begin
                            (let ((_g282900_
                                   (let ()
                                     (declare (not safe))
                                     (if (##values? _g282899_)
                                         (##values-length _g282899_)
                                         1))))
                              (if (not (let ()
                                         (declare (not safe))
                                         (##fx= _g282900_ 2)))
                                  (error "Context expects 2 values"
                                         _g282900_)))
                            (let ((_%$%target278297278353%_
                                   (let ()
                                     (declare (not safe))
                                     (##values-ref _g282899_ 0)))
                                  (_%$%tl278299278356%_
                                   (let ()
                                     (declare (not safe))
                                     (##values-ref _g282899_ 1))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl278299278356%_))
                                  (letrec ((_%$%loop278300278359%_
                                            (lambda (_%$%hd278298278363%_
                                                     _%$%clause278304278366%_)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd278298278363%_))
                                                  (let ((_%$%e278301278368%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%hd278298278363%_))))
                                                    (let ((_%$%lp-hd278302278372%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e278301278368%_)))
                                                          (_%$%lp-tl278303278375%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e278301278368%_))))
                                                      (_%$%loop278300278359%_
                                                       _%$%lp-tl278303278375%_
                                                       (cons _%$%lp-hd278302278372%_
                                                             _%$%clause278304278366%_))))
                                                  (let ((_%$%clause278305278378%_
                                                         (reverse _%$%clause278304278366%_)))
                                                    (_%$%loop278291278334%_
                                                     _%$%lp-tl278294278350%_
                                                     (cons _%$%clause278305278378%_
                                                           _%$%clause278295278341%_)))))))
                                    (_%$%loop278300278359%_
                                     _%$%target278297278353%_
                                     '()))
                                  (_%$%g278282278311%_ _%$%g278283278315%_)))))
                        (_%$%g278282278311%_ _%$%g278283278315%_))))
                (let ((_%$%clause278296278381%_
                       (reverse _%$%clause278295278341%_)))
                  (cons (let ()
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'make-!case-lambda))
                        (cons (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f '@list))
                                    (let ((__tmp282901
                                           (lambda (_%$%g278399278404%_
                                                    _%$%g278400278407%_)
                                             (cons (cons (let ()
                                                           (declare (not safe))
                                                           (gx#datum->syntax__0
                                                            '#f
                                                            '@lambda))
                                                         (let ((__tmp282902
                                                                (lambda (_%$%g278401278410%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 _%$%g278402278413%_)
                          (cons _%$%g278401278410%_ _%$%g278402278413%_))))
                   (declare (not safe))
                   (foldr__0 __tmp282902 '() _%$%g278399278404%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   _%$%g278400278407%_))))
                                      (declare (not safe))
                                      (foldr__0
                                       __tmp282901
                                       '()
                                       _%$%clause278296278381%_)))
                              '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop278291278334%_
                                           _%$%target278288278328%_
                                           '()))
                                        (_%$%g278282278311%_
                                         _%$%g278283278315%_)))))
                              (_%$%g278282278311%_ _%$%g278283278315%_))))
                      (_%$%g278282278311%_ _%$%g278283278315%_)))))
          (_%$%g278281278416%_ _%$stx278278%_))))
    (define |gxc[:0:]#@kw-lambda|
      (lambda (_%$stx278422%_)
        (let* ((_%$%g278426278444%_
                (lambda (_%$%g278427278440%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g278427278440%_))))
               (_%$%g278425278499%_
                (lambda (_%$%g278427278448%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g278427278448%_))
                      (let ((_%$%e278430278451%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g278427278448%_))))
                        (let ((_%$%hd278431278455%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e278430278451%_)))
                              (_%$%tl278432278458%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e278430278451%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl278432278458%_))
                              (let ((_%$%e278433278461%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl278432278458%_))))
                                (let ((_%$%hd278434278465%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e278433278461%_)))
                                      (_%$%tl278435278468%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e278433278461%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl278435278468%_))
                                      (let ((_%$%e278436278471%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl278435278468%_))))
                                        (let ((_%$%hd278437278475%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e278436278471%_)))
                                              (_%$%tl278438278478%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e278436278471%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl278438278478%_))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'make-!kw-lambda))
                                                    (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'quote))
                        (cons _%$%hd278434278465%_ '()))
                  (cons (cons (let ()
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'quote))
                              (cons _%$%hd278437278475%_ '()))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g278426278444%_
                                               _%$%g278427278448%_))))
                                      (_%$%g278426278444%_
                                       _%$%g278427278448%_))))
                              (_%$%g278426278444%_ _%$%g278427278448%_))))
                      (_%$%g278426278444%_ _%$%g278427278448%_)))))
          (_%$%g278425278499%_ _%$stx278422%_))))
    (define |gxc[:0:]#@kw-lambda-dispatch|
      (lambda (_%$stx278503%_)
        (let* ((_%$%g278507278525%_
                (lambda (_%$%g278508278521%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g278508278521%_))))
               (_%$%g278506278580%_
                (lambda (_%$%g278508278529%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g278508278529%_))
                      (let ((_%$%e278511278532%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g278508278529%_))))
                        (let ((_%$%hd278512278536%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e278511278532%_)))
                              (_%$%tl278513278539%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e278511278532%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl278513278539%_))
                              (let ((_%$%e278514278542%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl278513278539%_))))
                                (let ((_%$%hd278515278546%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e278514278542%_)))
                                      (_%$%tl278516278549%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e278514278542%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl278516278549%_))
                                      (let ((_%$%e278517278552%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl278516278549%_))))
                                        (let ((_%$%hd278518278556%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e278517278552%_)))
                                              (_%$%tl278519278559%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e278517278552%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl278519278559%_))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'make-!kw-lambda-primary))
                                                    (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'quote))
                        (cons _%$%hd278515278546%_ '()))
                  (cons (cons (let ()
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'quote))
                              (cons _%$%hd278518278556%_ '()))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g278507278525%_
                                               _%$%g278508278529%_))))
                                      (_%$%g278507278525%_
                                       _%$%g278508278529%_))))
                              (_%$%g278507278525%_ _%$%g278508278529%_))))
                      (_%$%g278507278525%_ _%$%g278508278529%_)))))
          (_%$%g278506278580%_ _%$stx278503%_))))
    (define |gxc[:0:]#declare-inline-rules!|
      (lambda (_%$stx278584%_)
        (let* ((_%$%g278588278617%_
                (lambda (_%$%g278589278613%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g278589278613%_))))
               (_%$%g278587278713%_
                (lambda (_%$%g278589278621%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g278589278621%_))
                      (let ((_%$%e278592278624%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g278589278621%_))))
                        (let ((_%$%hd278593278628%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e278592278624%_)))
                              (_%$%tl278594278631%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e278592278624%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl278594278631%_))
                              (let ((_g282903_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl278594278631%_
                                        '0))))
                                (begin
                                  (let ((_g282904_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g282903_)
                                               (##values-length _g282903_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g282904_ 2)))
                                        (error "Context expects 2 values"
                                               _g282904_)))
                                  (let ((_%$%target278595278634%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282903_ 0)))
                                        (_%$%tl278597278637%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282903_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl278597278637%_))
                                        (letrec ((_%$%loop278598278640%_
                                                  (lambda (_%$%hd278596278644%_
                                                           _%$%rule278602278647%_
                                                           _%$%proc278603278648%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd278596278644%_))
                                                        (let ((_%$%e278599278650%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%hd278596278644%_))))
                  (let ((_%$%lp-hd278600278654%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e278599278650%_)))
                        (_%$%lp-tl278601278657%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e278599278650%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%lp-hd278600278654%_))
                        (let ((_%$%e278606278660%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%lp-hd278600278654%_))))
                          (let ((_%$%hd278607278664%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e278606278660%_)))
                                (_%$%tl278608278667%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e278606278660%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl278608278667%_))
                                (let ((_%$%e278609278670%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl278608278667%_))))
                                  (let ((_%$%hd278610278674%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e278609278670%_)))
                                        (_%$%tl278611278677%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e278609278670%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl278611278677%_))
                                        (_%$%loop278598278640%_
                                         _%$%lp-tl278601278657%_
                                         (cons _%$%hd278610278674%_
                                               _%$%rule278602278647%_)
                                         (cons _%$%hd278607278664%_
                                               _%$%proc278603278648%_))
                                        (_%$%g278588278617%_
                                         _%$%g278589278621%_))))
                                (_%$%g278588278617%_ _%$%g278589278621%_))))
                        (_%$%g278588278617%_ _%$%g278589278621%_))))
                (let ((_%$%rule278604278680%_ (reverse _%$%rule278602278647%_))
                      (_%$%proc278605278682%_
                       (reverse _%$%proc278603278648%_)))
                  (cons (let ()
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'begin))
                        (begin
                          (let ()
                            (declare (not safe))
                            (gx#syntax-check-splice-targets
                             _%$%rule278604278680%_
                             _%$%proc278605278682%_))
                          (let ((__tmp282905
                                 (lambda (_%$%g278701278705%_
                                          _%$%g278702278708%_
                                          _%$%g278703278710%_)
                                   (cons (cons (let ()
                                                 (declare (not safe))
                                                 (gx#datum->syntax__0
                                                  '#f
                                                  'declare-inline-rule!))
                                               (cons _%$%g278702278708%_
                                                     (cons _%$%g278701278705%_
                                                           '())))
                                         _%$%g278703278710%_))))
                            (declare (not safe))
                            (foldr__1
                             __tmp282905
                             '()
                             _%$%rule278604278680%_
                             _%$%proc278605278682%_)))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop278598278640%_
                                           _%$%target278595278634%_
                                           '()
                                           '()))
                                        (_%$%g278588278617%_
                                         _%$%g278589278621%_)))))
                              (_%$%g278588278617%_ _%$%g278589278621%_))))
                      (_%$%g278588278617%_ _%$%g278589278621%_)))))
          (_%$%g278587278713%_ _%$stx278584%_))))
    (define |gxc[:0:]#declare-inline-rule!|
      (lambda (_%$stx278718%_)
        (let* ((_%$%g278722278740%_
                (lambda (_%$%g278723278736%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g278723278736%_))))
               (_%$%g278721278795%_
                (lambda (_%$%g278723278744%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g278723278744%_))
                      (let ((_%$%e278726278747%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g278723278744%_))))
                        (let ((_%$%hd278727278751%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e278726278747%_)))
                              (_%$%tl278728278754%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e278726278747%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl278728278754%_))
                              (let ((_%$%e278729278757%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl278728278754%_))))
                                (let ((_%$%hd278730278761%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e278729278757%_)))
                                      (_%$%tl278731278764%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e278729278757%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl278731278764%_))
                                      (let ((_%$%e278732278767%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl278731278764%_))))
                                        (let ((_%$%hd278733278771%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e278732278767%_)))
                                              (_%$%tl278734278774%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e278732278767%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl278734278774%_))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'let))
                                                    (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'type))
                        (cons (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0
                                       '#f
                                       'optimizer-lookup-type))
                                    (cons (cons (let ()
                                                  (declare (not safe))
                                                  (gx#datum->syntax__0
                                                   '#f
                                                   'quote))
                                                (cons _%$%hd278730278761%_
                                                      '()))
                                          '()))
                              '()))
                  (cons (cons (let ()
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'if))
                              (cons (cons (let ()
                                            (declare (not safe))
                                            (gx#datum->syntax__0
                                             '#f
                                             '!lambda?))
                                          (cons (let ()
                                                  (declare (not safe))
                                                  (gx#datum->syntax__0
                                                   '#f
                                                   'type))
                                                '()))
                                    (cons (cons (let ()
                                                  (declare (not safe))
                                                  (gx#datum->syntax__0
                                                   '#f
                                                   'set!))
                                                (cons (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               '!lambda-inline))
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gx#datum->syntax__0 '#f 'type))
                          '()))
              (cons _%$%hd278733278771%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (cons (cons (let ()
                                                        (declare (not safe))
                                                        (gx#datum->syntax__0
                                                         '#f
                                                         'displayln))
                                                      (cons '"*** WARNING unknown procedure "
                                                            (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (declare (not safe))
                                  (gx#datum->syntax__0 '#f 'quote))
                                (cons _%$%hd278730278761%_ '()))
                          (cons '"; ignoring inline rule" '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '()))))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g278722278740%_
                                               _%$%g278723278744%_))))
                                      (_%$%g278722278740%_
                                       _%$%g278723278744%_))))
                              (_%$%g278722278740%_ _%$%g278723278744%_))))
                      (_%$%g278722278740%_ _%$%g278723278744%_)))))
          (_%$%g278721278795%_ _%$stx278718%_))))
    (define |gxc[:0:]#declare-primitive-predicates|
      (lambda (_%$stx278799%_)
        (let* ((_%__stx282385282386%_ _%$stx278799%_)
               (_%$%g278804278829%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx282385282386%_)))))
          (let ((_%__kont282388282389%_
                 (lambda ()
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'begin))
                         '())))
                (_%__kont282390282391%_
                 (lambda (_%$%g278809278876%_
                          _%$%g278810278878%_
                          _%$%g278811278879%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'begin))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0
                                        '#f
                                        'declare-primitive-predicate))
                                     (cons _%$%g278811278879%_
                                           (cons _%$%g278810278878%_ '())))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0
                                              '#f
                                              'declare-primitive-predicates))
                                           _%$%g278809278876%_)
                                     '()))))))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx282385282386%_))
                (let ((_%$%e278806278905%_
                       (let ()
                         (declare (not safe))
                         (gx#syntax-e _%__stx282385282386%_))))
                  (let ((_%$%tl278808278912%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e278806278905%_)))
                        (_%$%hd278807278909%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e278806278905%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl278808278912%_))
                        (_%__kont282388282389%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl278808278912%_))
                            (let ((_%$%e278815278846%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#syntax-e _%$%tl278808278912%_))))
                              (let ((_%$%tl278817278853%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e278815278846%_)))
                                    (_%$%hd278816278850%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e278815278846%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%hd278816278850%_))
                                    (let ((_%$%e278818278856%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-e
                                              _%$%hd278816278850%_))))
                                      (let ((_%$%tl278820278863%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e278818278856%_)))
                                            (_%$%hd278819278860%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e278818278856%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl278820278863%_))
                                            (let ((_%$%e278821278866%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-e
                                                      _%$%tl278820278863%_))))
                                              (let ((_%$%tl278823278873%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e278821278866%_)))
                                                    (_%$%hd278822278870%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e278821278866%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl278823278873%_))
                                                    (_%__kont282390282391%_
                                                     _%$%tl278817278853%_
                                                     _%$%hd278822278870%_
                                                     _%$%hd278819278860%_)
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g278804278829%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g278804278829%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g278804278829%_)))))
                            (let ()
                              (declare (not safe))
                              (_%$%g278804278829%_))))))
                (let () (declare (not safe)) (_%$%g278804278829%_)))))))
    (define |gxc[:0:]#declare-primitive-procedures|
      (lambda (_%$stx278923%_)
        (let* ((_%__stx282429282430%_ _%$stx278923%_)
               (_%$%g278928278959%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx282429282430%_)))))
          (let ((_%__kont282432282433%_
                 (lambda ()
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'begin))
                         '())))
                (_%__kont282434282435%_
                 (lambda (_%$%g278933279024%_
                          _%$%g278934279026%_
                          _%$%g278935279027%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'begin))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0
                                        '#f
                                        'declare-primitive-procedure))
                                     (cons _%$%g278935279027%_
                                           (let ((__tmp282906
                                                  (lambda (_%$%g279047279050%_
                                                           _%$%g279048279053%_)
                                                    (cons _%$%g279047279050%_
                                                          _%$%g279048279053%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp282906
                                              '()
                                              _%$%g278934279026%_))))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0
                                              '#f
                                              'declare-primitive-procedures))
                                           _%$%g278933279024%_)
                                     '()))))))
            (let ((_%__match282472282473%_
                   (lambda (_%$%e278936278966%_
                            _%$%hd278937278970%_
                            _%$%tl278938278973%_
                            _%$%e278939278976%_
                            _%$%hd278940278980%_
                            _%$%tl278941278983%_
                            _%$%e278942278986%_
                            _%$%hd278943278990%_
                            _%$%tl278944278993%_
                            _%__splice282436282437%_
                            _%$%target278945278996%_
                            _%$%tl278947278999%_)
                     (letrec ((_%$%loop278948279002%_
                               (lambda (_%$%hd278946279006%_
                                        _%$%sig278952279009%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%hd278946279006%_))
                                     (let ((_%$%e278949279011%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#syntax-e
                                               _%$%hd278946279006%_))))
                                       (let ((_%$%lp-tl278951279018%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e278949279011%_)))
                                             (_%$%lp-hd278950279015%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e278949279011%_))))
                                         (_%$%loop278948279002%_
                                          _%$%lp-tl278951279018%_
                                          (cons _%$%lp-hd278950279015%_
                                                _%$%sig278952279009%_))))
                                     (let ((_%$%sig278953279021%_
                                            (reverse _%$%sig278952279009%_)))
                                       (_%__kont282434282435%_
                                        _%$%tl278941278983%_
                                        _%$%sig278953279021%_
                                        _%$%hd278943278990%_))))))
                       (_%$%loop278948279002%_
                        _%$%target278945278996%_
                        '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx282429282430%_))
                  (let ((_%$%e278930279063%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%__stx282429282430%_))))
                    (let ((_%$%tl278932279070%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e278930279063%_)))
                          (_%$%hd278931279067%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e278930279063%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl278932279070%_))
                          (_%__kont282432282433%_)
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl278932279070%_))
                              (let ((_%$%e278939278976%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl278932279070%_))))
                                (let ((_%$%tl278941278983%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e278939278976%_)))
                                      (_%$%hd278940278980%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e278939278976%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd278940278980%_))
                                      (let ((_%$%e278942278986%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%hd278940278980%_))))
                                        (let ((_%$%tl278944278993%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e278942278986%_)))
                                              (_%$%hd278943278990%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e278942278986%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair/null?
                                                 _%$%tl278944278993%_))
                                              (let ((_%__splice282436282437%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-split-splice->vector
                                                        _%$%tl278944278993%_
                                                        '0))))
                                                (let ((_%$%tl278947278999%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice282436282437%_
                                                          '1)))
                                                      (_%$%target278945278996%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice282436282437%_
                                                          '0))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl278947278999%_))
                                                      (_%__match282472282473%_
                                                       _%$%e278930279063%_
                                                       _%$%hd278931279067%_
                                                       _%$%tl278932279070%_
                                                       _%$%e278939278976%_
                                                       _%$%hd278940278980%_
                                                       _%$%tl278941278983%_
                                                       _%$%e278942278986%_
                                                       _%$%hd278943278990%_
                                                       _%$%tl278944278993%_
                                                       _%__splice282436282437%_
                                                       _%$%target278945278996%_
                                                       _%$%tl278947278999%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g278928278959%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g278928278959%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g278928278959%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g278928278959%_))))))
                  (let () (declare (not safe)) (_%$%g278928278959%_))))))))
    (define |gxc[:0:]#declare-primitive-procedure|
      (lambda (_%$stx279082%_)
        (let* ((_%__stx282475282476%_ _%$stx279082%_)
               (_%$%g279087279134%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx282475282476%_)))))
          (let ((_%__kont282478282479%_
                 (lambda (_%$%g279089279292%_ _%$%g279090279294%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0
                            '#f
                            'declare-primitive-case-lambda))
                         (cons _%$%g279090279294%_
                               (let ((__tmp282907
                                      (lambda (_%$%g279314279317%_
                                               _%$%g279315279320%_)
                                        (cons _%$%g279314279317%_
                                              _%$%g279315279320%_))))
                                 (declare (not safe))
                                 (foldr__0
                                  __tmp282907
                                  '()
                                  _%$%g279089279292%_))))))
                (_%__kont282482282483%_
                 (lambda (_%$%g279112279189%_ _%$%g279113279191%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f 'declare-primitive-lambda))
                         (cons _%$%g279113279191%_
                               (let ((__tmp282908
                                      (lambda (_%$%g279208279211%_
                                               _%$%g279209279214%_)
                                        (cons _%$%g279208279211%_
                                              _%$%g279209279214%_))))
                                 (declare (not safe))
                                 (foldr__0
                                  __tmp282908
                                  '()
                                  _%$%g279112279189%_)))))))
            (let* ((_%__match282542282543%_
                    (lambda (_%$%e279114279141%_
                             _%$%hd279115279145%_
                             _%$%tl279116279148%_
                             _%$%e279117279151%_
                             _%$%hd279118279155%_
                             _%$%tl279119279158%_
                             _%__splice282484282485%_
                             _%$%target279120279161%_
                             _%$%tl279122279164%_)
                      (letrec ((_%$%loop279123279167%_
                                (lambda (_%$%hd279121279171%_
                                         _%$%sig279127279174%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd279121279171%_))
                                      (let ((_%$%e279124279176%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%hd279121279171%_))))
                                        (let ((_%$%lp-tl279126279183%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e279124279176%_)))
                                              (_%$%lp-hd279125279180%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e279124279176%_))))
                                          (_%$%loop279123279167%_
                                           _%$%lp-tl279126279183%_
                                           (cons _%$%lp-hd279125279180%_
                                                 _%$%sig279127279174%_))))
                                      (let ((_%$%sig279128279186%_
                                             (reverse _%$%sig279127279174%_)))
                                        (_%__kont282482282483%_
                                         _%$%sig279128279186%_
                                         _%$%hd279118279155%_))))))
                        (_%$%loop279123279167%_
                         _%$%target279120279161%_
                         '()))))
                   (_%__match282534282535%_
                    (lambda (_%$%e279114279141%_
                             _%$%hd279115279145%_
                             _%$%tl279116279148%_
                             _%$%e279117279151%_
                             _%$%hd279118279155%_
                             _%$%tl279119279158%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair/null? _%$%tl279119279158%_))
                          (let ((_%__splice282484282485%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-split-splice->vector
                                    _%$%tl279119279158%_
                                    '0))))
                            (let ((_%$%tl279122279164%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice282484282485%_
                                      '1)))
                                  (_%$%target279120279161%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice282484282485%_
                                      '0))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl279122279164%_))
                                  (_%__match282542282543%_
                                   _%$%e279114279141%_
                                   _%$%hd279115279145%_
                                   _%$%tl279116279148%_
                                   _%$%e279117279151%_
                                   _%$%hd279118279155%_
                                   _%$%tl279119279158%_
                                   _%__splice282484282485%_
                                   _%$%target279120279161%_
                                   _%$%tl279122279164%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g279087279134%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g279087279134%_)))))
                   (_%__match282522282523%_
                    (lambda (_%$%e279091279224%_
                             _%$%hd279092279228%_
                             _%$%tl279093279231%_
                             _%$%e279094279234%_
                             _%$%hd279095279238%_
                             _%$%tl279096279241%_
                             _%$%e279097279244%_
                             _%$%hd279098279248%_
                             _%$%tl279099279251%_
                             _%$%e279100279254%_
                             _%$%hd279101279258%_
                             _%$%tl279102279261%_
                             _%__splice282480282481%_
                             _%$%target279103279264%_
                             _%$%tl279105279267%_)
                      (letrec ((_%$%loop279106279270%_
                                (lambda (_%$%hd279104279274%_
                                         _%$%sig279110279277%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd279104279274%_))
                                      (let ((_%$%e279107279279%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%hd279104279274%_))))
                                        (let ((_%$%lp-tl279109279286%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e279107279279%_)))
                                              (_%$%lp-hd279108279283%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e279107279279%_))))
                                          (_%$%loop279106279270%_
                                           _%$%lp-tl279109279286%_
                                           (cons _%$%lp-hd279108279283%_
                                                 _%$%sig279110279277%_))))
                                      (let ((_%$%sig279111279289%_
                                             (reverse _%$%sig279110279277%_)))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl279099279251%_))
                                            (_%__kont282478282479%_
                                             _%$%sig279111279289%_
                                             _%$%hd279095279238%_)
                                            (_%__match282534282535%_
                                             _%$%e279091279224%_
                                             _%$%hd279092279228%_
                                             _%$%tl279093279231%_
                                             _%$%e279094279234%_
                                             _%$%hd279095279238%_
                                             _%$%tl279096279241%_)))))))
                        (_%$%loop279106279270%_
                         _%$%target279103279264%_
                         '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx282475282476%_))
                  (let ((_%$%e279091279224%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%__stx282475282476%_))))
                    (let ((_%$%tl279093279231%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e279091279224%_)))
                          (_%$%hd279092279228%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e279091279224%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl279093279231%_))
                          (let ((_%$%e279094279234%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%tl279093279231%_))))
                            (let ((_%$%tl279096279241%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e279094279234%_)))
                                  (_%$%hd279095279238%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e279094279234%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl279096279241%_))
                                  (let ((_%$%e279097279244%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#syntax-e
                                            _%$%tl279096279241%_))))
                                    (let ((_%$%tl279099279251%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e279097279244%_)))
                                          (_%$%hd279098279248%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e279097279244%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%hd279098279248%_))
                                          (let ((_%$%e279100279254%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#syntax-e
                                                    _%$%hd279098279248%_))))
                                            (let ((_%$%tl279102279261%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e279100279254%_)))
                                                  (_%$%hd279101279258%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e279100279254%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#identifier?
                                                     _%$%hd279101279258%_))
                                                  (if (let ((__tmp282909
                                                             |gxc[1]#_g282910_|))
                                                        (declare (not safe))
                                                        (gx#free-identifier=?
                                                         __tmp282909
                                                         _%$%hd279101279258%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair/null?
                                                             _%$%tl279102279261%_))
                                                          (let ((_%__splice282480282481%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#syntax-split-splice->vector
                            _%$%tl279102279261%_
                            '0))))
                    (let ((_%$%tl279105279267%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice282480282481%_ '1)))
                          (_%$%target279103279264%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice282480282481%_ '0))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl279105279267%_))
                          (_%__match282522282523%_
                           _%$%e279091279224%_
                           _%$%hd279092279228%_
                           _%$%tl279093279231%_
                           _%$%e279094279234%_
                           _%$%hd279095279238%_
                           _%$%tl279096279241%_
                           _%$%e279097279244%_
                           _%$%hd279098279248%_
                           _%$%tl279099279251%_
                           _%$%e279100279254%_
                           _%$%hd279101279258%_
                           _%$%tl279102279261%_
                           _%__splice282480282481%_
                           _%$%target279103279264%_
                           _%$%tl279105279267%_)
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl279096279241%_))
                              (let ((_%__splice282484282485%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice->vector
                                        _%$%tl279096279241%_
                                        '0))))
                                (let ((_%$%tl279122279164%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice282484282485%_
                                          '1)))
                                      (_%$%target279120279161%_
                                       (let ()
                                         (declare (not safe))
                                         (##vector-ref
                                          _%__splice282484282485%_
                                          '0))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl279122279164%_))
                                      (_%__match282542282543%_
                                       _%$%e279091279224%_
                                       _%$%hd279092279228%_
                                       _%$%tl279093279231%_
                                       _%$%e279094279234%_
                                       _%$%hd279095279238%_
                                       _%$%tl279096279241%_
                                       _%__splice282484282485%_
                                       _%$%target279120279161%_
                                       _%$%tl279122279164%_)
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g279087279134%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g279087279134%_))))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair/null? _%$%tl279096279241%_))
                      (let ((_%__splice282484282485%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-split-splice->vector
                                _%$%tl279096279241%_
                                '0))))
                        (let ((_%$%tl279122279164%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice282484282485%_ '1)))
                              (_%$%target279120279161%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice282484282485%_ '0))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl279122279164%_))
                              (_%__match282542282543%_
                               _%$%e279091279224%_
                               _%$%hd279092279228%_
                               _%$%tl279093279231%_
                               _%$%e279094279234%_
                               _%$%hd279095279238%_
                               _%$%tl279096279241%_
                               _%__splice282484282485%_
                               _%$%target279120279161%_
                               _%$%tl279122279164%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g279087279134%_)))))
                      (let () (declare (not safe)) (_%$%g279087279134%_))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair/null? _%$%tl279096279241%_))
                  (let ((_%__splice282484282485%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-split-splice->vector
                            _%$%tl279096279241%_
                            '0))))
                    (let ((_%$%tl279122279164%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice282484282485%_ '1)))
                          (_%$%target279120279161%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref _%__splice282484282485%_ '0))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl279122279164%_))
                          (_%__match282542282543%_
                           _%$%e279091279224%_
                           _%$%hd279092279228%_
                           _%$%tl279093279231%_
                           _%$%e279094279234%_
                           _%$%hd279095279238%_
                           _%$%tl279096279241%_
                           _%__splice282484282485%_
                           _%$%target279120279161%_
                           _%$%tl279122279164%_)
                          (let ()
                            (declare (not safe))
                            (_%$%g279087279134%_)))))
                  (let () (declare (not safe)) (_%$%g279087279134%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair/null?
                                                         _%$%tl279096279241%_))
                                                      (let ((_%__splice282484282485%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-split-splice->vector
                        _%$%tl279096279241%_
                        '0))))
                (let ((_%$%tl279122279164%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice282484282485%_ '1)))
                      (_%$%target279120279161%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice282484282485%_ '0))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl279122279164%_))
                      (_%__match282542282543%_
                       _%$%e279091279224%_
                       _%$%hd279092279228%_
                       _%$%tl279093279231%_
                       _%$%e279094279234%_
                       _%$%hd279095279238%_
                       _%$%tl279096279241%_
                       _%__splice282484282485%_
                       _%$%target279120279161%_
                       _%$%tl279122279164%_)
                      (let () (declare (not safe)) (_%$%g279087279134%_)))))
              (let () (declare (not safe)) (_%$%g279087279134%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair/null?
                                                 _%$%tl279096279241%_))
                                              (let ((_%__splice282484282485%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-split-splice->vector
                                                        _%$%tl279096279241%_
                                                        '0))))
                                                (let ((_%$%tl279122279164%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice282484282485%_
                                                          '1)))
                                                      (_%$%target279120279161%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice282484282485%_
                                                          '0))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl279122279164%_))
                                                      (_%__match282542282543%_
                                                       _%$%e279091279224%_
                                                       _%$%hd279092279228%_
                                                       _%$%tl279093279231%_
                                                       _%$%e279094279234%_
                                                       _%$%hd279095279238%_
                                                       _%$%tl279096279241%_
                                                       _%__splice282484282485%_
                                                       _%$%target279120279161%_
                                                       _%$%tl279122279164%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g279087279134%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g279087279134%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl279096279241%_))
                                      (let ((_%__splice282484282485%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice->vector
                                                _%$%tl279096279241%_
                                                '0))))
                                        (let ((_%$%tl279122279164%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice282484282485%_
                                                  '1)))
                                              (_%$%target279120279161%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice282484282485%_
                                                  '0))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl279122279164%_))
                                              (_%__match282542282543%_
                                               _%$%e279091279224%_
                                               _%$%hd279092279228%_
                                               _%$%tl279093279231%_
                                               _%$%e279094279234%_
                                               _%$%hd279095279238%_
                                               _%$%tl279096279241%_
                                               _%__splice282484282485%_
                                               _%$%target279120279161%_
                                               _%$%tl279122279164%_)
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g279087279134%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g279087279134%_))))))
                          (let ()
                            (declare (not safe))
                            (_%$%g279087279134%_)))))
                  (let () (declare (not safe)) (_%$%g279087279134%_))))))))
    (define |gxc[1]#verify-procedure!|
      (lambda (_%ctx280477%_ _%id280479%_)
        (let ((_%proc280483%_
               (let ((__tmp282911
                      (lambda ()
                        (let ()
                          (declare (not safe))
                          (gx#eval-syntax__0 _%id280479%_)))))
                 (declare (not safe))
                 (__with-catch false __tmp282911))))
          (if (procedure? _%proc280483%_)
              '#!void
              (let ()
                (declare (not safe))
                (gx#raise-syntax-error
                 '#f
                 '"unknown procedure"
                 _%ctx280477%_
                 _%id280479%_))))))
    (define |gxc[1]#verify-class!|
      (lambda (_%ctx280468%_ _%id280470%_)
        (let ((_%klass280474%_
               (let ((__tmp282912
                      (lambda ()
                        (let ()
                          (declare (not safe))
                          (gx#eval-syntax__0 _%id280470%_)))))
                 (declare (not safe))
                 (__with-catch false __tmp282912))))
          (if (let ()
                (declare (not safe))
                (##structure-instance-of? _%klass280474%_ 'class))
              '#!void
              (let ()
                (declare (not safe))
                (gx#raise-syntax-error
                 '#f
                 '"unknown class"
                 _%ctx280468%_
                 _%id280470%_))))))
    (define |gxc[1]#parse-signature|
      (lambda (_%ctx279718%_ _%proc279720%_ _%sig279721%_)
        (letrec ((_%signature-arity279723%_
                  (lambda (_%args280400%_)
                    (let _%loop280403%_ ((_%rest280406%_ _%args280400%_)
                                         (_%count280408%_ '0))
                      (let* ((_%$%rest280409280420%_ _%rest280406%_)
                             (_%$%E280413280426%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (error '"No clause matching"
                                         _%$%rest280409280420%_
                                         '([_ . rest])
                                         '([])
                                         '(_)))
                                '#!void)))
                        (let ((_%$%K280416280457%_
                               (lambda (_%rest280454%_)
                                 (_%loop280403%_
                                  _%rest280454%_
                                  (let ()
                                    (declare (not safe))
                                    (##fx+ _%count280408%_ '1)))))
                              (_%$%K280415280446%_ (lambda () _%count280408%_))
                              (_%$%K280414280434%_
                               (lambda () (cons _%count280408%_ '()))))
                          (let ((_%$%try-match280411280450%_
                                 (lambda ()
                                   (if (null? _%$%rest280409280420%_)
                                       (_%$%K280415280446%_)
                                       (_%$%K280414280434%_)))))
                            (if (pair? _%$%rest280409280420%_)
                                (let* ((_%$%tl280418280461%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%rest280409280420%_)))
                                       (_%rest280465%_ _%$%tl280418280461%_))
                                  (_%$%K280416280457%_ _%rest280465%_))
                                (_%$%try-match280411280450%_))))))))
                 (_%make-signature279725%_
                  (lambda (_%args280282%_
                           _%return280284%_
                           _%effect280285%_
                           _%unchecked280286%_)
                    (let ((__tmp282913
                           (lambda (_%$%g280287280289%_)
                             (|gxc[1]#verify-class!|
                              _%ctx279718%_
                              _%$%g280287280289%_))))
                      (declare (not safe))
                      (gx#stx-for-each1 __tmp282913 _%args280282%_))
                    (|gxc[1]#verify-class!| _%ctx279718%_ _%return280284%_)
                    (if _%unchecked280286%_
                        (|gxc[1]#verify-procedure!|
                         _%ctx279718%_
                         _%unchecked280286%_)
                        '#!void)
                    (let ((_%arity280293%_
                           (_%signature-arity279723%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-map1 gx#stx-e _%args280282%_)))))
                      (if _%effect280285%_
                          (let ((_%effect280296%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax->datum _%effect280285%_))))
                            (if (and (list? _%effect280296%_)
                                     (let ()
                                       (declare (not safe))
                                       (andmap__0 symbol? _%effect280296%_)))
                                '#!void
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"bad effect"
                                   _%ctx279718%_
                                   _%proc279720%_
                                   _%effect280296%_))))
                          '#!void)
                      (cons _%arity280293%_
                            (cons (let* ((_%$%g280299280322%_
                                          (lambda (_%$%g280300280318%_)
                                            (let ()
                                              (declare (not safe))
                                              (gx#raise-syntax-error
                                               '#f
                                               '"Bad syntax; invalid match target"
                                               _%$%g280300280318%_))))
                                         (_%$%g280298280396%_
                                          (lambda (_%$%g280300280326%_)
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%g280300280326%_))
                                                (let ((_%$%e280305280329%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#syntax-e
                                                          _%$%g280300280326%_))))
                                                  (let ((_%$%hd280306280333%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e280305280329%_)))
                                                        (_%$%tl280307280336%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e280305280329%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl280307280336%_))
                                                        (let ((_%$%e280308280339%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%tl280307280336%_))))
                  (let ((_%$%hd280309280343%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e280308280339%_)))
                        (_%$%tl280310280346%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e280308280339%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl280310280346%_))
                        (let ((_%$%e280311280349%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl280310280346%_))))
                          (let ((_%$%hd280312280353%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e280311280349%_)))
                                (_%$%tl280313280356%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e280311280349%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl280313280356%_))
                                (let ((_%$%e280314280359%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl280313280356%_))))
                                  (let ((_%$%hd280315280363%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e280314280359%_)))
                                        (_%$%tl280316280366%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e280314280359%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl280316280366%_))
                                        (cons (let ()
                                                (declare (not safe))
                                                (gx#datum->syntax__0
                                                 '#f
                                                 'make-!signature))
                                              (cons 'arguments:
                                                    (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'quote))
                        (cons _%$%hd280306280333%_ '()))
                  (cons 'return:
                        (cons (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f 'quote))
                                    (cons _%$%hd280309280343%_ '()))
                              (cons 'effect:
                                    (cons (cons (let ()
                                                  (declare (not safe))
                                                  (gx#datum->syntax__0
                                                   '#f
                                                   'quote))
                                                (cons _%$%hd280312280353%_
                                                      '()))
                                          (cons 'unchecked:
                                                (cons (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'quote))
                                                            (cons _%$%hd280315280363%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              (cons 'origin:
                    (cons (cons (let ()
                                  (declare (not safe))
                                  (gx#datum->syntax__0 '#f 'quote))
                                (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f 'builtin))
                                      '()))
                          '())))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (_%$%g280299280322%_
                                         _%$%g280300280326%_))))
                                (_%$%g280299280322%_ _%$%g280300280326%_))))
                        (_%$%g280299280322%_ _%$%g280300280326%_))))
                (_%$%g280299280322%_ _%$%g280300280326%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g280299280322%_
                                                 _%$%g280300280326%_)))))
                                    (_%$%g280298280396%_
                                     (list _%args280282%_
                                           _%return280284%_
                                           _%effect280285%_
                                           _%unchecked280286%_)))
                                  '()))))))
          (|gxc[1]#verify-procedure!| _%ctx279718%_ _%proc279720%_)
          (let* ((_%__stx282553282554%_ _%sig279721%_)
                 (_%$%g279732279835%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%__stx282553282554%_)))))
            (let ((_%__kont282556282557%_
                   (lambda (_%$%g279734280263%_ _%$%g279735280265%_)
                     (_%make-signature279725%_
                      _%$%g279735280265%_
                      _%$%g279734280263%_
                      '#f
                      '#f)))
                  (_%__kont282558282559%_
                   (lambda (_%$%g279742280214%_
                            _%$%g279743280216%_
                            _%$%g279744280217%_)
                     (_%make-signature279725%_
                      _%$%g279744280217%_
                      _%$%g279743280216%_
                      _%$%g279742280214%_
                      '#f)))
                  (_%__kont282560282561%_
                   (lambda (_%$%g279758280138%_
                            _%$%g279759280140%_
                            _%$%g279760280141%_)
                     (_%make-signature279725%_
                      _%$%g279760280141%_
                      _%$%g279759280140%_
                      _%$%g279758280138%_
                      (let ((__tmp282914
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%proc279720%_))))
                        (declare (not safe))
                        (make-symbol__1 '"##" __tmp282914)))))
                  (_%__kont282562282563%_
                   (lambda (_%$%g279778280044%_
                            _%$%g279779280046%_
                            _%$%g279780280047%_
                            _%$%g279781280048%_)
                     (_%make-signature279725%_
                      _%$%g279781280048%_
                      _%$%g279780280047%_
                      '#f
                      (let ()
                        (declare (not safe))
                        (gx#stx-e _%$%g279778280044%_)))))
                  (_%__kont282564282565%_
                   (lambda (_%$%g279802279951%_ _%$%g279803279953%_)
                     (_%make-signature279725%_
                      _%$%g279803279953%_
                      _%$%g279802279951%_
                      '#f
                      (let ((__tmp282915
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%proc279720%_))))
                        (declare (not safe))
                        (make-symbol__1 '"##" __tmp282915)))))
                  (_%__kont282566282567%_
                   (lambda (_%$%g279814279886%_
                            _%$%g279815279888%_
                            _%$%g279816279889%_)
                     (_%make-signature279725%_
                      _%$%g279816279889%_
                      _%$%g279815279888%_
                      '#f
                      (let ()
                        (declare (not safe))
                        (gx#stx-e _%$%g279814279886%_))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx282553282554%_))
                  (let ((_%$%e279736280243%_
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%__stx282553282554%_))))
                    (let ((_%$%tl279738280250%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e279736280243%_)))
                          (_%$%hd279737280247%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e279736280243%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl279738280250%_))
                          (let ((_%$%e279739280253%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%tl279738280250%_))))
                            (let ((_%$%tl279741280260%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e279739280253%_)))
                                  (_%$%hd279740280257%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e279739280253%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl279741280260%_))
                                  (_%__kont282556282557%_
                                   _%$%hd279740280257%_
                                   _%$%hd279737280247%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl279741280260%_))
                                      (let ((_%$%e279751280190%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl279741280260%_))))
                                        (let ((_%$%tl279753280197%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e279751280190%_)))
                                              (_%$%hd279752280194%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e279751280190%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-datum?
                                                 _%$%hd279752280194%_))
                                              (let ((_%$%e279754280200%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd279752280194%_))))
                                                (if (equal? _%$%e279754280200%_
                                                            'effect:)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl279753280197%_))
                                                        (let ((_%$%e279755280204%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%tl279753280197%_))))
                  (let ((_%$%tl279757280211%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e279755280204%_)))
                        (_%$%hd279756280208%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e279755280204%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl279757280211%_))
                        (_%__kont282558282559%_
                         _%$%hd279756280208%_
                         _%$%hd279740280257%_
                         _%$%hd279737280247%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl279757280211%_))
                            (let ((_%$%e279774280124%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#syntax-e _%$%tl279757280211%_))))
                              (let ((_%$%tl279776280131%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e279774280124%_)))
                                    (_%$%hd279775280128%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e279774280124%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-datum? _%$%hd279775280128%_))
                                    (let ((_%$%e279777280134%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%hd279775280128%_))))
                                      (if (equal? _%$%e279777280134%_
                                                  'unchecked:)
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl279776280131%_))
                                              (_%__kont282560282561%_
                                               _%$%hd279756280208%_
                                               _%$%hd279740280257%_
                                               _%$%hd279737280247%_)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl279776280131%_))
                                                  (let ((_%$%e279799280034%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%tl279776280131%_))))
                                                    (let ((_%$%tl279801280041%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e279799280034%_)))
                                                          (_%$%hd279800280038%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e279799280034%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl279801280041%_))
                                                          (_%__kont282562282563%_
                                                           _%$%hd279800280038%_
                                                           _%$%hd279756280208%_
                                                           _%$%hd279740280257%_
                                                           _%$%hd279737280247%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g279732279835%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g279732279835%_))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g279732279835%_))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g279732279835%_)))))
                            (let ()
                              (declare (not safe))
                              (_%$%g279732279835%_))))))
                (let () (declare (not safe)) (_%$%g279732279835%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (equal? _%$%e279754280200%_
                                                                'unchecked:)
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-null?
                                                               _%$%tl279753280197%_))
                                                            (_%__kont282564282565%_
                                                             _%$%hd279740280257%_
                                                             _%$%hd279737280247%_)
                                                            (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl279753280197%_))
                        (let ((_%$%e279827279876%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl279753280197%_))))
                          (let ((_%$%tl279829279883%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e279827279876%_)))
                                (_%$%hd279828279880%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e279827279876%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl279829279883%_))
                                (_%__kont282566282567%_
                                 _%$%hd279828279880%_
                                 _%$%hd279740280257%_
                                 _%$%hd279737280247%_)
                                (let ()
                                  (declare (not safe))
                                  (_%$%g279732279835%_)))))
                        (let () (declare (not safe)) (_%$%g279732279835%_))))
                (let () (declare (not safe)) (_%$%g279732279835%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g279732279835%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g279732279835%_))))))
                          (let ()
                            (declare (not safe))
                            (_%$%g279732279835%_)))))
                  (let () (declare (not safe)) (_%$%g279732279835%_))))))))
    (define |gxc[1]#signature->unchecked-signature|
      (lambda (_%sig279329%_)
        (let* ((_%$%g279332279412%_
                (lambda (_%$%g279333279408%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g279333279408%_))))
               (_%$%g279331279714%_
                (lambda (_%$%g279333279416%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g279333279416%_))
                      (let ((_%$%e279339279419%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g279333279416%_))))
                        (let ((_%$%hd279340279423%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e279339279419%_)))
                              (_%$%tl279341279426%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e279339279419%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl279341279426%_))
                              (let ((_%$%e279342279429%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl279341279426%_))))
                                (let ((_%$%hd279343279433%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e279342279429%_)))
                                      (_%$%tl279344279436%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e279342279429%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-datum? _%$%hd279343279433%_))
                                      (let ((_%$%e279345279439%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd279343279433%_))))
                                        (if (equal? _%$%e279345279439%_
                                                    'arguments:)
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl279344279436%_))
                                                (let ((_%$%e279346279443%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#syntax-e
                                                          _%$%tl279344279436%_))))
                                                  (let ((_%$%hd279347279447%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e279346279443%_)))
                                                        (_%$%tl279348279450%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e279346279443%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd279347279447%_))
                                                        (let ((_%$%e279349279453%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%hd279347279447%_))))
                  (let ((_%$%hd279350279457%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e279349279453%_)))
                        (_%$%tl279351279460%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e279349279453%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#identifier? _%$%hd279350279457%_))
                        (if (let ((__tmp282916 |gxc[1]#_g282917_|))
                              (declare (not safe))
                              (gx#free-identifier=?
                               __tmp282916
                               _%$%hd279350279457%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl279351279460%_))
                                (let ((_%$%e279352279463%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl279351279460%_))))
                                  (let ((_%$%hd279353279467%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e279352279463%_)))
                                        (_%$%tl279354279470%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e279352279463%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl279354279470%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl279348279450%_))
                                            (let ((_%$%e279355279473%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-e
                                                      _%$%tl279348279450%_))))
                                              (let ((_%$%hd279356279477%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e279355279473%_)))
                                                    (_%$%tl279357279480%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e279355279473%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-datum?
                                                       _%$%hd279356279477%_))
                                                    (let ((_%$%e279358279483%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%hd279356279477%_))))
                                                      (if (equal? _%$%e279358279483%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          'return:)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl279357279480%_))
                      (let ((_%$%e279359279487%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%tl279357279480%_))))
                        (let ((_%$%hd279360279491%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e279359279487%_)))
                              (_%$%tl279361279494%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e279359279487%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd279360279491%_))
                              (let ((_%$%e279362279497%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%hd279360279491%_))))
                                (let ((_%$%hd279363279501%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e279362279497%_)))
                                      (_%$%tl279364279504%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e279362279497%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd279363279501%_))
                                      (if (let ((__tmp282918
                                                 |gxc[1]#_g282919_|))
                                            (declare (not safe))
                                            (gx#free-identifier=?
                                             __tmp282918
                                             _%$%hd279363279501%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl279364279504%_))
                                              (let ((_%$%e279365279507%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl279364279504%_))))
                                                (let ((_%$%hd279366279511%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e279365279507%_)))
                                                      (_%$%tl279367279514%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e279365279507%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl279367279514%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl279361279494%_))
                                                          (let ((_%$%e279368279517%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%$%tl279361279494%_))))
                    (let ((_%$%hd279369279521%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e279368279517%_)))
                          (_%$%tl279370279524%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e279368279517%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-datum? _%$%hd279369279521%_))
                          (let ((_%$%e279371279527%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%hd279369279521%_))))
                            (if (equal? _%$%e279371279527%_ 'effect:)
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%tl279370279524%_))
                                    (let ((_%$%e279372279531%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-e
                                              _%$%tl279370279524%_))))
                                      (let ((_%$%hd279373279535%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e279372279531%_)))
                                            (_%$%tl279374279538%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e279372279531%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%hd279373279535%_))
                                            (let ((_%$%e279375279541%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-e
                                                      _%$%hd279373279535%_))))
                                              (let ((_%$%hd279376279545%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e279375279541%_)))
                                                    (_%$%tl279377279548%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e279375279541%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#identifier?
                                                       _%$%hd279376279545%_))
                                                    (if (let ((__tmp282920
                                                               |gxc[1]#_g282921_|))
                                                          (declare (not safe))
                                                          (gx#free-identifier=?
                                                           __tmp282920
                                                           _%$%hd279376279545%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl279377279548%_))
                                                            (let ((_%$%e279378279551%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#syntax-e _%$%tl279377279548%_))))
                      (let ((_%$%hd279379279555%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e279378279551%_)))
                            (_%$%tl279380279558%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e279378279551%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl279380279558%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl279374279538%_))
                                (let ((_%$%e279381279561%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%tl279374279538%_))))
                                  (let ((_%$%hd279382279565%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e279381279561%_)))
                                        (_%$%tl279383279568%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e279381279561%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-datum? _%$%hd279382279565%_))
                                        (let ((_%$%e279384279571%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd279382279565%_))))
                                          (if (equal? _%$%e279384279571%_
                                                      'unchecked:)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl279383279568%_))
                                                  (let ((_%$%e279385279575%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%tl279383279568%_))))
                                                    (let ((_%$%hd279386279579%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e279385279575%_)))
                                                          (_%$%tl279387279582%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e279385279575%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%hd279386279579%_))
                                                          (let ((_%$%e279388279585%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%$%hd279386279579%_))))
                    (let ((_%$%hd279389279589%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e279388279585%_)))
                          (_%$%tl279390279592%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e279388279585%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#identifier? _%$%hd279389279589%_))
                          (if (let ((__tmp282922 |gxc[1]#_g282923_|))
                                (declare (not safe))
                                (gx#free-identifier=?
                                 __tmp282922
                                 _%$%hd279389279589%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl279390279592%_))
                                  (let ((_%$%e279391279595%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#syntax-e
                                            _%$%tl279390279592%_))))
                                    (let ((_%$%hd279392279599%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e279391279595%_)))
                                          (_%$%tl279393279602%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e279391279595%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl279393279602%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl279387279582%_))
                                              (let ((_%$%e279394279605%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl279387279582%_))))
                                                (let ((_%$%hd279395279609%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e279394279605%_)))
                                                      (_%$%tl279396279612%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e279394279605%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-datum?
                                                         _%$%hd279395279609%_))
                                                      (let ((_%$%e279397279615%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%hd279395279609%_))))
                (if (equal? _%$%e279397279615%_ 'origin:)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl279396279612%_))
                        (let ((_%$%e279398279619%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl279396279612%_))))
                          (let ((_%$%hd279399279623%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e279398279619%_)))
                                (_%$%tl279400279626%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e279398279619%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%hd279399279623%_))
                                (let ((_%$%e279401279629%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-e _%$%hd279399279623%_))))
                                  (let ((_%$%hd279402279633%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e279401279629%_)))
                                        (_%$%tl279403279636%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e279401279629%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#identifier?
                                           _%$%hd279402279633%_))
                                        (if (let ((__tmp282924
                                                   |gxc[1]#_g282925_|))
                                              (declare (not safe))
                                              (gx#free-identifier=?
                                               __tmp282924
                                               _%$%hd279402279633%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl279403279636%_))
                                                (let ((_%$%e279404279639%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#syntax-e
                                                          _%$%tl279403279636%_))))
                                                  (let ((_%$%hd279405279643%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e279404279639%_)))
                                                        (_%$%tl279406279646%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e279404279639%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl279406279646%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-null?
                                                               _%$%tl279400279626%_))
                                                            (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-e _%$%hd279392279599%_))
                        (cons _%$%hd279392279599%_
                              (cons (cons (let ()
                                            (declare (not safe))
                                            (gx#datum->syntax__0
                                             '#f
                                             'make-!signature))
                                          (cons 'return:
                                                (cons (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'quote))
                                                            (cons _%$%hd279366279511%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              (cons 'origin:
                    (cons (cons (let ()
                                  (declare (not safe))
                                  (gx#datum->syntax__0 '#f 'quote))
                                (cons _%$%hd279405279643%_ '()))
                          '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '()))
                        '#f)
                    (_%$%g279332279412%_ _%$%g279333279416%_))
                (_%$%g279332279412%_ _%$%g279333279416%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g279332279412%_
                                                 _%$%g279333279416%_))
                                            (_%$%g279332279412%_
                                             _%$%g279333279416%_))
                                        (_%$%g279332279412%_
                                         _%$%g279333279416%_))))
                                (_%$%g279332279412%_ _%$%g279333279416%_))))
                        (_%$%g279332279412%_ _%$%g279333279416%_))
                    (_%$%g279332279412%_ _%$%g279333279416%_)))
              (_%$%g279332279412%_ _%$%g279333279416%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g279332279412%_
                                               _%$%g279333279416%_))
                                          (_%$%g279332279412%_
                                           _%$%g279333279416%_))))
                                  (_%$%g279332279412%_ _%$%g279333279416%_))
                              (_%$%g279332279412%_ _%$%g279333279416%_))
                          (_%$%g279332279412%_ _%$%g279333279416%_))))
                  (_%$%g279332279412%_ _%$%g279333279416%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g279332279412%_
                                                   _%$%g279333279416%_))
                                              (_%$%g279332279412%_
                                               _%$%g279333279416%_)))
                                        (_%$%g279332279412%_
                                         _%$%g279333279416%_))))
                                (_%$%g279332279412%_ _%$%g279333279416%_))
                            (_%$%g279332279412%_ _%$%g279333279416%_))))
                    (_%$%g279332279412%_ _%$%g279333279416%_))
                (_%$%g279332279412%_ _%$%g279333279416%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g279332279412%_
                                                     _%$%g279333279416%_))))
                                            (_%$%g279332279412%_
                                             _%$%g279333279416%_))))
                                    (_%$%g279332279412%_ _%$%g279333279416%_))
                                (_%$%g279332279412%_ _%$%g279333279416%_)))
                          (_%$%g279332279412%_ _%$%g279333279416%_))))
                  (_%$%g279332279412%_ _%$%g279333279416%_))
              (_%$%g279332279412%_ _%$%g279333279416%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g279332279412%_
                                               _%$%g279333279416%_))
                                          (_%$%g279332279412%_
                                           _%$%g279333279416%_))
                                      (_%$%g279332279412%_
                                       _%$%g279333279416%_))))
                              (_%$%g279332279412%_ _%$%g279333279416%_))))
                      (_%$%g279332279412%_ _%$%g279333279416%_))
                  (_%$%g279332279412%_ _%$%g279333279416%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g279332279412%_
                                                     _%$%g279333279416%_))))
                                            (_%$%g279332279412%_
                                             _%$%g279333279416%_))
                                        (_%$%g279332279412%_
                                         _%$%g279333279416%_))))
                                (_%$%g279332279412%_ _%$%g279333279416%_))
                            (_%$%g279332279412%_ _%$%g279333279416%_))
                        (_%$%g279332279412%_ _%$%g279333279416%_))))
                (_%$%g279332279412%_ _%$%g279333279416%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g279332279412%_
                                                 _%$%g279333279416%_))
                                            (_%$%g279332279412%_
                                             _%$%g279333279416%_)))
                                      (_%$%g279332279412%_
                                       _%$%g279333279416%_))))
                              (_%$%g279332279412%_ _%$%g279333279416%_))))
                      (_%$%g279332279412%_ _%$%g279333279416%_)))))
          (_%$%g279331279714%_ _%sig279329%_))))
    (define |gxc[:0:]#declare-primitive-predicate|
      (lambda (_%stx280486%_)
        (let* ((_%$%g280489280507%_
                (lambda (_%$%g280490280503%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g280490280503%_))))
               (_%$%g280488280562%_
                (lambda (_%$%g280490280511%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g280490280511%_))
                      (let ((_%$%e280493280514%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g280490280511%_))))
                        (let ((_%$%hd280494280518%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e280493280514%_)))
                              (_%$%tl280495280521%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e280493280514%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl280495280521%_))
                              (let ((_%$%e280496280524%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl280495280521%_))))
                                (let ((_%$%hd280497280528%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e280496280524%_)))
                                      (_%$%tl280498280531%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e280496280524%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl280498280531%_))
                                      (let ((_%$%e280499280534%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl280498280531%_))))
                                        (let ((_%$%hd280500280538%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e280499280534%_)))
                                              (_%$%tl280501280541%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e280499280534%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl280501280541%_))
                                              (if (and (let ()
                                                         (declare (not safe))
                                                         (gx#identifier?
                                                          _%$%hd280497280528%_))
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#identifier?
                                                          _%$%hd280500280538%_)))
                                                  (begin
                                                    (|gxc[1]#verify-procedure!|
                                                     _%stx280486%_
                                                     _%$%hd280497280528%_)
                                                    (|gxc[1]#verify-class!|
                                                     _%stx280486%_
                                                     _%$%hd280500280538%_)
                                                    (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#datum->syntax__0
                                                             '#f
                                                             'declare-type))
                                                          (cons _%$%hd280497280528%_
                                                                (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                      (declare (not safe))
                                      (gx#datum->syntax__0
                                       '#f
                                       'make-!primitive-predicate))
                                    (cons (cons (let ()
                                                  (declare (not safe))
                                                  (gx#datum->syntax__0
                                                   '#f
                                                   'quote))
                                                (cons _%$%hd280500280538%_
                                                      '()))
                                          '()))
                              '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g280489280507%_
                                                   _%$%g280490280511%_))
                                              (_%$%g280489280507%_
                                               _%$%g280490280511%_))))
                                      (_%$%g280489280507%_
                                       _%$%g280490280511%_))))
                              (_%$%g280489280507%_ _%$%g280490280511%_))))
                      (_%$%g280489280507%_ _%$%g280490280511%_)))))
          (_%$%g280488280562%_ _%stx280486%_))))
    (define |gxc[:0:]#declare-primitive-lambda|
      (lambda (_%stx280566%_)
        (let* ((_%$%g280569280593%_
                (lambda (_%$%g280570280589%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g280570280589%_))))
               (_%$%g280568280874%_
                (lambda (_%$%g280570280597%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g280570280597%_))
                      (let ((_%$%e280573280600%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g280570280597%_))))
                        (let ((_%$%hd280574280604%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e280573280600%_)))
                              (_%$%tl280575280607%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e280573280600%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl280575280607%_))
                              (let ((_%$%e280576280610%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl280575280607%_))))
                                (let ((_%$%hd280577280614%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e280576280610%_)))
                                      (_%$%tl280578280617%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e280576280610%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl280578280617%_))
                                      (let ((_g282926_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%tl280578280617%_
                                                '0))))
                                        (begin
                                          (let ((_g282927_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g282926_)
                                                       (##values-length
                                                        _g282926_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g282927_ 2)))
                                                (error "Context expects 2 values"
                                                       _g282927_)))
                                          (let ((_%$%target280579280620%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g282926_ 0)))
                                                (_%$%tl280581280623%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g282926_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl280581280623%_))
                                                (letrec ((_%$%loop280582280626%_
                                                          (lambda (_%$%hd280580280630%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%signature280586280633%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd280580280630%_))
                        (let ((_%$%e280583280635%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%hd280580280630%_))))
                          (let ((_%$%lp-hd280584280639%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e280583280635%_)))
                                (_%$%lp-tl280585280642%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e280583280635%_))))
                            (_%$%loop280582280626%_
                             _%$%lp-tl280585280642%_
                             (cons _%$%lp-hd280584280639%_
                                   _%$%signature280586280633%_))))
                        (let ((_%$%signature280587280645%_
                               (reverse _%$%signature280586280633%_)))
                          (if (let ()
                                (declare (not safe))
                                (gx#identifier? _%$%hd280577280614%_))
                              (let* ((_%$%g280668280683%_
                                      (lambda (_%$%g280669280679%_)
                                        (let ()
                                          (declare (not safe))
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid match target"
                                           _%$%g280669280679%_))))
                                     (_%$%g280667280862%_
                                      (lambda (_%$%g280669280687%_)
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%g280669280687%_))
                                            (let ((_%$%e280672280690%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-e
                                                      _%$%g280669280687%_))))
                                              (let ((_%$%hd280673280694%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e280672280690%_)))
                                                    (_%$%tl280674280697%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e280672280690%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl280674280697%_))
                                                    (let ((_%$%e280675280700%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#syntax-e
                                                              _%$%tl280674280697%_))))
                                                      (let ((_%$%hd280676280704%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e280675280700%_)))
                    (_%$%tl280677280707%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e280675280700%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl280677280707%_))
                    (let* ((_%$%g280728280736%_
                            (lambda (_%$%g280729280732%_)
                              (let ()
                                (declare (not safe))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%$%g280729280732%_))))
                           (_%$%g280727280858%_
                            (lambda (_%$%g280729280740%_)
                              (let* ((_%unchecked280756%_
                                      (|gxc[1]#signature->unchecked-signature|
                                       _%$%hd280676280704%_))
                                     (_%$%g280759280767%_
                                      (lambda (_%$%g280760280763%_)
                                        (let ()
                                          (declare (not safe))
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid match target"
                                           _%$%g280760280763%_))))
                                     (_%$%g280758280790%_
                                      (lambda (_%$%g280760280771%_)
                                        (cons (let ()
                                                (declare (not safe))
                                                (gx#datum->syntax__0
                                                 '#f
                                                 'begin))
                                              (cons _%$%g280729280740%_
                                                    (cons _%$%g280760280771%_
                                                          '()))))))
                                (_%$%g280758280790%_
                                 (if _%unchecked280756%_
                                     (let* ((_%$%g280794280809%_
                                             (lambda (_%$%g280795280805%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#raise-syntax-error
                                                  '#f
                                                  '"Bad syntax; invalid match target"
                                                  _%$%g280795280805%_))))
                                            (_%$%g280793280854%_
                                             (lambda (_%$%g280795280813%_)
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%g280795280813%_))
                                                   (let ((_%$%e280798280816%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#syntax-e
                                                             _%$%g280795280813%_))))
                                                     (let ((_%$%hd280799280820%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e280798280816%_)))
                                                           (_%$%tl280800280823%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e280798280816%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-pair?
                                                              _%$%tl280800280823%_))
                                                           (let ((_%$%e280801280826%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#syntax-e _%$%tl280800280823%_))))
                     (let ((_%$%hd280802280830%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e280801280826%_)))
                           (_%$%tl280803280833%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e280801280826%_))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-null? _%$%tl280803280833%_))
                           (cons (let ()
                                   (declare (not safe))
                                   (gx#datum->syntax__0 '#f 'declare-type))
                                 (cons _%$%hd280799280820%_
                                       (cons (cons (let ()
                                                     (declare (not safe))
                                                     (gx#datum->syntax__0
                                                      '#f
                                                      'make-!primitive-lambda))
                                                   (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#datum->syntax__0 '#f 'quote))
                       (cons _%$%hd280673280694%_ '()))
                 (cons '#f
                       (cons 'signature: (cons _%$%hd280802280830%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             '())))
                           (_%$%g280794280809%_ _%$%g280795280813%_))))
                   (_%$%g280794280809%_ _%$%g280795280813%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g280794280809%_
                                                    _%$%g280795280813%_)))))
                                       (_%$%g280793280854%_
                                        _%unchecked280756%_))
                                     '(begin)))))))
                      (_%$%g280727280858%_
                       (cons (let ()
                               (declare (not safe))
                               (gx#datum->syntax__0 '#f 'declare-type))
                             (cons _%$%hd280577280614%_
                                   (cons (cons (let ()
                                                 (declare (not safe))
                                                 (gx#datum->syntax__0
                                                  '#f
                                                  'make-!primitive-lambda))
                                               (cons (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#datum->syntax__0
                                                              '#f
                                                              'quote))
                                                           (cons _%$%hd280673280694%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons '#f
                                                           (cons 'signature:
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons _%$%hd280676280704%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                         '())))))
                    (_%$%g280668280683%_ _%$%g280669280687%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g280668280683%_
                                                     _%$%g280669280687%_))))
                                            (_%$%g280668280683%_
                                             _%$%g280669280687%_)))))
                                (_%$%g280667280862%_
                                 (|gxc[1]#parse-signature|
                                  _%stx280566%_
                                  _%$%hd280577280614%_
                                  (let ((__tmp282928
                                         (lambda (_%$%g280865280868%_
                                                  _%$%g280866280871%_)
                                           (cons _%$%g280865280868%_
                                                 _%$%g280866280871%_))))
                                    (declare (not safe))
                                    (foldr__0
                                     __tmp282928
                                     '()
                                     _%$%signature280587280645%_)))))
                              (_%$%g280569280593%_ _%$%g280570280597%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop280582280626%_
                                                   _%$%target280579280620%_
                                                   '()))
                                                (_%$%g280569280593%_
                                                 _%$%g280570280597%_)))))
                                      (_%$%g280569280593%_
                                       _%$%g280570280597%_))))
                              (_%$%g280569280593%_ _%$%g280570280597%_))))
                      (_%$%g280569280593%_ _%$%g280570280597%_)))))
          (_%$%g280568280874%_ _%stx280566%_))))
    (define |gxc[:0:]#declare-primitive-case-lambda|
      (lambda (_%stx280879%_)
        (let* ((_%$%g280882280906%_
                (lambda (_%$%g280883280902%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g280883280902%_))))
               (_%$%g280881281781%_
                (lambda (_%$%g280883280910%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g280883280910%_))
                      (let ((_%$%e280886280913%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g280883280910%_))))
                        (let ((_%$%hd280887280917%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e280886280913%_)))
                              (_%$%tl280888280920%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e280886280913%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl280888280920%_))
                              (let ((_%$%e280889280923%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl280888280920%_))))
                                (let ((_%$%hd280890280927%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e280889280923%_)))
                                      (_%$%tl280891280930%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e280889280923%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl280891280930%_))
                                      (let ((_g282929_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%tl280891280930%_
                                                '0))))
                                        (begin
                                          (let ((_g282930_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g282929_)
                                                       (##values-length
                                                        _g282929_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g282930_ 2)))
                                                (error "Context expects 2 values"
                                                       _g282930_)))
                                          (let ((_%$%target280892280933%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g282929_ 0)))
                                                (_%$%tl280894280936%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g282929_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl280894280936%_))
                                                (letrec ((_%$%loop280895280939%_
                                                          (lambda (_%$%hd280893280943%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%case-signature280899280946%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd280893280943%_))
                        (let ((_%$%e280896280948%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%hd280893280943%_))))
                          (let ((_%$%lp-hd280897280952%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e280896280948%_)))
                                (_%$%lp-tl280898280955%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e280896280948%_))))
                            (_%$%loop280895280939%_
                             _%$%lp-tl280898280955%_
                             (cons _%$%lp-hd280897280952%_
                                   _%$%case-signature280899280946%_))))
                        (let ((_%$%case-signature280900280958%_
                               (reverse _%$%case-signature280899280946%_)))
                          (if (let ()
                                (declare (not safe))
                                (gx#identifier? _%$%hd280890280927%_))
                              (let* ((_%signatures280994%_
                                      (map (lambda (_%$%g280980280982%_)
                                             (|gxc[1]#parse-signature|
                                              _%stx280879%_
                                              _%$%hd280890280927%_
                                              _%$%g280980280982%_))
                                           (let ((__tmp282931
                                                  (lambda (_%$%g280985280988%_
                                                           _%$%g280986280991%_)
                                                    (cons _%$%g280985280988%_
                                                          _%$%g280986280991%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp282931
                                              '()
                                              _%$%case-signature280900280958%_))))
                                     (_%$%g280997281023%_
                                      (lambda (_%$%g280998281019%_)
                                        (let ()
                                          (declare (not safe))
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid match target"
                                           _%$%g280998281019%_))))
                                     (_%$%g280996281777%_
                                      (lambda (_%$%g280998281027%_)
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair/null?
                                               _%$%g280998281027%_))
                                            (let ((_g282932_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-split-splice
                                                      _%$%g280998281027%_
                                                      '0))))
                                              (begin
                                                (let ((_g282933_
                                                       (let ()
                                                         (declare (not safe))
                                                         (if (##values?
                                                              _g282932_)
                                                             (##values-length
                                                              _g282932_)
                                                             1))))
                                                  (if (not (let ()
                                                             (declare
                                                               (not safe))
                                                             (##fx= _g282933_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            2)))
              (error "Context expects 2 values" _g282933_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ((_%$%target281001281030%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##values-ref
                                                          _g282932_
                                                          0)))
                                                      (_%$%tl281003281033%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##values-ref
                                                          _g282932_
                                                          1))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl281003281033%_))
                                                      (letrec ((_%$%loop281004281036%_
                                                                (lambda (_%$%hd281002281040%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 _%$%sig281008281043%_
                                 _%$%arity281009281044%_)
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd281002281040%_))
                              (let ((_%$%e281005281046%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%hd281002281040%_))))
                                (let ((_%$%lp-hd281006281050%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e281005281046%_)))
                                      (_%$%lp-tl281007281053%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e281005281046%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%lp-hd281006281050%_))
                                      (let ((_%$%e281012281056%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%lp-hd281006281050%_))))
                                        (let ((_%$%hd281013281060%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e281012281056%_)))
                                              (_%$%tl281014281063%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e281012281056%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl281014281063%_))
                                              (let ((_%$%e281015281066%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl281014281063%_))))
                                                (let ((_%$%hd281016281070%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e281015281066%_)))
                                                      (_%$%tl281017281073%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e281015281066%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl281017281073%_))
                                                      (_%$%loop281004281036%_
                                                       _%$%lp-tl281007281053%_
                                                       (cons _%$%hd281016281070%_
                                                             _%$%sig281008281043%_)
                                                       (cons _%$%hd281013281060%_
                                                             _%$%arity281009281044%_))
                                                      (_%$%g280997281023%_
                                                       _%$%g280998281027%_))))
                                              (_%$%g280997281023%_
                                               _%$%g280998281027%_))))
                                      (_%$%g280997281023%_
                                       _%$%g280998281027%_))))
                              (let ((_%$%sig281010281076%_
                                     (reverse _%$%sig281008281043%_))
                                    (_%$%arity281011281078%_
                                     (reverse _%$%arity281009281044%_)))
                                (let* ((_%$%g281099281107%_
                                        (lambda (_%$%g281100281103%_)
                                          (let ()
                                            (declare (not safe))
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Bad syntax; invalid match target"
                                             _%$%g281100281103%_))))
                                       (_%$%g281098281762%_
                                        (lambda (_%$%g281100281111%_)
                                          (let* ((_%$%g281127281135%_
                                                  (lambda (_%$%g281128281131%_)
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#raise-syntax-error
                                                       '#f
                                                       '"Bad syntax; invalid match target"
                                                       _%$%g281128281131%_))))
                                                 (_%$%g281126281157%_
                                                  (lambda (_%$%g281128281139%_)
                                                    (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#datum->syntax__0
                                                             '#f
                                                             'begin))
                                                          (cons _%$%g281100281111%_
                                                                (cons _%$%g281128281139%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g281126281157%_
                                             (let ((_g282934_
                                                    (let _%loop281161%_ ((_%rest281164%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  _%signatures280994%_)
                                 (_%unchecked-proc281166%_ '#f)
                                 (_%unchecked-clauses281167%_ '()))
              (let* ((_%$%rest281168281176%_ _%rest281164%_)
                     (_%$%else281170281188%_
                      (lambda ()
                        (values _%unchecked-proc281166%_
                                (reverse! _%unchecked-clauses281167%_))))
                     (_%$%K281172281629%_
                      (lambda (_%rest281192%_ _%hd281194%_)
                        (let* ((_%$%g281196281283%_
                                (lambda (_%$%g281197281279%_)
                                  (let ()
                                    (declare (not safe))
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Bad syntax; invalid match target"
                                     _%$%g281197281279%_))))
                               (_%$%g281195281625%_
                                (lambda (_%$%g281197281287%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%g281197281287%_))
                                      (let ((_%$%e281204281290%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%g281197281287%_))))
                                        (let ((_%$%hd281205281294%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e281204281290%_)))
                                              (_%$%tl281206281297%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e281204281290%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl281206281297%_))
                                              (let ((_%$%e281207281300%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl281206281297%_))))
                                                (let ((_%$%hd281208281304%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e281207281300%_)))
                                                      (_%$%tl281209281307%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e281207281300%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%hd281208281304%_))
                                                      (let ((_%$%e281210281310%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-e _%$%hd281208281304%_))))
                (let ((_%$%hd281211281314%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e281210281310%_)))
                      (_%$%tl281212281317%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e281210281310%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl281212281317%_))
                      (let ((_%$%e281213281320%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%tl281212281317%_))))
                        (let ((_%$%hd281214281324%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e281213281320%_)))
                              (_%$%tl281215281327%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e281213281320%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-datum? _%$%hd281214281324%_))
                              (let ((_%$%e281216281330%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%hd281214281324%_))))
                                (if (equal? _%$%e281216281330%_ 'arguments:)
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl281215281327%_))
                                        (let ((_%$%e281217281334%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-e
                                                  _%$%tl281215281327%_))))
                                          (let ((_%$%hd281218281338%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e281217281334%_)))
                                                (_%$%tl281219281341%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e281217281334%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%hd281218281338%_))
                                                (let ((_%$%e281220281344%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#syntax-e
                                                          _%$%hd281218281338%_))))
                                                  (let ((_%$%hd281221281348%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e281220281344%_)))
                                                        (_%$%tl281222281351%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e281220281344%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#identifier?
                                                           _%$%hd281221281348%_))
                                                        (if (let ((__tmp282936
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           |gxc[1]#_g282937_|))
                      (declare (not safe))
                      (gx#free-identifier=? __tmp282936 _%$%hd281221281348%_))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl281222281351%_))
                        (let ((_%$%e281223281354%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl281222281351%_))))
                          (let ((_%$%hd281224281358%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e281223281354%_)))
                                (_%$%tl281225281361%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e281223281354%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl281225281361%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%tl281219281341%_))
                                    (let ((_%$%e281226281364%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-e
                                              _%$%tl281219281341%_))))
                                      (let ((_%$%hd281227281368%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e281226281364%_)))
                                            (_%$%tl281228281371%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e281226281364%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-datum?
                                               _%$%hd281227281368%_))
                                            (let ((_%$%e281229281374%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%hd281227281368%_))))
                                              (if (equal? _%$%e281229281374%_
                                                          'return:)
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl281228281371%_))
                                                      (let ((_%$%e281230281378%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-e _%$%tl281228281371%_))))
                (let ((_%$%hd281231281382%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e281230281378%_)))
                      (_%$%tl281232281385%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e281230281378%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%hd281231281382%_))
                      (let ((_%$%e281233281388%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%hd281231281382%_))))
                        (let ((_%$%hd281234281392%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e281233281388%_)))
                              (_%$%tl281235281395%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e281233281388%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#identifier? _%$%hd281234281392%_))
                              (if (let ((__tmp282938 |gxc[1]#_g282939_|))
                                    (declare (not safe))
                                    (gx#free-identifier=?
                                     __tmp282938
                                     _%$%hd281234281392%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl281235281395%_))
                                      (let ((_%$%e281236281398%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl281235281395%_))))
                                        (let ((_%$%hd281237281402%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e281236281398%_)))
                                              (_%$%tl281238281405%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e281236281398%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl281238281405%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl281232281385%_))
                                                  (let ((_%$%e281239281408%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%tl281232281385%_))))
                                                    (let ((_%$%hd281240281412%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e281239281408%_)))
                                                          (_%$%tl281241281415%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e281239281408%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-datum?
                                                             _%$%hd281240281412%_))
                                                          (let ((_%$%e281242281418%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%hd281240281412%_))))
                    (if (equal? _%$%e281242281418%_ 'effect:)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl281241281415%_))
                            (let ((_%$%e281243281422%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#syntax-e _%$%tl281241281415%_))))
                              (let ((_%$%hd281244281426%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e281243281422%_)))
                                    (_%$%tl281245281429%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e281243281422%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%hd281244281426%_))
                                    (let ((_%$%e281246281432%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-e
                                              _%$%hd281244281426%_))))
                                      (let ((_%$%hd281247281436%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e281246281432%_)))
                                            (_%$%tl281248281439%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e281246281432%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#identifier?
                                               _%$%hd281247281436%_))
                                            (if (let ((__tmp282940
                                                       |gxc[1]#_g282941_|))
                                                  (declare (not safe))
                                                  (gx#free-identifier=?
                                                   __tmp282940
                                                   _%$%hd281247281436%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl281248281439%_))
                                                    (let ((_%$%e281249281442%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#syntax-e
                                                              _%$%tl281248281439%_))))
                                                      (let ((_%$%hd281250281446%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##car _%$%e281249281442%_)))
                    (_%$%tl281251281449%_
                     (let ()
                       (declare (not safe))
                       (##cdr _%$%e281249281442%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl281251281449%_))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl281245281429%_))
                        (let ((_%$%e281252281452%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl281245281429%_))))
                          (let ((_%$%hd281253281456%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e281252281452%_)))
                                (_%$%tl281254281459%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e281252281452%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-datum? _%$%hd281253281456%_))
                                (let ((_%$%e281255281462%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%hd281253281456%_))))
                                  (if (equal? _%$%e281255281462%_ 'unchecked:)
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl281254281459%_))
                                          (let ((_%$%e281256281466%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#syntax-e
                                                    _%$%tl281254281459%_))))
                                            (let ((_%$%hd281257281470%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e281256281466%_)))
                                                  (_%$%tl281258281473%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e281256281466%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd281257281470%_))
                                                  (let ((_%$%e281259281476%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%hd281257281470%_))))
                                                    (let ((_%$%hd281260281480%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e281259281476%_)))
                                                          (_%$%tl281261281483%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e281259281476%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#identifier?
                                                             _%$%hd281260281480%_))
                                                          (if (let ((__tmp282942
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             |gxc[1]#_g282943_|))
                        (declare (not safe))
                        (gx#free-identifier=?
                         __tmp282942
                         _%$%hd281260281480%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl281261281483%_))
                          (let ((_%$%e281262281486%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%tl281261281483%_))))
                            (let ((_%$%hd281263281490%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e281262281486%_)))
                                  (_%$%tl281264281493%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e281262281486%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl281264281493%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl281258281473%_))
                                      (let ((_%$%e281265281496%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl281258281473%_))))
                                        (let ((_%$%hd281266281500%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e281265281496%_)))
                                              (_%$%tl281267281503%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e281265281496%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-datum?
                                                 _%$%hd281266281500%_))
                                              (let ((_%$%e281268281506%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd281266281500%_))))
                                                (if (equal? _%$%e281268281506%_
                                                            'origin:)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl281267281503%_))
                                                        (let ((_%$%e281269281510%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%tl281267281503%_))))
                  (let ((_%$%hd281270281514%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e281269281510%_)))
                        (_%$%tl281271281517%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e281269281510%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd281270281514%_))
                        (let ((_%$%e281272281520%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%hd281270281514%_))))
                          (let ((_%$%hd281273281524%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e281272281520%_)))
                                (_%$%tl281274281527%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e281272281520%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%hd281273281524%_))
                                (if (let ((__tmp282944 |gxc[1]#_g282945_|))
                                      (declare (not safe))
                                      (gx#free-identifier=?
                                       __tmp282944
                                       _%$%hd281273281524%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl281274281527%_))
                                        (let ((_%$%e281275281530%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-e
                                                  _%$%tl281274281527%_))))
                                          (let ((_%$%hd281276281534%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e281275281530%_)))
                                                (_%$%tl281277281537%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e281275281530%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl281277281537%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl281271281517%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl281209281307%_))
                                                        (let ((_%clause281617%_
                                                               (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (declare (not safe))
                               (gx#datum->syntax__0
                                '#f
                                'make-!primitive-lambda))
                             (cons (cons (let ()
                                           (declare (not safe))
                                           (gx#datum->syntax__0 '#f 'quote))
                                         (cons _%$%hd281205281294%_ '()))
                                   (cons '#f
                                         (cons 'signature:
                                               (cons (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#datum->syntax__0
                                                              '#f
                                                              'make-!signature))
                                                           (cons 'return:
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%hd281237281402%_ '()))
                               (cons 'origin:
                                     (cons (cons (let ()
                                                   (declare (not safe))
                                                   (gx#datum->syntax__0
                                                    '#f
                                                    'quote))
                                                 (cons _%$%hd281276281534%_
                                                       '()))
                                           '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '()))))))
                      (_%unchecked281619%_
                       (let ()
                         (declare (not safe))
                         (gx#stx-e _%$%hd281263281490%_))))
                  (_%loop281161%_
                   _%rest281192%_
                   (let ((_%$e281621%_ _%unchecked281619%_))
                     (if _%$e281621%_ _%$e281621%_ _%unchecked-proc281166%_))
                   (cons _%clause281617%_ _%unchecked-clauses281167%_)))
                (_%$%g281196281283%_ _%$%g281197281287%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g281196281283%_
                                                     _%$%g281197281287%_))
                                                (_%$%g281196281283%_
                                                 _%$%g281197281287%_))))
                                        (_%$%g281196281283%_
                                         _%$%g281197281287%_))
                                    (_%$%g281196281283%_ _%$%g281197281287%_))
                                (_%$%g281196281283%_ _%$%g281197281287%_))))
                        (_%$%g281196281283%_ _%$%g281197281287%_))))
                (_%$%g281196281283%_ _%$%g281197281287%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g281196281283%_
                                                     _%$%g281197281287%_)))
                                              (_%$%g281196281283%_
                                               _%$%g281197281287%_))))
                                      (_%$%g281196281283%_
                                       _%$%g281197281287%_))
                                  (_%$%g281196281283%_ _%$%g281197281287%_))))
                          (_%$%g281196281283%_ _%$%g281197281287%_))
                      (_%$%g281196281283%_ _%$%g281197281287%_))
                  (_%$%g281196281283%_ _%$%g281197281287%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g281196281283%_
                                                   _%$%g281197281287%_))))
                                          (_%$%g281196281283%_
                                           _%$%g281197281287%_))
                                      (_%$%g281196281283%_
                                       _%$%g281197281287%_)))
                                (_%$%g281196281283%_ _%$%g281197281287%_))))
                        (_%$%g281196281283%_ _%$%g281197281287%_))
                    (_%$%g281196281283%_ _%$%g281197281287%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g281196281283%_
                                                     _%$%g281197281287%_))
                                                (_%$%g281196281283%_
                                                 _%$%g281197281287%_))
                                            (_%$%g281196281283%_
                                             _%$%g281197281287%_))))
                                    (_%$%g281196281283%_
                                     _%$%g281197281287%_))))
                            (_%$%g281196281283%_ _%$%g281197281287%_))
                        (_%$%g281196281283%_ _%$%g281197281287%_)))
                  (_%$%g281196281283%_ _%$%g281197281287%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g281196281283%_
                                                   _%$%g281197281287%_))
                                              (_%$%g281196281283%_
                                               _%$%g281197281287%_))))
                                      (_%$%g281196281283%_
                                       _%$%g281197281287%_))
                                  (_%$%g281196281283%_ _%$%g281197281287%_))
                              (_%$%g281196281283%_ _%$%g281197281287%_))))
                      (_%$%g281196281283%_ _%$%g281197281287%_))))
              (_%$%g281196281283%_ _%$%g281197281287%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g281196281283%_
                                                   _%$%g281197281287%_)))
                                            (_%$%g281196281283%_
                                             _%$%g281197281287%_))))
                                    (_%$%g281196281283%_ _%$%g281197281287%_))
                                (_%$%g281196281283%_ _%$%g281197281287%_))))
                        (_%$%g281196281283%_ _%$%g281197281287%_))
                    (_%$%g281196281283%_ _%$%g281197281287%_))
                (_%$%g281196281283%_ _%$%g281197281287%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g281196281283%_
                                                 _%$%g281197281287%_))))
                                        (_%$%g281196281283%_
                                         _%$%g281197281287%_))
                                    (_%$%g281196281283%_ _%$%g281197281287%_)))
                              (_%$%g281196281283%_ _%$%g281197281287%_))))
                      (_%$%g281196281283%_ _%$%g281197281287%_))))
              (_%$%g281196281283%_ _%$%g281197281287%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g281196281283%_
                                               _%$%g281197281287%_))))
                                      (_%$%g281196281283%_
                                       _%$%g281197281287%_)))))
                          (_%$%g281195281625%_ _%hd281194%_)))))
                (if (pair? _%$%rest281168281176%_)
                    (let ((_%$%hd281173281633%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest281168281176%_)))
                          (_%$%tl281174281636%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest281168281176%_))))
                      (let* ((_%hd281639%_ _%$%hd281173281633%_)
                             (_%rest281642%_ _%$%tl281174281636%_))
                        (_%$%K281172281629%_ _%rest281642%_ _%hd281639%_)))
                    (_%$%else281170281188%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (begin
                                                 (let ((_g282935_
                                                        (let ()
                                                          (declare (not safe))
                                                          (if (##values?
                                                               _g282934_)
                                                              (##values-length
                                                               _g282934_)
                                                              1))))
                                                   (if (not (let ()
                                                              (declare
                                                                (not safe))
                                                              (##fx= _g282935_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             2)))
               (error "Context expects 2 values" _g282935_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (let ((_%unchecked-proc281645%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##values-ref
                                                           _g282934_
                                                           0)))
                                                       (_%unchecked-clauses281647%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##values-ref
                                                           _g282934_
                                                           1))))
                                                   (if _%unchecked-proc281645%_
                                                       (let* ((_%$%g281649281673%_
                                                               (lambda (_%$%g281650281669%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#raise-syntax-error
                            '#f
                            '"Bad syntax; invalid match target"
                            _%$%g281650281669%_))))
                      (_%$%g281648281758%_
                       (lambda (_%$%g281650281677%_)
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-pair? _%$%g281650281677%_))
                             (let ((_%$%e281653281680%_
                                    (let ()
                                      (declare (not safe))
                                      (gx#syntax-e _%$%g281650281677%_))))
                               (let ((_%$%hd281654281684%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e281653281680%_)))
                                     (_%$%tl281655281687%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e281653281680%_))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%tl281655281687%_))
                                     (let ((_%$%e281656281690%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#syntax-e
                                               _%$%tl281655281687%_))))
                                       (let ((_%$%hd281657281694%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e281656281690%_)))
                                             (_%$%tl281658281697%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e281656281690%_))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair/null?
                                                _%$%hd281657281694%_))
                                             (let ((_g282946_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#syntax-split-splice
                                                       _%$%hd281657281694%_
                                                       '0))))
                                               (begin
                                                 (let ((_g282947_
                                                        (let ()
                                                          (declare (not safe))
                                                          (if (##values?
                                                               _g282946_)
                                                              (##values-length
                                                               _g282946_)
                                                              1))))
                                                   (if (not (let ()
                                                              (declare
                                                                (not safe))
                                                              (##fx= _g282947_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             2)))
               (error "Context expects 2 values" _g282947_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (let ((_%$%target281659281700%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##values-ref
                                                           _g282946_
                                                           0)))
                                                       (_%$%tl281661281703%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##values-ref
                                                           _g282946_
                                                           1))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-null?
                                                          _%$%tl281661281703%_))
                                                       (letrec ((_%$%loop281662281706%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (lambda (_%$%hd281660281710%_
                                  _%$%clause281666281713%_)
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%hd281660281710%_))
                               (let ((_%$%e281663281715%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#syntax-e _%$%hd281660281710%_))))
                                 (let ((_%$%lp-hd281664281719%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e281663281715%_)))
                                       (_%$%lp-tl281665281722%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e281663281715%_))))
                                   (_%$%loop281662281706%_
                                    _%$%lp-tl281665281722%_
                                    (cons _%$%lp-hd281664281719%_
                                          _%$%clause281666281713%_))))
                               (let ((_%$%clause281667281725%_
                                      (reverse _%$%clause281666281713%_)))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-null? _%$%tl281658281697%_))
                                     (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0
                                              '#f
                                              'declare-type))
                                           (cons _%$%hd281654281684%_
                                                 (cons (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f 'make-!primitive-case-lambda))
                     (cons (cons (let ()
                                   (declare (not safe))
                                   (gx#datum->syntax__0 '#f '@list))
                                 (let ((__tmp282948
                                        (lambda (_%$%g281749281752%_
                                                 _%$%g281750281755%_)
                                          (cons _%$%g281749281752%_
                                                _%$%g281750281755%_))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp282948
                                    '()
                                    _%$%clause281667281725%_)))
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (_%$%g281649281673%_
                                      _%$%g281650281677%_)))))))
                 (_%$%loop281662281706%_ _%$%target281659281700%_ '()))
               (_%$%g281649281673%_ _%$%g281650281677%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             (_%$%g281649281673%_
                                              _%$%g281650281677%_))))
                                     (_%$%g281649281673%_
                                      _%$%g281650281677%_))))
                             (_%$%g281649281673%_ _%$%g281650281677%_)))))
                 (_%$%g281648281758%_
                  (list _%unchecked-proc281645%_ _%unchecked-clauses281647%_)))
               '(begin))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  (_%$%g281098281762%_
                                   (cons (let ()
                                           (declare (not safe))
                                           (gx#datum->syntax__0
                                            '#f
                                            'declare-type))
                                         (cons _%$%hd280890280927%_
                                               (cons (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#datum->syntax__0
                                                              '#f
                                                              'make-!primitive-case-lambda))
                                                           (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (declare (not safe))
                                 (gx#datum->syntax__0 '#f '@list))
                               (begin
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-check-splice-targets
                                    _%$%sig281010281076%_
                                    _%$%arity281011281078%_))
                                 (let ((__tmp282949
                                        (lambda (_%$%g281765281769%_
                                                 _%$%g281766281772%_
                                                 _%$%g281767281774%_)
                                          (cons (cons (let ()
                                                        (declare (not safe))
                                                        (gx#datum->syntax__0
                                                         '#f
                                                         'make-!primitive-lambda))
                                                      (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gx#datum->syntax__0 '#f 'quote))
                          (cons _%$%g281766281772%_ '()))
                    (cons '#f
                          (cons 'signature: (cons _%$%g281765281769%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                _%$%g281767281774%_))))
                                   (declare (not safe))
                                   (foldr__1
                                    __tmp282949
                                    '()
                                    _%$%sig281010281076%_
                                    _%$%arity281011281078%_))))
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '()))))))))))
                (_%$%loop281004281036%_ _%$%target281001281030%_ '() '()))
              (_%$%g280997281023%_ _%$%g280998281027%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g280997281023%_
                                             _%$%g280998281027%_)))))
                                (_%$%g280996281777%_ _%signatures280994%_))
                              (_%$%g280882280906%_ _%$%g280883280910%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop280895280939%_
                                                   _%$%target280892280933%_
                                                   '()))
                                                (_%$%g280882280906%_
                                                 _%$%g280883280910%_)))))
                                      (_%$%g280882280906%_
                                       _%$%g280883280910%_))))
                              (_%$%g280882280906%_ _%$%g280883280910%_))))
                      (_%$%g280882280906%_ _%$%g280883280910%_)))))
          (_%$%g280881281781%_ _%stx280879%_))))
    (define |gxc[:0:]#declare-builtin-class|
      (lambda (_%$stx281789%_)
        (let* ((_%__stx282769282770%_ _%$stx281789%_)
               (_%$%g281795281855%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx282769282770%_)))))
          (let ((_%__kont282772282773%_
                 (lambda (_%$%g281797282077%_ _%$%g281798282079%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0
                            '#f
                            'optimizer-declare-builtin-class!))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%g281798282079%_ '()))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0
                                              '#f
                                              'make-!class))
                                           (cons (cons (let ()
                                                         (declare (not safe))
                                                         (gx#datum->syntax__0
                                                          '#f
                                                          'class-type-id))
                                                       (cons _%$%g281798282079%_
                                                             '()))
                                                 (cons (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f 'quote))
                     (cons _%$%g281797282077%_ '()))
               (cons (cons (let ()
                             (declare (not safe))
                             (gx#datum->syntax__0 '#f '@list))
                           '())
                     (cons '#f
                           (cons '#f (cons '#f (cons '#t (cons '#f '())))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont282774282775%_
                 (lambda (_%$%g281812282002%_
                          _%$%g281813282004%_
                          _%$%g281814282005%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0
                            '#f
                            'optimizer-declare-builtin-class!))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%g281814282005%_ '()))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0
                                              '#f
                                              'make-!class))
                                           (cons (cons (let ()
                                                         (declare (not safe))
                                                         (gx#datum->syntax__0
                                                          '#f
                                                          'class-type-id))
                                                       (cons _%$%g281814282005%_
                                                             '()))
                                                 (cons (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f 'quote))
                     (cons _%$%g281813282004%_ '()))
               (cons (cons (let ()
                             (declare (not safe))
                             (gx#datum->syntax__0 '#f 'quote))
                           (cons _%$%g281812282002%_ '()))
                     (cons '#f
                           (cons '#f (cons '#f (cons '#f (cons '#f '())))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont282776282777%_
                 (lambda (_%$%g281831281916%_
                          _%$%g281832281918%_
                          _%$%g281833281919%_)
                   (cons (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0
                            '#f
                            'optimizer-declare-builtin-class!))
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'quote))
                                     (cons _%$%g281833281919%_ '()))
                               (cons (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0
                                              '#f
                                              'make-!class))
                                           (cons (cons (let ()
                                                         (declare (not safe))
                                                         (gx#datum->syntax__0
                                                          '#f
                                                          'class-type-id))
                                                       (cons _%$%g281833281919%_
                                                             '()))
                                                 (cons (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f 'quote))
                     (cons _%$%g281832281918%_ '()))
               (cons (cons (let ()
                             (declare (not safe))
                             (gx#datum->syntax__0 '#f 'quote))
                           (cons _%$%g281831281916%_ '()))
                     (cons '#f
                           (cons '#t (cons '#f (cons '#f (cons '#f '())))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '()))))))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx282769282770%_))
                (let ((_%$%e281799282033%_
                       (let ()
                         (declare (not safe))
                         (gx#syntax-e _%__stx282769282770%_))))
                  (let ((_%$%tl281801282040%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e281799282033%_)))
                        (_%$%hd281800282037%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e281799282033%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl281801282040%_))
                        (let ((_%$%e281802282043%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%tl281801282040%_))))
                          (let ((_%$%tl281804282050%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e281802282043%_)))
                                (_%$%hd281803282047%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e281802282043%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-datum? _%$%hd281803282047%_))
                                (let ((_%$%e281805282053%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%hd281803282047%_))))
                                  (if (equal? _%$%e281805282053%_ 'system:)
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl281804282050%_))
                                          (let ((_%$%e281806282057%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#syntax-e
                                                    _%$%tl281804282050%_))))
                                            (let ((_%$%tl281808282064%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e281806282057%_)))
                                                  (_%$%hd281807282061%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e281806282057%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl281808282064%_))
                                                  (let ((_%$%e281809282067%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%tl281808282064%_))))
                                                    (let ((_%$%tl281811282074%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e281809282067%_)))
                                                          (_%$%hd281810282071%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e281809282067%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl281811282074%_))
                                                          (_%__kont282772282773%_
                                                           _%$%hd281810282071%_
                                                           _%$%hd281807282061%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (_%$%g281795281855%_)))))
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g281795281855%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g281795281855%_)))
                                      (if (equal? _%$%e281805282053%_ 'struct:)
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl281804282050%_))
                                              (let ((_%$%e281822281972%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl281804282050%_))))
                                                (let ((_%$%tl281824281979%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e281822281972%_)))
                                                      (_%$%hd281823281976%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e281822281972%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl281824281979%_))
                                                      (let ((_%$%e281825281982%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-e _%$%tl281824281979%_))))
                (let ((_%$%tl281827281989%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e281825281982%_)))
                      (_%$%hd281826281986%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e281825281982%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%tl281827281989%_))
                      (let ((_%$%e281828281992%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%tl281827281989%_))))
                        (let ((_%$%tl281830281999%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e281828281992%_)))
                              (_%$%hd281829281996%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e281828281992%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl281830281999%_))
                              (_%__kont282774282775%_
                               _%$%hd281829281996%_
                               _%$%hd281826281986%_
                               _%$%hd281823281976%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g281795281855%_)))))
                      (let () (declare (not safe)) (_%$%g281795281855%_)))))
              (let () (declare (not safe)) (_%$%g281795281855%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g281795281855%_)))
                                          (if (equal? _%$%e281805282053%_
                                                      'class:)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl281804282050%_))
                                                  (let ((_%$%e281841281886%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%$%tl281804282050%_))))
                                                    (let ((_%$%tl281843281893%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e281841281886%_)))
                                                          (_%$%hd281842281890%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e281841281886%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl281843281893%_))
                                                          (let ((_%$%e281844281896%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%$%tl281843281893%_))))
                    (let ((_%$%tl281846281903%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e281844281896%_)))
                          (_%$%hd281845281900%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e281844281896%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl281846281903%_))
                          (let ((_%$%e281847281906%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%tl281846281903%_))))
                            (let ((_%$%tl281849281913%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e281847281906%_)))
                                  (_%$%hd281848281910%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e281847281906%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl281849281913%_))
                                  (_%__kont282776282777%_
                                   _%$%hd281848281910%_
                                   _%$%hd281845281900%_
                                   _%$%hd281842281890%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g281795281855%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g281795281855%_)))))
                  (let () (declare (not safe)) (_%$%g281795281855%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g281795281855%_)))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g281795281855%_))))))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g281795281855%_)))))
                        (let () (declare (not safe)) (_%$%g281795281855%_)))))
                (let () (declare (not safe)) (_%$%g281795281855%_)))))))
    (define |gxc[:0:]#declare-builtin-classes|
      (lambda (_%$stx282101%_)
        (let* ((_%$%g282105282125%_
                (lambda (_%$%g282106282121%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g282106282121%_))))
               (_%$%g282104282194%_
                (lambda (_%$%g282106282129%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g282106282129%_))
                      (let ((_%$%e282108282132%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g282106282129%_))))
                        (let ((_%$%hd282109282136%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e282108282132%_)))
                              (_%$%tl282110282139%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e282108282132%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl282110282139%_))
                              (let ((_g282950_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl282110282139%_
                                        '0))))
                                (begin
                                  (let ((_g282951_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g282950_)
                                               (##values-length _g282950_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g282951_ 2)))
                                        (error "Context expects 2 values"
                                               _g282951_)))
                                  (let ((_%$%target282111282142%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282950_ 0)))
                                        (_%$%tl282113282145%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g282950_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl282113282145%_))
                                        (letrec ((_%$%loop282114282148%_
                                                  (lambda (_%$%hd282112282152%_
                                                           _%$%decl282118282155%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd282112282152%_))
                                                        (let ((_%$%e282115282157%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-e _%$%hd282112282152%_))))
                  (let ((_%$%lp-hd282116282161%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e282115282157%_)))
                        (_%$%lp-tl282117282164%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e282115282157%_))))
                    (_%$%loop282114282148%_
                     _%$%lp-tl282117282164%_
                     (cons _%$%lp-hd282116282161%_ _%$%decl282118282155%_))))
                (let ((_%$%decl282119282167%_
                       (reverse _%$%decl282118282155%_)))
                  (cons (let ()
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'begin))
                        (let ((__tmp282952
                               (lambda (_%$%g282185282188%_
                                        _%$%g282186282191%_)
                                 (cons (cons (let ()
                                               (declare (not safe))
                                               (gx#datum->syntax__0
                                                '#f
                                                'declare-builtin-class))
                                             _%$%g282185282188%_)
                                       _%$%g282186282191%_))))
                          (declare (not safe))
                          (foldr__0
                           __tmp282952
                           '()
                           _%$%decl282119282167%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop282114282148%_
                                           _%$%target282111282142%_
                                           '()))
                                        (_%$%g282105282125%_
                                         _%$%g282106282129%_)))))
                              (_%$%g282105282125%_ _%$%g282106282129%_))))
                      (_%$%g282105282125%_ _%$%g282106282129%_)))))
          (_%$%g282104282194%_ _%$stx282101%_))))))
