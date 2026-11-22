(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |[1]#_g182239_|
    (gx#core-deserialize-mark
     '(0
       ($%arg181090 . _%$%arg181090181161%_)
       (id . _%id181114%_)
       ($%arg181089 . _%$%arg181089181147%_)
       (arg . _%arg181177%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g182240_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g182239_|)))
  (define |[1]#_g182242_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g182243_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g182242_|)))
  (define |[1]#_g182244_|
    (gx#core-deserialize-mark
     '(0
       ($%arg181210 . _%$%arg181210181267%_)
       (id . _%id181234%_)
       ($%arg181211 . _%$%arg181211181281%_)
       (arg . _%arg181297%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g182245_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g182244_|)))
  (define |[1]#_g182247_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g182248_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g182247_|)))
  (define |[1]#_g182249_|
    (gx#core-deserialize-mark
     '(0
       (id . _%id181354%_)
       ($%arg181330 . _%$%arg181330181387%_)
       ($%arg181331 . _%$%arg181331181401%_)
       (arg . _%arg181417%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g182250_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g182249_|)))
  (define |[1]#_g182252_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g182253_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g182252_|)))
  (define |[1]#_g182254_|
    (gx#core-deserialize-mark
     '(0
       ($%arg181451 . _%$%arg181451181521%_)
       (id . _%id181474%_)
       ($%arg181450 . _%$%arg181450181507%_)
       (arg . _%arg181537%_))
     (gx#import-module '(:gerbil/core/contract Interface))))
  (define |[1]#_g182255_|
    (##structure
     gx#syntax-quote::t
     'with-dispatch-arguments
     #f
     (gx#current-expander-context)
     (list |[1]#_g182254_|)))
  (define |[1]#_g182257_|
    (gx#core-deserialize-mark
     '(0)
     (gx#import-module '(:gerbil/core/contract TypedDefinitions))))
  (define |[1]#_g182258_|
    (##structure
     gx#syntax-quote::t
     'using
     #f
     (gx#current-expander-context)
     (list |[1]#_g182257_|)))
  (begin
    (define |[:0:]#@set-load-path!|
      (lambda (_%$stx181071%_)
        (let* ((_%__stx182130182131%_ _%$stx181071%_)
               (_%$%g181076181097%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx182130182131%_))))
          (let ((_%__kont182133182134%_
                 (lambda (_%$%g181078181163%_)
                   (cons (gx#datum->syntax
                          |[1]#_g182240_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'paths) '())
                                     (cons (let ((__tmp182241
                                                  (lambda (_%$%g181178181181%_
                                                           _%$%g181179181184%_)
                                                    (cons _%$%g181178181181%_
                                                          _%$%g181179181184%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp182241
                                              '()
                                              _%$%g181078181163%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g182243_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'paths)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':list) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__set-load-path!)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'paths)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont182137182138%_
                 (lambda (_%$%g181091181104%_)
                   (gx#datum->syntax '#f 'set-load-path!))))
            (let* ((_%$%g181075181116%_
                    (lambda ()
                      (let ((_%$%g181091181104%_ _%__stx182130182131%_))
                        (if (gx#identifier? _%$%g181091181104%_)
                            (_%__kont182137182138%_ _%$%g181091181104%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g181076181097%_))))))
                   (_%__match182153182154%_
                    (lambda (_%$%e181079181123%_
                             _%$%hd181080181127%_
                             _%$%tl181081181130%_
                             _%__splice182135182136%_
                             _%$%target181082181133%_
                             _%$%tl181084181136%_)
                      (letrec ((_%$%loop181085181139%_
                                (lambda (_%$%hd181083181143%_
                                         _%$%arg181089181146%_)
                                  (if (gx#stx-pair? _%$%hd181083181143%_)
                                      (let ((_%$%e181086181149%_
                                             (gx#syntax-e
                                              _%$%hd181083181143%_)))
                                        (let ((_%$%lp-tl181088181156%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e181086181149%_)))
                                              (_%$%lp-hd181087181153%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e181086181149%_))))
                                          (_%$%loop181085181139%_
                                           _%$%lp-tl181088181156%_
                                           (cons _%$%lp-hd181087181153%_
                                                 _%$%arg181089181146%_))))
                                      (let ((_%$%arg181090181159%_
                                             (reverse _%$%arg181089181146%_)))
                                        (_%__kont182133182134%_
                                         _%$%arg181090181159%_))))))
                        (_%$%loop181085181139%_
                         _%$%target181082181133%_
                         '())))))
              (if (gx#stx-pair? _%__stx182130182131%_)
                  (let ((_%$%e181079181123%_
                         (gx#syntax-e _%__stx182130182131%_)))
                    (let ((_%$%tl181081181130%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e181079181123%_)))
                          (_%$%hd181080181127%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e181079181123%_))))
                      (if (gx#stx-pair/null? _%$%tl181081181130%_)
                          (let ((_%__splice182135182136%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl181081181130%_
                                  '0)))
                            (let ((_%$%tl181084181136%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182135182136%_
                                      '1)))
                                  (_%$%target181082181133%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182135182136%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl181084181136%_)
                                  (_%__match182153182154%_
                                   _%$%e181079181123%_
                                   _%$%hd181080181127%_
                                   _%$%tl181081181130%_
                                   _%__splice182135182136%_
                                   _%$%target181082181133%_
                                   _%$%tl181084181136%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g181075181116%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g181075181116%_)))))
                  (let () (declare (not safe)) (_%$%g181075181116%_))))))))
    (define |[:0:]#@load-module|
      (lambda (_%$stx181192%_)
        (let* ((_%__stx182156182157%_ _%$stx181192%_)
               (_%$%g181197181218%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx182156182157%_))))
          (let ((_%__kont182159182160%_
                 (lambda (_%$%g181199181283%_)
                   (cons (gx#datum->syntax
                          |[1]#_g182245_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'modpath) '())
                                     (cons (let ((__tmp182246
                                                  (lambda (_%$%g181298181301%_
                                                           _%$%g181299181304%_)
                                                    (cons _%$%g181298181301%_
                                                          _%$%g181299181304%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp182246
                                              '()
                                              _%$%g181199181283%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g182248_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'modpath)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':string) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__load-module)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'modpath)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont182163182164%_
                 (lambda (_%$%g181212181225%_)
                   (gx#datum->syntax '#f 'load-module))))
            (let* ((_%$%g181196181236%_
                    (lambda ()
                      (let ((_%$%g181212181225%_ _%__stx182156182157%_))
                        (if (gx#identifier? _%$%g181212181225%_)
                            (_%__kont182163182164%_ _%$%g181212181225%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g181197181218%_))))))
                   (_%__match182179182180%_
                    (lambda (_%$%e181200181243%_
                             _%$%hd181201181247%_
                             _%$%tl181202181250%_
                             _%__splice182161182162%_
                             _%$%target181203181253%_
                             _%$%tl181205181256%_)
                      (letrec ((_%$%loop181206181259%_
                                (lambda (_%$%hd181204181263%_
                                         _%$%arg181210181266%_)
                                  (if (gx#stx-pair? _%$%hd181204181263%_)
                                      (let ((_%$%e181207181269%_
                                             (gx#syntax-e
                                              _%$%hd181204181263%_)))
                                        (let ((_%$%lp-tl181209181276%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e181207181269%_)))
                                              (_%$%lp-hd181208181273%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e181207181269%_))))
                                          (_%$%loop181206181259%_
                                           _%$%lp-tl181209181276%_
                                           (cons _%$%lp-hd181208181273%_
                                                 _%$%arg181210181266%_))))
                                      (let ((_%$%arg181211181279%_
                                             (reverse _%$%arg181210181266%_)))
                                        (_%__kont182159182160%_
                                         _%$%arg181211181279%_))))))
                        (_%$%loop181206181259%_
                         _%$%target181203181253%_
                         '())))))
              (if (gx#stx-pair? _%__stx182156182157%_)
                  (let ((_%$%e181200181243%_
                         (gx#syntax-e _%__stx182156182157%_)))
                    (let ((_%$%tl181202181250%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e181200181243%_)))
                          (_%$%hd181201181247%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e181200181243%_))))
                      (if (gx#stx-pair/null? _%$%tl181202181250%_)
                          (let ((_%__splice182161182162%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl181202181250%_
                                  '0)))
                            (let ((_%$%tl181205181256%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182161182162%_
                                      '1)))
                                  (_%$%target181203181253%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182161182162%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl181205181256%_)
                                  (_%__match182179182180%_
                                   _%$%e181200181243%_
                                   _%$%hd181201181247%_
                                   _%$%tl181202181250%_
                                   _%__splice182161182162%_
                                   _%$%target181203181253%_
                                   _%$%tl181205181256%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g181196181236%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g181196181236%_)))))
                  (let () (declare (not safe)) (_%$%g181196181236%_))))))))
    (define |[:0:]#@reload-module!|
      (lambda (_%$stx181312%_)
        (let* ((_%__stx182182182183%_ _%$stx181312%_)
               (_%$%g181317181338%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx182182182183%_))))
          (let ((_%__kont182185182186%_
                 (lambda (_%$%g181319181403%_)
                   (cons (gx#datum->syntax
                          |[1]#_g182250_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'modpath) '())
                                     (cons (let ((__tmp182251
                                                  (lambda (_%$%g181418181421%_
                                                           _%$%g181419181424%_)
                                                    (cons _%$%g181418181421%_
                                                          _%$%g181419181424%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp182251
                                              '()
                                              _%$%g181319181403%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g182253_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'modpath)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':string) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__reload-module!)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'modpath)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont182189182190%_
                 (lambda (_%$%g181332181345%_)
                   (gx#datum->syntax '#f 'reload-module!))))
            (let* ((_%$%g181316181356%_
                    (lambda ()
                      (let ((_%$%g181332181345%_ _%__stx182182182183%_))
                        (if (gx#identifier? _%$%g181332181345%_)
                            (_%__kont182189182190%_ _%$%g181332181345%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g181317181338%_))))))
                   (_%__match182205182206%_
                    (lambda (_%$%e181320181363%_
                             _%$%hd181321181367%_
                             _%$%tl181322181370%_
                             _%__splice182187182188%_
                             _%$%target181323181373%_
                             _%$%tl181325181376%_)
                      (letrec ((_%$%loop181326181379%_
                                (lambda (_%$%hd181324181383%_
                                         _%$%arg181330181386%_)
                                  (if (gx#stx-pair? _%$%hd181324181383%_)
                                      (let ((_%$%e181327181389%_
                                             (gx#syntax-e
                                              _%$%hd181324181383%_)))
                                        (let ((_%$%lp-tl181329181396%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e181327181389%_)))
                                              (_%$%lp-hd181328181393%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e181327181389%_))))
                                          (_%$%loop181326181379%_
                                           _%$%lp-tl181329181396%_
                                           (cons _%$%lp-hd181328181393%_
                                                 _%$%arg181330181386%_))))
                                      (let ((_%$%arg181331181399%_
                                             (reverse _%$%arg181330181386%_)))
                                        (_%__kont182185182186%_
                                         _%$%arg181331181399%_))))))
                        (_%$%loop181326181379%_
                         _%$%target181323181373%_
                         '())))))
              (if (gx#stx-pair? _%__stx182182182183%_)
                  (let ((_%$%e181320181363%_
                         (gx#syntax-e _%__stx182182182183%_)))
                    (let ((_%$%tl181322181370%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e181320181363%_)))
                          (_%$%hd181321181367%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e181320181363%_))))
                      (if (gx#stx-pair/null? _%$%tl181322181370%_)
                          (let ((_%__splice182187182188%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl181322181370%_
                                  '0)))
                            (let ((_%$%tl181325181376%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182187182188%_
                                      '1)))
                                  (_%$%target181323181373%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182187182188%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl181325181376%_)
                                  (_%__match182205182206%_
                                   _%$%e181320181363%_
                                   _%$%hd181321181367%_
                                   _%$%tl181322181370%_
                                   _%__splice182187182188%_
                                   _%$%target181323181373%_
                                   _%$%tl181325181376%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g181316181356%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g181316181356%_)))))
                  (let () (declare (not safe)) (_%$%g181316181356%_))))))))
    (define |[:0:]#@module-load-order|
      (lambda (_%$stx181432%_)
        (let* ((_%__stx182208182209%_ _%$stx181432%_)
               (_%$%g181437181458%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid match target"
                   _%__stx182208182209%_))))
          (let ((_%__kont182211182212%_
                 (lambda (_%$%g181439181523%_)
                   (cons (gx#datum->syntax
                          |[1]#_g182255_|
                          'with-dispatch-arguments
                          '#f
                          '#f)
                         (cons (cons (cons (gx#datum->syntax '#f 'modpath) '())
                                     (cons (let ((__tmp182256
                                                  (lambda (_%$%g181538181541%_
                                                           _%$%g181539181544%_)
                                                    (cons _%$%g181538181541%_
                                                          _%$%g181539181544%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp182256
                                              '()
                                              _%$%g181439181523%_))
                                           '()))
                               (cons (cons (gx#datum->syntax
                                            |[1]#_g182258_|
                                            'using
                                            '#f
                                            '#f)
                                           (cons (cons (cons (gx#datum->syntax
                                                              '#f
                                                              'modpath)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            ':)
                           (cons (gx#datum->syntax '#f ':string) '())))
               '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons (gx#datum->syntax
                                                              '#f
                                                              '__module-load-order)
                                                             (cons (gx#datum->syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '#f
                            'modpath)
                           '()))
               '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     '())))))
                (_%__kont182215182216%_
                 (lambda (_%$%g181452181465%_)
                   (gx#datum->syntax '#f 'module-load-order))))
            (let* ((_%$%g181436181476%_
                    (lambda ()
                      (let ((_%$%g181452181465%_ _%__stx182208182209%_))
                        (if (gx#identifier? _%$%g181452181465%_)
                            (_%__kont182215182216%_ _%$%g181452181465%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g181437181458%_))))))
                   (_%__match182231182232%_
                    (lambda (_%$%e181440181483%_
                             _%$%hd181441181487%_
                             _%$%tl181442181490%_
                             _%__splice182213182214%_
                             _%$%target181443181493%_
                             _%$%tl181445181496%_)
                      (letrec ((_%$%loop181446181499%_
                                (lambda (_%$%hd181444181503%_
                                         _%$%arg181450181506%_)
                                  (if (gx#stx-pair? _%$%hd181444181503%_)
                                      (let ((_%$%e181447181509%_
                                             (gx#syntax-e
                                              _%$%hd181444181503%_)))
                                        (let ((_%$%lp-tl181449181516%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e181447181509%_)))
                                              (_%$%lp-hd181448181513%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e181447181509%_))))
                                          (_%$%loop181446181499%_
                                           _%$%lp-tl181449181516%_
                                           (cons _%$%lp-hd181448181513%_
                                                 _%$%arg181450181506%_))))
                                      (let ((_%$%arg181451181519%_
                                             (reverse _%$%arg181450181506%_)))
                                        (_%__kont182211182212%_
                                         _%$%arg181451181519%_))))))
                        (_%$%loop181446181499%_
                         _%$%target181443181493%_
                         '())))))
              (if (gx#stx-pair? _%__stx182208182209%_)
                  (let ((_%$%e181440181483%_
                         (gx#syntax-e _%__stx182208182209%_)))
                    (let ((_%$%tl181442181490%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e181440181483%_)))
                          (_%$%hd181441181487%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e181440181483%_))))
                      (if (gx#stx-pair/null? _%$%tl181442181490%_)
                          (let ((_%__splice182213182214%_
                                 (gx#syntax-split-splice->vector
                                  _%$%tl181442181490%_
                                  '0)))
                            (let ((_%$%tl181445181496%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182213182214%_
                                      '1)))
                                  (_%$%target181443181493%_
                                   (let ()
                                     (declare (not safe))
                                     (##vector-ref
                                      _%__splice182213182214%_
                                      '0))))
                              (if (gx#stx-null? _%$%tl181445181496%_)
                                  (_%__match182231182232%_
                                   _%$%e181440181483%_
                                   _%$%hd181441181487%_
                                   _%$%tl181442181490%_
                                   _%__splice182213182214%_
                                   _%$%target181443181493%_
                                   _%$%tl181445181496%_)
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g181436181476%_)))))
                          (let ()
                            (declare (not safe))
                            (_%$%g181436181476%_)))))
                  (let () (declare (not safe)) (_%$%g181436181476%_))))))))))
