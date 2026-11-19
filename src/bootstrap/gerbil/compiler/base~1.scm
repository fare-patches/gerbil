(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gxc[1]#_g203144_|
    (##structure
     gx#syntax-quote::t
     'symbol-table::t
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203146_|
    (##structure
     gx#syntax-quote::t
     'make-symbol-table
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203148_|
    (##structure
     gx#syntax-quote::t
     'symbol-table?
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203150_|
    (##structure
     gx#syntax-quote::t
     'symbol-table-gensyms
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203151_|
    (##structure
     gx#syntax-quote::t
     'symbol-table-bindings
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203153_|
    (##structure
     gx#syntax-quote::t
     'symbol-table-gensyms-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203154_|
    (##structure
     gx#syntax-quote::t
     'symbol-table-bindings-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203156_|
    (##structure
     gx#syntax-quote::t
     '&symbol-table-gensyms
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203157_|
    (##structure
     gx#syntax-quote::t
     '&symbol-table-bindings
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203159_|
    (##structure
     gx#syntax-quote::t
     '&symbol-table-gensyms-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gxc[1]#_g203160_|
    (##structure
     gx#syntax-quote::t
     '&symbol-table-bindings-set!
     #f
     (gx#current-expander-context)
     '()))
  (begin
    (define |gxc[:0:]#ast-case|
      (lambda (_%stx202104%_)
        (let ()
          (declare (not safe))
          (gx#macro-expand-syntax-case__%
           _%stx202104%_
           'stx-eq?
           'stx-e
           'quote))))
    (define |gxc[:0:]#ast-rules|
      (lambda (_%stx202107%_)
        (let* ((_%$%g202110202134%_
                (lambda (_%$%g202111202130%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g202111202130%_))))
               (_%$%g202109202433%_
                (lambda (_%$%g202111202138%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g202111202138%_))
                      (let ((_%$%e202114202141%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g202111202138%_))))
                        (let ((_%$%hd202115202145%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e202114202141%_)))
                              (_%$%tl202116202148%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e202114202141%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl202116202148%_))
                              (let ((_%$%e202117202151%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl202116202148%_))))
                                (let ((_%$%hd202118202155%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e202117202151%_)))
                                      (_%$%tl202119202158%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e202117202151%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl202119202158%_))
                                      (let ((_g203135_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%tl202119202158%_
                                                '0))))
                                        (begin
                                          (let ((_g203136_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g203135_)
                                                       (##values-length
                                                        _g203135_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g203136_ 2)))
                                                (error "Context expects 2 values"
                                                       _g203136_)))
                                          (let ((_%$%target202120202161%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g203135_ 0)))
                                                (_%$%tl202122202164%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g203135_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl202122202164%_))
                                                (letrec ((_%$%loop202123202167%_
                                                          (lambda (_%$%hd202121202171%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%clause202127202174%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd202121202171%_))
                        (let ((_%$%e202124202176%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-e _%$%hd202121202171%_))))
                          (let ((_%$%lp-hd202125202180%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e202124202176%_)))
                                (_%$%lp-tl202126202183%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e202124202176%_))))
                            (_%$%loop202123202167%_
                             _%$%lp-tl202126202183%_
                             (cons _%$%lp-hd202125202180%_
                                   _%$%clause202127202174%_))))
                        (let ((_%$%clause202128202186%_
                               (reverse _%$%clause202127202174%_)))
                          (if (let ()
                                (declare (not safe))
                                (gx#identifier-list? _%$%hd202118202155%_))
                              (let* ((_%$%g202210202227%_
                                      (lambda (_%$%g202211202223%_)
                                        (let ()
                                          (declare (not safe))
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid match target"
                                           _%$%g202211202223%_))))
                                     (_%$%g202209202286%_
                                      (lambda (_%$%g202211202231%_)
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair/null?
                                               _%$%g202211202231%_))
                                            (let ((_g203137_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#syntax-split-splice
                                                      _%$%g202211202231%_
                                                      '0))))
                                              (begin
                                                (let ((_g203138_
                                                       (let ()
                                                         (declare (not safe))
                                                         (if (##values?
                                                              _g203137_)
                                                             (##values-length
                                                              _g203137_)
                                                             1))))
                                                  (if (not (let ()
                                                             (declare
                                                               (not safe))
                                                             (##fx= _g203138_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            2)))
              (error "Context expects 2 values" _g203138_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ((_%$%target202213202234%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##values-ref
                                                          _g203137_
                                                          0)))
                                                      (_%$%tl202215202237%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##values-ref
                                                          _g203137_
                                                          1))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl202215202237%_))
                                                      (letrec ((_%$%loop202216202240%_
                                                                (lambda (_%$%hd202214202244%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 _%$%clause202220202247%_)
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd202214202244%_))
                              (let ((_%$%e202217202249%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%hd202214202244%_))))
                                (let ((_%$%lp-hd202218202253%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e202217202249%_)))
                                      (_%$%lp-tl202219202256%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e202217202249%_))))
                                  (_%$%loop202216202240%_
                                   _%$%lp-tl202219202256%_
                                   (cons _%$%lp-hd202218202253%_
                                         _%$%clause202220202247%_))))
                              (let ((_%$%clause202221202259%_
                                     (reverse _%$%clause202220202247%_)))
                                (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f 'lambda))
                                      (cons (cons (let ()
                                                    (declare (not safe))
                                                    (gx#datum->syntax__0
                                                     '#f
                                                     '$stx))
                                                  '())
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'ast-case))
                                                        (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f '$stx))
                      (cons _%$%hd202118202155%_
                            (let ((__tmp203139
                                   (lambda (_%$%g202277202280%_
                                            _%$%g202278202283%_)
                                     (cons _%$%g202277202280%_
                                           _%$%g202278202283%_))))
                              (declare (not safe))
                              (foldr__0
                               __tmp203139
                               '()
                               _%$%clause202221202259%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '()))))))))
                (_%$%loop202216202240%_ _%$%target202213202234%_ '()))
              (_%$%g202210202227%_ _%$%g202211202231%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%g202210202227%_
                                             _%$%g202211202231%_)))))
                                (_%$%g202209202286%_
                                 (let ((__tmp203142
                                        (lambda (_%clause202290%_)
                                          (let* ((_%__stx203054203055%_
                                                  _%clause202290%_)
                                                 (_%$%g202294202321%_
                                                  (lambda ()
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#raise-syntax-error
                                                       '#f
                                                       '"Bad syntax; invalid match target"
                                                       _%__stx203054203055%_)))))
                                            (let ((_%__kont203057203058%_
                                                   (lambda (_%$%g202296202406%_
                                                            _%$%g202297202408%_)
                                                     (cons _%$%g202297202408%_
                                                           (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 (declare (not safe))
                                 (gx#datum->syntax__0 '#f 'syntax))
                               (cons _%$%g202296202406%_ '()))
                         '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont203059203060%_
                                                   (lambda (_%$%g202304202358%_
                                                            _%$%g202305202360%_
                                                            _%$%g202306202361%_)
                                                     (cons _%$%g202306202361%_
                                                           (cons _%$%g202305202360%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (cons (let ()
                                       (declare (not safe))
                                       (gx#datum->syntax__0 '#f 'syntax))
                                     (cons _%$%g202304202358%_ '()))
                               '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%__stx203054203055%_))
                                                  (let ((_%$%e202298202386%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#syntax-e
                                                            _%__stx203054203055%_))))
                                                    (let ((_%$%tl202300202393%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e202298202386%_)))
                                                          (_%$%hd202299202390%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e202298202386%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl202300202393%_))
                                                          (let ((_%$%e202301202396%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#syntax-e _%$%tl202300202393%_))))
                    (let ((_%$%tl202303202403%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e202301202396%_)))
                          (_%$%hd202302202400%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e202301202396%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl202303202403%_))
                          (_%__kont203057203058%_
                           _%$%hd202302202400%_
                           _%$%hd202299202390%_)
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl202303202403%_))
                              (let ((_%$%e202313202348%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl202303202403%_))))
                                (let ((_%$%tl202315202355%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e202313202348%_)))
                                      (_%$%hd202314202352%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e202313202348%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl202315202355%_))
                                      (_%__kont203059203060%_
                                       _%$%hd202314202352%_
                                       _%$%hd202302202400%_
                                       _%$%hd202299202390%_)
                                      (_%$%g202294202321%_))))
                              (_%$%g202294202321%_)))))
                  (_%$%g202294202321%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g202294202321%_))))))
                                       (__tmp203140
                                        (let ((__tmp203141
                                               (lambda (_%$%g202424202427%_
                                                        _%$%g202425202430%_)
                                                 (cons _%$%g202424202427%_
                                                       _%$%g202425202430%_))))
                                          (declare (not safe))
                                          (foldr__0
                                           __tmp203141
                                           '()
                                           _%$%clause202128202186%_))))
                                   (declare (not safe))
                                   (gx#stx-map1 __tmp203142 __tmp203140))))
                              (_%$%g202110202134%_ _%$%g202111202138%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop202123202167%_
                                                   _%$%target202120202161%_
                                                   '()))
                                                (_%$%g202110202134%_
                                                 _%$%g202111202138%_)))))
                                      (_%$%g202110202134%_
                                       _%$%g202111202138%_))))
                              (_%$%g202110202134%_ _%$%g202111202138%_))))
                      (_%$%g202110202134%_ _%$%g202111202138%_)))))
          (_%$%g202109202433%_ _%stx202107%_))))
    (define |gxc[:0:]#symbol-table|
      (let ((__obj203104
             (let ()
               (declare (not safe))
               (##structure
                gerbil/core/mop~MOP-2#class-type-info::t
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f
                '#f))))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           __obj203104
           'gxc#symbol-table::t
           '2
           '#f
           '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 'symbol-table '3 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           __obj203104
           '(gensyms bindings)
           '6
           '#f
           '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           __obj203104
           '(gensyms bindings)
           '8
           '#f
           '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '() '5 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '#t '9 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '#f '10 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '#f '12 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 ':init! '13 '#f '#f))
        (let ((__tmp203143 |gxc[1]#_g203144_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203143 '4 '#f '#f))
        (let ((__tmp203145 |gxc[1]#_g203146_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203145 '14 '#f '#f))
        (let ((__tmp203147 |gxc[1]#_g203148_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203147 '15 '#f '#f))
        (let ((__tmp203149
               (cons (cons 'gensyms |gxc[1]#_g203150_|)
                     (cons (cons 'bindings |gxc[1]#_g203151_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203149 '16 '#f '#f))
        (let ((__tmp203152
               (cons (cons 'gensyms |gxc[1]#_g203153_|)
                     (cons (cons 'bindings |gxc[1]#_g203154_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203152 '17 '#f '#f))
        (let ((__tmp203155
               (cons (cons 'gensyms |gxc[1]#_g203156_|)
                     (cons (cons 'bindings |gxc[1]#_g203157_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203155 '18 '#f '#f))
        (let ((__tmp203158
               (cons (cons 'gensyms |gxc[1]#_g203159_|)
                     (cons (cons 'bindings |gxc[1]#_g203160_|) '()))))
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 __tmp203158 '19 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '() '20 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '() '22 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj203104 '() '21 '#f '#f))
        __obj203104))
    (define |gxc[:0:]#with-verbose-mutex|
      (lambda (_%$stx202439%_)
        (let* ((_%$%g202443202457%_
                (lambda (_%$%g202444202453%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g202444202453%_))))
               (_%$%g202442202498%_
                (lambda (_%$%g202444202461%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g202444202461%_))
                      (let ((_%$%e202446202464%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g202444202461%_))))
                        (let ((_%$%hd202447202468%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e202446202464%_)))
                              (_%$%tl202448202471%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e202446202464%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl202448202471%_))
                              (let ((_%$%e202449202474%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl202448202471%_))))
                                (let ((_%$%hd202450202478%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e202449202474%_)))
                                      (_%$%tl202451202481%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e202449202474%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl202451202481%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0
                                               '#f
                                               'with-lock))
                                            (cons (let ()
                                                    (declare (not safe))
                                                    (gx#datum->syntax__0
                                                     '#f
                                                     '__verbose-mutex))
                                                  (cons (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f 'lambda))
                      (cons '() (cons _%$%hd202450202478%_ '())))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (_%$%g202443202457%_
                                       _%$%g202444202461%_))))
                              (_%$%g202443202457%_ _%$%g202444202461%_))))
                      (_%$%g202443202457%_ _%$%g202444202461%_)))))
          (_%$%g202442202498%_ _%$stx202439%_))))
    (define |gxc[:0:]#go!|
      (lambda (_%$stx202502%_)
        (let* ((_%$%g202506202520%_
                (lambda (_%$%g202507202516%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g202507202516%_))))
               (_%$%g202505202561%_
                (lambda (_%$%g202507202524%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g202507202524%_))
                      (let ((_%$%e202509202527%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g202507202524%_))))
                        (let ((_%$%hd202510202531%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e202509202527%_)))
                              (_%$%tl202511202534%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e202509202527%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl202511202534%_))
                              (let ((_%$%e202512202537%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl202511202534%_))))
                                (let ((_%$%hd202513202541%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e202512202537%_)))
                                      (_%$%tl202514202544%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e202512202537%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl202514202544%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f 'spawn))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'lambda))
                                                        (cons '()
                                                              (cons _%$%hd202513202541%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '()))
                                      (_%$%g202506202520%_
                                       _%$%g202507202524%_))))
                              (_%$%g202506202520%_ _%$%g202507202524%_))))
                      (_%$%g202506202520%_ _%$%g202507202524%_)))))
          (_%$%g202505202561%_ _%$stx202502%_))))))
