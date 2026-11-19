(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gx[1]#_g202075_|
    (##structure
     gx#syntax-quote::t
     'expander
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202077_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern::t
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202079_|
    (##structure
     gx#syntax-quote::t
     'make-syntax-pattern
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202081_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern?
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202083_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern-id
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202084_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern-depth
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202085_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern-e
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202087_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern-id-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202088_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern-depth-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202089_|
    (##structure
     gx#syntax-quote::t
     'syntax-pattern-e-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202091_|
    (##structure
     gx#syntax-quote::t
     '&syntax-pattern-id
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202092_|
    (##structure
     gx#syntax-quote::t
     '&syntax-pattern-depth
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202093_|
    (##structure
     gx#syntax-quote::t
     '&syntax-pattern-e
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202095_|
    (##structure
     gx#syntax-quote::t
     '&syntax-pattern-id-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202096_|
    (##structure
     gx#syntax-quote::t
     '&syntax-pattern-depth-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gx[1]#_g202097_|
    (##structure
     gx#syntax-quote::t
     '&syntax-pattern-e-set!
     #f
     (gx#current-expander-context)
     '()))
  (begin
    (define |gx[:0:]#syntax-pattern|
      (let ((__obj201952
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
           __obj201952
           'gx#syntax-pattern::t
           '2
           '#f
           '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 'syntax-pattern '3 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '(id depth) '6 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '(e id depth) '8 '#f '#f))
        (let ((__tmp202074 (cons |gx[1]#_g202075_| '())))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202074 '5 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '#t '9 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '#f '10 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '#f '12 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '#f '13 '#f '#f))
        (let ((__tmp202076 |gx[1]#_g202077_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202076 '4 '#f '#f))
        (let ((__tmp202078 |gx[1]#_g202079_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202078 '14 '#f '#f))
        (let ((__tmp202080 |gx[1]#_g202081_|))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202080 '15 '#f '#f))
        (let ((__tmp202082
               (cons (cons 'id |gx[1]#_g202083_|)
                     (cons (cons 'depth |gx[1]#_g202084_|)
                           (cons (cons 'e |gx[1]#_g202085_|) '())))))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202082 '16 '#f '#f))
        (let ((__tmp202086
               (cons (cons 'id |gx[1]#_g202087_|)
                     (cons (cons 'depth |gx[1]#_g202088_|)
                           (cons (cons 'e |gx[1]#_g202089_|) '())))))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202086 '17 '#f '#f))
        (let ((__tmp202090
               (cons (cons 'id |gx[1]#_g202091_|)
                     (cons (cons 'depth |gx[1]#_g202092_|)
                           (cons (cons 'e |gx[1]#_g202093_|) '())))))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202090 '18 '#f '#f))
        (let ((__tmp202094
               (cons (cons 'id |gx[1]#_g202095_|)
                     (cons (cons 'depth |gx[1]#_g202096_|)
                           (cons (cons 'e |gx[1]#_g202097_|) '())))))
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 __tmp202094 '19 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '() '20 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '() '22 '#f '#f))
        (let ()
          (declare (not safe))
          (##unchecked-structure-set! __obj201952 '() '21 '#f '#f))
        __obj201952))
    (define |gx[:0:]#syntax-split-splice*|
      (lambda (_%$stx200407%_)
        (let* ((_%$%g200411200433%_
                (lambda (_%$%g200412200429%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g200412200429%_))))
               (_%$%g200410200503%_
                (lambda (_%$%g200412200437%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g200412200437%_))
                      (let ((_%$%e200416200440%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-e _%$%g200412200437%_))))
                        (let ((_%$%hd200417200444%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e200416200440%_)))
                              (_%$%tl200418200447%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e200416200440%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl200418200447%_))
                              (let ((_%$%e200419200450%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-e _%$%tl200418200447%_))))
                                (let ((_%$%hd200420200454%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e200419200450%_)))
                                      (_%$%tl200421200457%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e200419200450%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl200421200457%_))
                                      (let ((_%$%e200422200460%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-e
                                                _%$%tl200421200457%_))))
                                        (let ((_%$%hd200423200464%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e200422200460%_)))
                                              (_%$%tl200424200467%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e200422200460%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl200424200467%_))
                                              (let ((_%$%e200425200470%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-e
                                                        _%$%tl200424200467%_))))
                                                (let ((_%$%hd200426200474%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e200425200470%_)))
                                                      (_%$%tl200427200477%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e200425200470%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl200427200477%_))
                                                      (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'let))
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gx#datum->syntax__0 '#f 'lp))
                          (cons (cons (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f 'rest))
                                            (cons _%$%hd200420200454%_ '()))
                                      (cons (cons (let ()
                                                    (declare (not safe))
                                                    (gx#datum->syntax__0
                                                     '#f
                                                     'r))
                                                  (cons (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f '@list))
                      '())
                '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '()))
                                (cons (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f 'if))
                                            (cons (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           'stx-pair?))
                                                        (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f 'rest))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#datum->syntax__0 '#f 'match))
                      (cons (cons (let ()
                                    (declare (not safe))
                                    (gx#datum->syntax__0 '#f 'syntax-e))
                                  (cons (let ()
                                          (declare (not safe))
                                          (gx#datum->syntax__0 '#f 'rest))
                                        '()))
                            (cons (cons (cons (let ()
                                                (declare (not safe))
                                                (gx#datum->syntax__0
                                                 '#f
                                                 '@list))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'hd))
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'rest))))
                                        (cons (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'lp))
                                                    (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#datum->syntax__0
                                                             '#f
                                                             'rest))
                                                          (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'cons))
                              (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f 'hd))
                                    (cons (let ()
                                            (declare (not safe))
                                            (gx#datum->syntax__0 '#f 'r))
                                          '())))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))
                                  '())))
                (cons (cons (let ()
                              (declare (not safe))
                              (gx#datum->syntax__0 '#f 'let))
                            (cons (let ()
                                    (declare (not safe))
                                    (gx#datum->syntax__0 '#f 'lp))
                                  (cons (cons (cons _%$%hd200423200464%_
                                                    (cons _%$%hd200423200464%_
                                                          '()))
                                              (cons (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#datum->syntax__0
                                                             '#f
                                                             'l))
                                                          (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'r))
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#datum->syntax__0 '#f 'r))
                        (cons (let ()
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'rest))
                              '()))
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       'cond))
                                                    (cons (cons (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (declare (not safe))
                                (gx#datum->syntax__0 '#f 'null?))
                              (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f 'l))
                                    '()))
                        (cons (cons _%$%hd200426200474%_
                                    (cons (let ()
                                            (declare (not safe))
                                            (gx#datum->syntax__0 '#f 'l))
                                          (cons (let ()
                                                  (declare (not safe))
                                                  (gx#datum->syntax__0 '#f 'r))
                                                '())))
                              '()))
                  (cons (cons (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f 'fxpositive?))
                                    (cons _%$%hd200423200464%_ '()))
                              (cons (cons (let ()
                                            (declare (not safe))
                                            (gx#datum->syntax__0 '#f 'lp))
                                          (cons (cons (let ()
                                                        (declare (not safe))
                                                        (gx#datum->syntax__0
                                                         '#f
                                                         'fx1-))
                                                      (cons _%$%hd200423200464%_
                                                            '()))
                                                (cons (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'cdr))
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gx#datum->syntax__0 '#f 'l))
                          '()))
              (cons (cons (let ()
                            (declare (not safe))
                            (gx#datum->syntax__0 '#f 'cons))
                          (cons (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f 'car))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f 'l))
                                            '()))
                                (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f 'r))
                                      '())))
                    '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '()))
                        (cons (cons (let ()
                                      (declare (not safe))
                                      (gx#datum->syntax__0 '#f 'else))
                                    (cons (cons _%$%hd200426200474%_
                                                (cons (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#datum->syntax__0
                                                               '#f
                                                               'reverse!))
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gx#datum->syntax__0 '#f 'l))
                          '()))
              (cons (let () (declare (not safe)) (gx#datum->syntax__0 '#f 'r))
                    '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          '()))
                              '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))))
                      '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '()))))
              (_%$%g200411200433%_ _%$%g200412200437%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g200411200433%_
                                               _%$%g200412200437%_))))
                                      (_%$%g200411200433%_
                                       _%$%g200412200437%_))))
                              (_%$%g200411200433%_ _%$%g200412200437%_))))
                      (_%$%g200411200433%_ _%$%g200412200437%_)))))
          (_%$%g200410200503%_ _%$stx200407%_))))))
