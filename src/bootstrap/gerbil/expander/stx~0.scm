(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/stx::timestamp 1795039816)
  (begin
    (declare (not safe))
    (define gx#identifier-wrap::t
      (make-class-type
       'gx#identifier-wrap::t
       'syntax
       (list gx#AST::t)
       '(marks)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print:))))
       '#f))
    (define gx#identifier-wrap? (__make-class-predicate gx#identifier-wrap::t))
    (define gx#make-identifier-wrap
      (lambda _%$args185409%_
        (apply make-instance gx#identifier-wrap::t _%$args185409%_)))
    (define gx#identifier-wrap-marks
      (__make-class-slot-accessor gx#identifier-wrap::t 'marks))
    (define gx#identifier-wrap-e
      (__make-class-slot-accessor gx#identifier-wrap::t 'e))
    (define gx#identifier-wrap-source
      (__make-class-slot-accessor gx#identifier-wrap::t 'source))
    (define gx#identifier-wrap-marks-set!
      (__make-class-slot-mutator gx#identifier-wrap::t 'marks))
    (define gx#identifier-wrap-e-set!
      (__make-class-slot-mutator gx#identifier-wrap::t 'e))
    (define gx#identifier-wrap-source-set!
      (__make-class-slot-mutator gx#identifier-wrap::t 'source))
    (define gx#&identifier-wrap-marks
      (__make-class-slot-unchecked-accessor gx#identifier-wrap::t 'marks))
    (define gx#&identifier-wrap-e
      (__make-class-slot-unchecked-accessor gx#identifier-wrap::t 'e))
    (define gx#&identifier-wrap-source
      (__make-class-slot-unchecked-accessor gx#identifier-wrap::t 'source))
    (define gx#&identifier-wrap-marks-set!
      (__make-class-slot-unchecked-mutator gx#identifier-wrap::t 'marks))
    (define gx#&identifier-wrap-e-set!
      (__make-class-slot-unchecked-mutator gx#identifier-wrap::t 'e))
    (define gx#&identifier-wrap-source-set!
      (__make-class-slot-unchecked-mutator gx#identifier-wrap::t 'source))
    (define gx#syntax-wrap::t
      (make-class-type
       'gx#syntax-wrap::t
       'syntax
       (list gx#AST::t)
       '(mark)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print:))))
       '#f))
    (define gx#syntax-wrap? (__make-class-predicate gx#syntax-wrap::t))
    (define gx#make-syntax-wrap
      (lambda _%$args185406%_
        (apply make-instance gx#syntax-wrap::t _%$args185406%_)))
    (define gx#syntax-wrap-mark
      (__make-class-slot-accessor gx#syntax-wrap::t 'mark))
    (define gx#syntax-wrap-e (__make-class-slot-accessor gx#syntax-wrap::t 'e))
    (define gx#syntax-wrap-source
      (__make-class-slot-accessor gx#syntax-wrap::t 'source))
    (define gx#syntax-wrap-mark-set!
      (__make-class-slot-mutator gx#syntax-wrap::t 'mark))
    (define gx#syntax-wrap-e-set!
      (__make-class-slot-mutator gx#syntax-wrap::t 'e))
    (define gx#syntax-wrap-source-set!
      (__make-class-slot-mutator gx#syntax-wrap::t 'source))
    (define gx#&syntax-wrap-mark
      (__make-class-slot-unchecked-accessor gx#syntax-wrap::t 'mark))
    (define gx#&syntax-wrap-e
      (__make-class-slot-unchecked-accessor gx#syntax-wrap::t 'e))
    (define gx#&syntax-wrap-source
      (__make-class-slot-unchecked-accessor gx#syntax-wrap::t 'source))
    (define gx#&syntax-wrap-mark-set!
      (__make-class-slot-unchecked-mutator gx#syntax-wrap::t 'mark))
    (define gx#&syntax-wrap-e-set!
      (__make-class-slot-unchecked-mutator gx#syntax-wrap::t 'e))
    (define gx#&syntax-wrap-source-set!
      (__make-class-slot-unchecked-mutator gx#syntax-wrap::t 'source))
    (define gx#syntax-quote::t
      (make-class-type
       'gx#syntax-quote::t
       'syntax
       (list gx#AST::t)
       '(context marks)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print:))))
       '#f))
    (define gx#syntax-quote? (__make-class-predicate gx#syntax-quote::t))
    (define gx#make-syntax-quote
      (lambda _%$args185403%_
        (apply make-instance gx#syntax-quote::t _%$args185403%_)))
    (define gx#syntax-quote-context
      (__make-class-slot-accessor gx#syntax-quote::t 'context))
    (define gx#syntax-quote-marks
      (__make-class-slot-accessor gx#syntax-quote::t 'marks))
    (define gx#syntax-quote-e
      (__make-class-slot-accessor gx#syntax-quote::t 'e))
    (define gx#syntax-quote-source
      (__make-class-slot-accessor gx#syntax-quote::t 'source))
    (define gx#syntax-quote-context-set!
      (__make-class-slot-mutator gx#syntax-quote::t 'context))
    (define gx#syntax-quote-marks-set!
      (__make-class-slot-mutator gx#syntax-quote::t 'marks))
    (define gx#syntax-quote-e-set!
      (__make-class-slot-mutator gx#syntax-quote::t 'e))
    (define gx#syntax-quote-source-set!
      (__make-class-slot-mutator gx#syntax-quote::t 'source))
    (define gx#&syntax-quote-context
      (__make-class-slot-unchecked-accessor gx#syntax-quote::t 'context))
    (define gx#&syntax-quote-marks
      (__make-class-slot-unchecked-accessor gx#syntax-quote::t 'marks))
    (define gx#&syntax-quote-e
      (__make-class-slot-unchecked-accessor gx#syntax-quote::t 'e))
    (define gx#&syntax-quote-source
      (__make-class-slot-unchecked-accessor gx#syntax-quote::t 'source))
    (define gx#&syntax-quote-context-set!
      (__make-class-slot-unchecked-mutator gx#syntax-quote::t 'context))
    (define gx#&syntax-quote-marks-set!
      (__make-class-slot-unchecked-mutator gx#syntax-quote::t 'marks))
    (define gx#&syntax-quote-e-set!
      (__make-class-slot-unchecked-mutator gx#syntax-quote::t 'e))
    (define gx#&syntax-quote-source-set!
      (__make-class-slot-unchecked-mutator gx#syntax-quote::t 'source))
    (define gx#identifier?
      (lambda (_%stx185401%_) (symbol? (gx#stx-e _%stx185401%_))))
    (define gx#identifier-quote?
      (lambda (_%stx185399%_)
        (if (##structure-direct-instance-of? _%stx185399%_ 'gx#syntax-quote::t)
            (symbol? (##unchecked-structure-ref _%stx185399%_ '1 '#f '#f))
            '#f)))
    (define gx#sealed-syntax?
      (lambda (_%stx185394%_)
        (if (##structure-direct-instance-of? _%stx185394%_ 'gx#syntax-quote::t)
            '#t
            (if (##structure-direct-instance-of?
                 _%stx185394%_
                 'gx#syntax-wrap::t)
                (gx#sealed-syntax?
                 (##unchecked-structure-ref _%stx185394%_ '1 '#f '#f))
                '#f))))
    (define gx#sealed-syntax-unwrap
      (lambda (_%stx185389%_)
        (if (##structure-direct-instance-of? _%stx185389%_ 'gx#syntax-quote::t)
            _%stx185389%_
            (if (##structure-direct-instance-of?
                 _%stx185389%_
                 'gx#syntax-wrap::t)
                (gx#sealed-syntax-unwrap
                 (##unchecked-structure-ref _%stx185389%_ '1 '#f '#f))
                '#f))))
    (define gx#syntax-e
      (lambda (_%stx185363%_)
        (if (##structure-direct-instance-of? _%stx185363%_ 'gx#syntax-wrap::t)
            (let _%lp185366%_ ((_%e185368%_
                                (##unchecked-structure-ref
                                 _%stx185363%_
                                 '1
                                 '#f
                                 '#f))
                               (_%marks185369%_
                                (cons (##unchecked-structure-ref
                                       _%stx185363%_
                                       '3
                                       '#f
                                       '#f)
                                      '())))
              (if (##structure? _%e185368%_)
                  (let ((_%$e185372%_
                         (##type-id (##structure-type _%e185368%_))))
                    (if (eq? 'gx#syntax-wrap::t _%$e185372%_)
                        (_%lp185366%_
                         (##unchecked-structure-ref _%e185368%_ '1 '#f '#f)
                         (gx#apply-mark
                          (##unchecked-structure-ref _%e185368%_ '3 '#f '#f)
                          _%marks185369%_))
                        (if (or (eq? 'gx#syntax-quote::t _%$e185372%_)
                                (eq? 'gx#identifier-wrap::t _%$e185372%_))
                            (##unchecked-structure-ref _%e185368%_ '1 '#f '#f)
                            (if (eq? 'gerbil#AST::t _%$e185372%_)
                                (_%lp185366%_
                                 (##unchecked-structure-ref
                                  _%e185368%_
                                  '1
                                  '#f
                                  '#f)
                                 _%marks185369%_)
                                _%e185368%_))))
                  (if (null? _%marks185369%_)
                      _%e185368%_
                      (if (pair? _%e185368%_)
                          (cons (gx#stx-wrap
                                 (##car _%e185368%_)
                                 _%marks185369%_)
                                (gx#stx-wrap
                                 (##cdr _%e185368%_)
                                 _%marks185369%_))
                          (if (vector? _%e185368%_)
                              (vector-map
                               (lambda (_%$%g185380185382%_)
                                 (gx#stx-wrap
                                  _%$%g185380185382%_
                                  _%marks185369%_))
                               _%e185368%_)
                              (if (box? _%e185368%_)
                                  (box (gx#stx-wrap
                                        (unbox _%e185368%_)
                                        _%marks185369%_))
                                  _%e185368%_))))))
            (if (##structure-instance-of? _%stx185363%_ 'gerbil#AST::t)
                (##unchecked-structure-ref _%stx185363%_ '1 '#f '#f)
                _%stx185363%_))))
    (define gx#syntax->datum
      (lambda (_%stx185356%_)
        (if (##structure-instance-of? _%stx185356%_ 'gerbil#AST::t)
            (gx#syntax->datum
             (##unchecked-structure-ref _%stx185356%_ '1 '#f '#f))
            (if (pair? _%stx185356%_)
                (cons (gx#syntax->datum (##car _%stx185356%_))
                      (gx#syntax->datum (##cdr _%stx185356%_)))
                (if (vector? _%stx185356%_)
                    (vector-map gx#syntax->datum _%stx185356%_)
                    (if (box? _%stx185356%_)
                        (box (gx#syntax->datum (unbox _%stx185356%_)))
                        _%stx185356%_))))))
    (define gx#datum->syntax__%
      (lambda (_%stx185290%_ _%datum185291%_ _%src185292%_ _%quote?185293%_)
        (letrec ((_%wrap-datum185295%_
                  (lambda (_%e185328%_ _%marks185329%_)
                    (_%wrap-inner185297%_
                     _%e185328%_
                     (lambda (_%$%g185330185332%_)
                       (##structure
                        gx#identifier-wrap::t
                        _%$%g185330185332%_
                        _%src185292%_
                        _%marks185329%_)))))
                 (_%wrap-quote185296%_
                  (lambda (_%e185320%_ _%ctx185321%_ _%marks185322%_)
                    (_%wrap-inner185297%_
                     _%e185320%_
                     (lambda (_%$%g185323185325%_)
                       (##structure
                        gx#syntax-quote::t
                        _%$%g185323185325%_
                        _%src185292%_
                        _%ctx185321%_
                        _%marks185322%_)))))
                 (_%wrap-inner185297%_
                  (lambda (_%e185308%_ _%wrap-e185309%_)
                    (let _%recur185311%_ ((_%e185313%_ _%e185308%_))
                      (if (symbol? _%e185313%_)
                          (_%wrap-e185309%_ _%e185313%_)
                          (if (pair? _%e185313%_)
                              (cons (_%recur185311%_ (##car _%e185313%_))
                                    (_%recur185311%_ (##cdr _%e185313%_)))
                              (if (vector? _%e185313%_)
                                  (vector-map _%recur185311%_ _%e185313%_)
                                  (if (box? _%e185313%_)
                                      (box (_%recur185311%_
                                            (unbox _%e185313%_)))
                                      _%e185313%_)))))))
                 (_%wrap-outer185298%_
                  (lambda (_%e185306%_)
                    (if (##structure-instance-of? _%e185306%_ 'gerbil#AST::t)
                        _%e185306%_
                        (##structure gx#AST::t _%e185306%_ _%src185292%_)))))
          (if (##structure-instance-of? _%datum185291%_ 'gerbil#AST::t)
              _%datum185291%_
              (if _%stx185290%_
                  (if (gx#identifier? _%stx185290%_)
                      (let ((_%stx185303%_ (gx#stx-unwrap__0 _%stx185290%_)))
                        (_%wrap-outer185298%_
                         (if (##structure-direct-instance-of?
                              _%stx185303%_
                              'gx#syntax-quote::t)
                             (if _%quote?185293%_
                                 (_%wrap-quote185296%_
                                  _%datum185291%_
                                  (##unchecked-structure-ref
                                   _%stx185303%_
                                   '3
                                   '#f
                                   '#f)
                                  (##unchecked-structure-ref
                                   _%stx185303%_
                                   '4
                                   '#f
                                   '#f))
                                 (_%wrap-datum185295%_
                                  _%datum185291%_
                                  (##unchecked-structure-ref
                                   _%stx185303%_
                                   '4
                                   '#f
                                   '#f)))
                             (_%wrap-datum185295%_
                              _%datum185291%_
                              (##unchecked-structure-ref
                               _%stx185303%_
                               '3
                               '#f
                               '#f)))))
                      (error '"Bad template syntax; expected identifier"
                             _%stx185290%_))
                  (##structure gx#AST::t _%datum185291%_ _%src185292%_))))))
    (define gx#datum->syntax__0
      (lambda (_%stx185338%_ _%datum185339%_)
        (let* ((_%src185341%_ '#f) (_%quote?185343%_ '#t))
          (gx#datum->syntax__%
           _%stx185338%_
           _%datum185339%_
           _%src185341%_
           _%quote?185343%_))))
    (define gx#datum->syntax__1
      (lambda (_%stx185345%_ _%datum185346%_ _%src185347%_)
        (let ((_%quote?185349%_ '#t))
          (gx#datum->syntax__%
           _%stx185345%_
           _%datum185346%_
           _%src185347%_
           _%quote?185349%_))))
    (define gx#datum->syntax
      (lambda _g185489_
        (let ((_g185490_ (##length _g185489_)))
          (cond ((##fx= _g185490_ 2) (apply gx#datum->syntax__0 _g185489_))
                ((##fx= _g185490_ 3) (apply gx#datum->syntax__1 _g185489_))
                ((##fx= _g185490_ 4) (apply gx#datum->syntax__% _g185489_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#datum->syntax
                  _g185489_))))))
    (define gx#stx-unwrap__%
      (lambda (_%stx185256%_ _%marks185257%_)
        (let _%lp185259%_ ((_%e185261%_ _%stx185256%_)
                           (_%marks185262%_ _%marks185257%_)
                           (_%src185263%_ (gx#stx-source _%stx185256%_)))
          (if (##structure-direct-instance-of? _%e185261%_ 'gx#syntax-wrap::t)
              (_%lp185259%_
               (##unchecked-structure-ref _%e185261%_ '1 '#f '#f)
               (gx#apply-mark
                (##unchecked-structure-ref _%e185261%_ '3 '#f '#f)
                _%marks185262%_)
               (##unchecked-structure-ref _%e185261%_ '2 '#f '#f))
              (if (##structure-direct-instance-of?
                   _%e185261%_
                   'gx#identifier-wrap::t)
                  (if (null? _%marks185262%_)
                      _%e185261%_
                      (##structure
                       gx#identifier-wrap::t
                       (##unchecked-structure-ref _%e185261%_ '1 '#f '#f)
                       (##unchecked-structure-ref _%e185261%_ '2 '#f '#f)
                       (foldl__0
                        gx#apply-mark
                        (##unchecked-structure-ref _%e185261%_ '3 '#f '#f)
                        _%marks185262%_)))
                  (if (##structure-direct-instance-of?
                       _%e185261%_
                       'gx#syntax-quote::t)
                      _%e185261%_
                      (if (##structure-instance-of? _%e185261%_ 'gerbil#AST::t)
                          (_%lp185259%_
                           (##unchecked-structure-ref _%e185261%_ '1 '#f '#f)
                           _%marks185262%_
                           (##unchecked-structure-ref _%e185261%_ '2 '#f '#f))
                          (if (symbol? _%e185261%_)
                              (##structure
                               gx#identifier-wrap::t
                               _%e185261%_
                               _%src185263%_
                               (reverse _%marks185262%_))
                              (if (null? _%marks185262%_)
                                  _%e185261%_
                                  (if (pair? _%e185261%_)
                                      (cons (gx#stx-wrap
                                             (##car _%e185261%_)
                                             _%marks185262%_)
                                            (gx#stx-wrap
                                             (##cdr _%e185261%_)
                                             _%marks185262%_))
                                      (if (vector? _%e185261%_)
                                          (vector-map
                                           (lambda (_%$%g185272185274%_)
                                             (gx#stx-wrap
                                              _%$%g185272185274%_
                                              _%marks185262%_))
                                           _%e185261%_)
                                          (if (box? _%e185261%_)
                                              (box (gx#stx-wrap
                                                    (unbox _%e185261%_)
                                                    _%marks185262%_))
                                              _%e185261%_))))))))))))
    (define gx#stx-unwrap__0
      (lambda (_%stx185282%_)
        (let ((_%marks185284%_ '()))
          (gx#stx-unwrap__% _%stx185282%_ _%marks185284%_))))
    (define gx#stx-unwrap
      (lambda _g185491_
        (let ((_g185492_ (##length _g185491_)))
          (cond ((##fx= _g185492_ 1) (apply gx#stx-unwrap__0 _g185491_))
                ((##fx= _g185492_ 2) (apply gx#stx-unwrap__% _g185491_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#stx-unwrap
                  _g185491_))))))
    (define gx#stx-wrap
      (lambda (_%stx185249%_ _%marks185250%_)
        (foldl__0
         (lambda (_%mark185252%_ _%stx185253%_)
           (gx#stx-apply-mark _%stx185253%_ _%mark185252%_))
         _%stx185249%_
         _%marks185250%_)))
    (define gx#stx-rewrap
      (lambda (_%stx185243%_ _%marks185244%_)
        (foldr__0
         (lambda (_%mark185246%_ _%stx185247%_)
           (gx#stx-apply-mark _%stx185247%_ _%mark185246%_))
         _%stx185243%_
         _%marks185244%_)))
    (define gx#stx-apply-mark
      (lambda (_%stx185237%_ _%mark185238%_)
        (if (##structure-direct-instance-of? _%stx185237%_ 'gx#syntax-quote::t)
            _%stx185237%_
            (if (and (##structure-direct-instance-of?
                      _%stx185237%_
                      'gx#syntax-wrap::t)
                     (eq? _%mark185238%_
                          (##unchecked-structure-ref
                           _%stx185237%_
                           '3
                           '#f
                           '#f)))
                (##unchecked-structure-ref _%stx185237%_ '1 '#f '#f)
                (##structure
                 gx#syntax-wrap::t
                 _%stx185237%_
                 (gx#stx-source _%stx185237%_)
                 _%mark185238%_)))))
    (define gx#apply-mark
      (lambda (_%mark185201%_ _%marks185202%_)
        (let* ((_%$%marks185203185211%_ _%marks185202%_)
               (_%$%else185205185219%_
                (lambda () (cons _%mark185201%_ _%marks185202%_)))
               (_%$%K185207185225%_
                (lambda (_%rest185222%_ _%hd185223%_)
                  (if (eq? _%mark185201%_ _%hd185223%_)
                      _%rest185222%_
                      (cons _%mark185201%_ _%marks185202%_)))))
          (if (pair? _%$%marks185203185211%_)
              (let ((_%$%hd185208185228%_ (##car _%$%marks185203185211%_))
                    (_%$%tl185209185230%_ (##cdr _%$%marks185203185211%_)))
                (let* ((_%hd185233%_ _%$%hd185208185228%_)
                       (_%rest185235%_ _%$%tl185209185230%_))
                  (_%$%K185207185225%_ _%rest185235%_ _%hd185233%_)))
              (_%$%else185205185219%_)))))
    (define gx#stx-e
      (lambda (_%stx185196%_)
        (if (##structure-direct-instance-of? _%stx185196%_ 'gx#syntax-wrap::t)
            (gx#stx-e (##unchecked-structure-ref _%stx185196%_ '1 '#f '#f))
            (if (##structure-instance-of? _%stx185196%_ 'gerbil#AST::t)
                (##unchecked-structure-ref _%stx185196%_ '1 '#f '#f)
                _%stx185196%_))))
    (define gx#stx-source
      (lambda (_%stx185194%_)
        (if (##structure-instance-of? _%stx185194%_ 'gerbil#AST::t)
            (##unchecked-structure-ref _%stx185194%_ '2 '#f '#f)
            '#f)))
    (define gx#stx-wrap-source
      (lambda (_%stx185188%_ _%src185189%_)
        (if (or (##structure-instance-of? _%stx185188%_ 'gerbil#AST::t)
                (not _%src185189%_))
            _%stx185188%_
            (##structure gx#AST::t _%stx185188%_ _%src185189%_))))
    (define gx#stx-datum?
      (lambda (_%stx185186%_) (gx#self-quoting? (gx#stx-e _%stx185186%_))))
    (define gx#self-quoting?
      (lambda (_%x185169%_)
        (let ((_%$e185171%_ (immediate? _%x185169%_)))
          (if _%$e185171%_
              _%$e185171%_
              (let ((_%$e185174%_ (number? _%x185169%_)))
                (if _%$e185174%_
                    _%$e185174%_
                    (let ((_%$e185177%_ (keyword? _%x185169%_)))
                      (if _%$e185177%_
                          _%$e185177%_
                          (let ((_%$e185180%_ (string? _%x185169%_)))
                            (if _%$e185180%_
                                _%$e185180%_
                                (let ((_%$e185183%_ (vector? _%x185169%_)))
                                  (if _%$e185183%_
                                      _%$e185183%_
                                      (u8vector? _%x185169%_)))))))))))))
    (define gx#stx-boolean?
      (lambda (_%e185167%_) (boolean? (gx#stx-e _%e185167%_))))
    (define gx#stx-keyword?
      (lambda (_%e185165%_) (keyword? (gx#stx-e _%e185165%_))))
    (define gx#stx-char? (lambda (_%e185163%_) (char? (gx#stx-e _%e185163%_))))
    (define gx#stx-number?
      (lambda (_%e185161%_) (number? (gx#stx-e _%e185161%_))))
    (define gx#stx-fixnum?
      (lambda (_%e185159%_) (fixnum? (gx#stx-e _%e185159%_))))
    (define gx#stx-string?
      (lambda (_%e185157%_) (string? (gx#stx-e _%e185157%_))))
    (define gx#stx-null? (lambda (_%e185155%_) (null? (gx#stx-e _%e185155%_))))
    (define gx#stx-pair? (lambda (_%e185153%_) (pair? (gx#stx-e _%e185153%_))))
    (define gx#stx-list?
      (lambda (_%e185115%_)
        (let* ((_%$%g185116185125%_ (gx#stx-e _%e185115%_))
               (_%$%E185119185129%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%g185116185125%_
                         '([_ . rest])
                         '(tail))
                  '#!void)))
          (let ((_%$%K185121185145%_
                 (lambda (_%rest185143%_) (gx#stx-list? _%rest185143%_)))
                (_%$%K185120185135%_
                 (lambda (_%tail185133%_) (null? _%tail185133%_))))
            (if (pair? _%$%g185116185125%_)
                (let* ((_%$%tl185123185148%_ (##cdr _%$%g185116185125%_))
                       (_%rest185151%_ _%$%tl185123185148%_))
                  (gx#stx-list? _%rest185151%_))
                (let ((_%tail185138%_ _%$%g185116185125%_))
                  (null? _%tail185138%_)))))))
    (define gx#stx-pair/null?
      (lambda (_%e185108%_)
        (let* ((_%e185110%_ (gx#stx-e _%e185108%_))
               (_%$e185112%_ (pair? _%e185110%_)))
          (if _%$e185112%_ _%$e185112%_ (null? _%e185110%_)))))
    (define gx#stx-vector?
      (lambda (_%e185106%_) (vector? (gx#stx-e _%e185106%_))))
    (define gx#stx-box? (lambda (_%e185104%_) (box? (gx#stx-e _%e185104%_))))
    (define gx#stx-eq?
      (lambda (_%x185101%_ _%y185102%_)
        (eq? (gx#stx-e _%x185101%_) (gx#stx-e _%y185102%_))))
    (define gx#stx-eqv?
      (lambda (_%x185098%_ _%y185099%_)
        (eqv? (gx#stx-e _%x185098%_) (gx#stx-e _%y185099%_))))
    (define gx#stx-equal?
      (lambda (_%x185095%_ _%y185096%_)
        (equal? (gx#stx-e _%x185095%_) (gx#stx-e _%y185096%_))))
    (define gx#stx-false? (lambda (_%x185093%_) (not (gx#stx-e _%x185093%_))))
    (define gx#stx-identifier
      (lambda (_%template185090%_ . _%args185091%_)
        (gx#datum->syntax__1
         _%template185090%_
         (apply make-symbol (gx#syntax->datum _%args185091%_))
         (gx#stx-source _%template185090%_))))
    (define gx#stx-identifier-marks
      (lambda (_%stx185088%_)
        (gx#stx-identifier-marks* (gx#stx-unwrap__0 _%stx185088%_))))
    (define gx#stx-identifier-marks*
      (lambda (_%stx185083%_)
        (if (##structure-direct-instance-of?
             _%stx185083%_
             'gx#identifier-wrap::t)
            (##unchecked-structure-ref _%stx185083%_ '3 '#f '#f)
            (if (##structure-direct-instance-of?
                 _%stx185083%_
                 'gx#syntax-quote::t)
                (##unchecked-structure-ref _%stx185083%_ '4 '#f '#f)
                (error '"Bad wrap; expected unwrapped identifier"
                       _%stx185083%_)))))
    (define gx#stx-identifier-context
      (lambda (_%stx185079%_)
        (let ((_%stx185081%_ (gx#stx-unwrap__0 _%stx185079%_)))
          (if (gx#identifier-quote? _%stx185081%_)
              (##unchecked-structure-ref _%stx185081%_ '3 '#f '#f)
              '#f))))
    (define gx#identifier-list?
      (lambda (_%stx185034%_)
        (let* ((_%$%g185035185045%_ (gx#stx-e _%stx185034%_))
               (_%$%else185038185053%_ (lambda () '#f)))
          (let ((_%$%K185041185067%_
                 (lambda (_%rest185064%_ _%hd185065%_)
                   (if (gx#identifier? _%hd185065%_)
                       (gx#identifier-list? _%rest185064%_)
                       '#f)))
                (_%$%K185040185058%_ (lambda () '#t)))
            (let ((_%$%try-match185037185061%_
                   (lambda ()
                     (if (null? _%$%g185035185045%_)
                         (_%$%K185040185058%_)
                         (_%$%else185038185053%_)))))
              (if (pair? _%$%g185035185045%_)
                  (let ((_%$%tl185043185072%_ (##cdr _%$%g185035185045%_))
                        (_%$%hd185042185070%_ (##car _%$%g185035185045%_)))
                    (let ((_%hd185075%_ _%$%hd185042185070%_)
                          (_%rest185077%_ _%$%tl185043185072%_))
                      (_%$%K185041185067%_ _%rest185077%_ _%hd185075%_)))
                  (_%$%try-match185037185061%_)))))))
    (define gx#genident__%
      (lambda (_%e185014%_ _%src185015%_)
        (gx#datum->syntax__1
         (if (gx#identifier? _%src185015%_) _%src185015%_ '#f)
         (make-symbol__1
          '"$%"
          (##gensym
           (let ((_%e185017%_ (gx#stx-e _%e185014%_)))
             (if (symbol? _%e185017%_) _%e185017%_ 'g))))
         _%src185015%_)))
    (define gx#genident__0
      (lambda ()
        (let* ((_%e185023%_ 'g) (_%src185025%_ '#f))
          (gx#genident__% _%e185023%_ _%src185025%_))))
    (define gx#genident__1
      (lambda (_%e185027%_)
        (let ((_%src185029%_ '#f))
          (gx#genident__% _%e185027%_ _%src185029%_))))
    (define gx#genident
      (lambda _g185493_
        (let ((_g185494_ (##length _g185493_)))
          (cond ((##fx= _g185494_ 0) (apply gx#genident__0 _g185493_))
                ((##fx= _g185494_ 1) (apply gx#genident__1 _g185493_))
                ((##fx= _g185494_ 2) (apply gx#genident__% _g185493_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#genident
                  _g185493_))))))
    (define gx#gentemps
      (lambda (_%stx-lst185009%_)
        (gx#stx-map1
         (lambda (_%x185011%_) (gx#genident__% _%x185011%_ _%x185011%_))
         _%stx-lst185009%_)))
    (define gx#syntax->list
      (lambda (_%stx185007%_) (gx#stx-map1 values _%stx185007%_)))
    (define gx#stx-car
      (lambda (_%stx185004%_)
        (declare (safe))
        (car (gx#syntax-e _%stx185004%_))))
    (define gx#stx-cdr
      (lambda (_%stx185001%_)
        (declare (safe))
        (cdr (gx#syntax-e _%stx185001%_))))
    (define gx#stx-length
      (lambda (_%stx184966%_)
        (let _%lp184968%_ ((_%rest184970%_ _%stx184966%_) (_%n184971%_ '0))
          (let* ((_%$%g184972184980%_ (gx#stx-e _%rest184970%_))
                 (_%$%else184974184988%_ (lambda () _%n184971%_))
                 (_%$%K184976184993%_
                  (lambda (_%rest184991%_)
                    (_%lp184968%_ _%rest184991%_ (##fx+ _%n184971%_ '1)))))
            (if (pair? _%$%g184972184980%_)
                (let* ((_%$%tl184978184996%_ (##cdr _%$%g184972184980%_))
                       (_%rest184999%_ _%$%tl184978184996%_))
                  (_%$%K184976184993%_ _%rest184999%_))
                (_%$%else184974184988%_))))))
    (define gx#stx-for-each
      (lambda _g185495_
        (let ((_g185496_ (##length _g185495_)))
          (cond ((##fx= _g185496_ 2) (apply gx#stx-for-each1 _g185495_))
                ((##fx= _g185496_ 3) (apply gx#stx-for-each2 _g185495_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#stx-for-each
                  _g185495_))))))
    (define gx#stx-for-each1
      (lambda (_%f184909%_ _%stx184910%_)
        (if (procedure? _%f184909%_)
            '#!void
            (error '"expected procedure" _%f184909%_))
        (let _%lp184912%_ ((_%rest184914%_ _%stx184910%_))
          (let* ((_%$%g184915184925%_ (gx#syntax-e _%rest184914%_))
                 (_%$%else184918184933%_
                  (lambda () (_%f184909%_ _%rest184914%_))))
            (let ((_%$%K184921184947%_
                   (lambda (_%rest184944%_ _%hd184945%_)
                     (_%f184909%_ _%hd184945%_)
                     (_%lp184912%_ _%rest184944%_)))
                  (_%$%K184920184938%_ (lambda () '#!void)))
              (let ((_%$%try-match184917184941%_
                     (lambda ()
                       (if (null? _%$%g184915184925%_)
                           (_%$%K184920184938%_)
                           (_%$%else184918184933%_)))))
                (if (pair? _%$%g184915184925%_)
                    (let ((_%$%tl184923184952%_ (##cdr _%$%g184915184925%_))
                          (_%$%hd184922184950%_ (##car _%$%g184915184925%_)))
                      (let ((_%hd184955%_ _%$%hd184922184950%_)
                            (_%rest184957%_ _%$%tl184923184952%_))
                        (_%$%K184921184947%_ _%rest184957%_ _%hd184955%_)))
                    (_%$%try-match184917184941%_))))))))
    (define gx#stx-for-each2
      (lambda (_%f184814%_ _%xstx184815%_ _%ystx184816%_)
        (if (procedure? _%f184814%_)
            '#!void
            (error '"expected procedure" _%f184814%_))
        (let _%lp184818%_ ((_%xrest184820%_ _%xstx184815%_)
                           (_%yrest184821%_ _%ystx184816%_))
          (let* ((_%$%g184822184832%_ (gx#syntax-e _%xrest184820%_))
                 (_%$%else184825184840%_ (lambda () '#!void)))
            (let ((_%$%K184828184897%_
                   (lambda (_%xrest184866%_ _%xhd184867%_)
                     (let* ((_%$%g184868184875%_ (gx#syntax-e _%yrest184821%_))
                            (_%$%E184870184879%_
                             (lambda ()
                               (error '"No clause matching"
                                      _%$%g184868184875%_
                                      '([yhd . yrest]))
                               '#!void))
                            (_%$%K184871184885%_
                             (lambda (_%yrest184882%_ _%yhd184883%_)
                               (_%f184814%_ _%xhd184867%_ _%yhd184883%_)
                               (_%lp184818%_
                                _%xrest184866%_
                                _%yrest184882%_))))
                       (if (pair? _%$%g184868184875%_)
                           (let ((_%$%hd184872184888%_
                                  (##car _%$%g184868184875%_))
                                 (_%$%tl184873184890%_
                                  (##cdr _%$%g184868184875%_)))
                             (let* ((_%yhd184893%_ _%$%hd184872184888%_)
                                    (_%yrest184895%_ _%$%tl184873184890%_))
                               (_%$%K184871184885%_
                                _%yrest184895%_
                                _%yhd184893%_)))
                           (_%$%E184870184879%_)))))
                  (_%$%K184827184860%_
                   (lambda ()
                     (let* ((_%$%yrest184844184849%_ _%yrest184821%_)
                            (_%$%E184846184853%_
                             (lambda ()
                               (error '"No clause matching"
                                      _%$%yrest184844184849%_
                                      '((? (not stx-null?))))
                               '#!void))
                            (_%$%K184847184857%_
                             (lambda ()
                               (_%f184814%_ _%xrest184820%_ _%yrest184821%_))))
                       (if (gx#stx-null? _%$%yrest184844184849%_)
                           (_%$%E184846184853%_)
                           (_%$%K184847184857%_))))))
              (let ((_%$%try-match184824184863%_
                     (lambda ()
                       (if (null? _%$%g184822184832%_)
                           (_%$%else184825184840%_)
                           (_%$%K184827184860%_)))))
                (if (pair? _%$%g184822184832%_)
                    (let ((_%$%tl184830184902%_ (##cdr _%$%g184822184832%_))
                          (_%$%hd184829184900%_ (##car _%$%g184822184832%_)))
                      (let ((_%xhd184905%_ _%$%hd184829184900%_)
                            (_%xrest184907%_ _%$%tl184830184902%_))
                        (_%$%K184828184897%_ _%xrest184907%_ _%xhd184905%_)))
                    (_%$%try-match184824184863%_))))))))
    (define gx#stx-map
      (lambda _g185497_
        (let ((_g185498_ (##length _g185497_)))
          (cond ((##fx= _g185498_ 2) (apply gx#stx-map1 _g185497_))
                ((##fx= _g185498_ 3) (apply gx#stx-map2 _g185497_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#stx-map
                  _g185497_))))))
    (define gx#stx-map1
      (lambda (_%f184757%_ _%stx184758%_)
        (if (procedure? _%f184757%_)
            '#!void
            (error '"expected procedure" _%f184757%_))
        (let _%recur184760%_ ((_%rest184762%_ _%stx184758%_))
          (let* ((_%$%g184763184773%_ (gx#syntax-e _%rest184762%_))
                 (_%$%else184766184781%_
                  (lambda () (_%f184757%_ _%rest184762%_))))
            (let ((_%$%K184769184795%_
                   (lambda (_%rest184792%_ _%hd184793%_)
                     (cons (_%f184757%_ _%hd184793%_)
                           (_%recur184760%_ _%rest184792%_))))
                  (_%$%K184768184786%_ (lambda () '())))
              (let ((_%$%try-match184765184789%_
                     (lambda ()
                       (if (null? _%$%g184763184773%_)
                           (_%$%K184768184786%_)
                           (_%$%else184766184781%_)))))
                (if (pair? _%$%g184763184773%_)
                    (let ((_%$%tl184771184800%_ (##cdr _%$%g184763184773%_))
                          (_%$%hd184770184798%_ (##car _%$%g184763184773%_)))
                      (let ((_%hd184803%_ _%$%hd184770184798%_)
                            (_%rest184805%_ _%$%tl184771184800%_))
                        (_%$%K184769184795%_ _%rest184805%_ _%hd184803%_)))
                    (_%$%try-match184765184789%_))))))))
    (define gx#stx-map2
      (lambda (_%f184662%_ _%xstx184663%_ _%ystx184664%_)
        (if (procedure? _%f184662%_)
            '#!void
            (error '"expected procedure" _%f184662%_))
        (let _%recur184666%_ ((_%xrest184668%_ _%xstx184663%_)
                              (_%yrest184669%_ _%ystx184664%_))
          (let* ((_%$%g184670184680%_ (gx#syntax-e _%xrest184668%_))
                 (_%$%else184673184688%_ (lambda () '())))
            (let ((_%$%K184676184745%_
                   (lambda (_%xrest184714%_ _%xhd184715%_)
                     (let* ((_%$%g184716184723%_ (gx#syntax-e _%yrest184669%_))
                            (_%$%E184718184727%_
                             (lambda ()
                               (error '"No clause matching"
                                      _%$%g184716184723%_
                                      '([yhd . yrest]))
                               '#!void))
                            (_%$%K184719184733%_
                             (lambda (_%yrest184730%_ _%yhd184731%_)
                               (cons (_%f184662%_ _%xhd184715%_ _%yhd184731%_)
                                     (_%recur184666%_
                                      _%xrest184714%_
                                      _%yrest184730%_)))))
                       (if (pair? _%$%g184716184723%_)
                           (let ((_%$%hd184720184736%_
                                  (##car _%$%g184716184723%_))
                                 (_%$%tl184721184738%_
                                  (##cdr _%$%g184716184723%_)))
                             (let* ((_%yhd184741%_ _%$%hd184720184736%_)
                                    (_%yrest184743%_ _%$%tl184721184738%_))
                               (_%$%K184719184733%_
                                _%yrest184743%_
                                _%yhd184741%_)))
                           (_%$%E184718184727%_)))))
                  (_%$%K184675184708%_
                   (lambda ()
                     (let* ((_%$%yrest184692184697%_ _%yrest184669%_)
                            (_%$%E184694184701%_
                             (lambda ()
                               (error '"No clause matching"
                                      _%$%yrest184692184697%_
                                      '((? (not stx-null?))))
                               '#!void))
                            (_%$%K184695184705%_
                             (lambda ()
                               (_%f184662%_ _%xrest184668%_ _%yrest184669%_))))
                       (if (gx#stx-null? _%$%yrest184692184697%_)
                           (_%$%E184694184701%_)
                           (_%$%K184695184705%_))))))
              (let ((_%$%try-match184672184711%_
                     (lambda ()
                       (if (null? _%$%g184670184680%_)
                           (_%$%else184673184688%_)
                           (_%$%K184675184708%_)))))
                (if (pair? _%$%g184670184680%_)
                    (let ((_%$%tl184678184750%_ (##cdr _%$%g184670184680%_))
                          (_%$%hd184677184748%_ (##car _%$%g184670184680%_)))
                      (let ((_%xhd184753%_ _%$%hd184677184748%_)
                            (_%xrest184755%_ _%$%tl184678184750%_))
                        (_%$%K184676184745%_ _%xrest184755%_ _%xhd184753%_)))
                    (_%$%try-match184672184711%_))))))))
    (define gx#stx-andmap
      (lambda (_%f184612%_ _%stx184613%_)
        (if (procedure? _%f184612%_)
            '#!void
            (error '"expected procedure" _%f184612%_))
        (let _%lp184615%_ ((_%rest184617%_ _%stx184613%_))
          (let* ((_%$%g184618184628%_ (gx#syntax-e _%rest184617%_))
                 (_%$%else184621184636%_
                  (lambda () (_%f184612%_ _%rest184617%_))))
            (let ((_%$%K184624184650%_
                   (lambda (_%rest184647%_ _%hd184648%_)
                     (if (_%f184612%_ _%hd184648%_)
                         (_%lp184615%_ _%rest184647%_)
                         '#f)))
                  (_%$%K184623184641%_ (lambda () '#t)))
              (let ((_%$%try-match184620184644%_
                     (lambda ()
                       (if (null? _%$%g184618184628%_)
                           (_%$%K184623184641%_)
                           (_%$%else184621184636%_)))))
                (if (pair? _%$%g184618184628%_)
                    (let ((_%$%tl184626184655%_ (##cdr _%$%g184618184628%_))
                          (_%$%hd184625184653%_ (##car _%$%g184618184628%_)))
                      (let ((_%hd184658%_ _%$%hd184625184653%_)
                            (_%rest184660%_ _%$%tl184626184655%_))
                        (_%$%K184624184650%_ _%rest184660%_ _%hd184658%_)))
                    (_%$%try-match184620184644%_))))))))
    (define gx#stx-ormap
      (lambda (_%f184559%_ _%stx184560%_)
        (if (procedure? _%f184559%_)
            '#!void
            (error '"expected procedure" _%f184559%_))
        (let _%lp184562%_ ((_%rest184564%_ _%stx184560%_))
          (let* ((_%$%g184565184575%_ (gx#syntax-e _%rest184564%_))
                 (_%$%else184568184583%_
                  (lambda () (_%f184559%_ _%rest184564%_))))
            (let ((_%$%K184571184600%_
                   (lambda (_%rest184594%_ _%hd184595%_)
                     (let ((_%$e184597%_ (_%f184559%_ _%hd184595%_)))
                       (if _%$e184597%_
                           _%$e184597%_
                           (_%lp184562%_ _%rest184594%_)))))
                  (_%$%K184570184588%_ (lambda () '#f)))
              (let ((_%$%try-match184567184591%_
                     (lambda ()
                       (if (null? _%$%g184565184575%_)
                           (_%$%K184570184588%_)
                           (_%$%else184568184583%_)))))
                (if (pair? _%$%g184565184575%_)
                    (let ((_%$%tl184573184605%_ (##cdr _%$%g184565184575%_))
                          (_%$%hd184572184603%_ (##car _%$%g184565184575%_)))
                      (let ((_%hd184608%_ _%$%hd184572184603%_)
                            (_%rest184610%_ _%$%tl184573184605%_))
                        (_%$%K184571184600%_ _%rest184610%_ _%hd184608%_)))
                    (_%$%try-match184567184591%_))))))))
    (define gx#stx-foldl
      (lambda (_%f184507%_ _%iv184508%_ _%stx184509%_)
        (if (procedure? _%f184507%_)
            '#!void
            (error '"expected procedure" _%f184507%_))
        (let _%lp184511%_ ((_%r184513%_ _%iv184508%_)
                           (_%rest184514%_ _%stx184509%_))
          (let* ((_%$%g184515184525%_ (gx#syntax-e _%rest184514%_))
                 (_%$%else184518184533%_
                  (lambda () (_%f184507%_ _%rest184514%_ _%r184513%_))))
            (let ((_%$%K184521184547%_
                   (lambda (_%rest184544%_ _%hd184545%_)
                     (_%lp184511%_
                      (_%f184507%_ _%hd184545%_ _%r184513%_)
                      _%rest184544%_)))
                  (_%$%K184520184538%_ (lambda () _%r184513%_)))
              (let ((_%$%try-match184517184541%_
                     (lambda ()
                       (if (null? _%$%g184515184525%_)
                           (_%$%K184520184538%_)
                           (_%$%else184518184533%_)))))
                (if (pair? _%$%g184515184525%_)
                    (let ((_%$%tl184523184552%_ (##cdr _%$%g184515184525%_))
                          (_%$%hd184522184550%_ (##car _%$%g184515184525%_)))
                      (let ((_%hd184555%_ _%$%hd184522184550%_)
                            (_%rest184557%_ _%$%tl184523184552%_))
                        (_%$%K184521184547%_ _%rest184557%_ _%hd184555%_)))
                    (_%$%try-match184517184541%_))))))))
    (define gx#stx-foldr
      (lambda (_%f184456%_ _%iv184457%_ _%stx184458%_)
        (if (procedure? _%f184456%_)
            '#!void
            (error '"expected procedure" _%f184456%_))
        (let _%recur184460%_ ((_%rest184462%_ _%stx184458%_))
          (let* ((_%$%g184463184473%_ (gx#syntax-e _%rest184462%_))
                 (_%$%else184466184481%_
                  (lambda () (_%f184456%_ _%rest184462%_ _%iv184457%_))))
            (let ((_%$%K184469184495%_
                   (lambda (_%rest184492%_ _%hd184493%_)
                     (_%f184456%_
                      _%hd184493%_
                      (_%recur184460%_ _%rest184492%_))))
                  (_%$%K184468184486%_ (lambda () _%iv184457%_)))
              (let ((_%$%try-match184465184489%_
                     (lambda ()
                       (if (null? _%$%g184463184473%_)
                           (_%$%K184468184486%_)
                           (_%$%else184466184481%_)))))
                (if (pair? _%$%g184463184473%_)
                    (let ((_%$%tl184471184500%_ (##cdr _%$%g184463184473%_))
                          (_%$%hd184470184498%_ (##car _%$%g184463184473%_)))
                      (let ((_%hd184503%_ _%$%hd184470184498%_)
                            (_%rest184505%_ _%$%tl184471184500%_))
                        (_%$%K184469184495%_ _%rest184505%_ _%hd184503%_)))
                    (_%$%try-match184465184489%_))))))))
    (define gx#stx-reverse
      (lambda (_%stx184454%_) (gx#stx-foldl cons '() _%stx184454%_)))
    (define gx#stx-last
      (lambda (_%stx184415%_)
        (let _%lp184417%_ ((_%rest184419%_ _%stx184415%_))
          (let* ((_%$%g184420184428%_ (gx#syntax-e _%rest184419%_))
                 (_%$%else184422184436%_ (lambda () _%rest184419%_))
                 (_%$%K184424184442%_
                  (lambda (_%rest184439%_ _%hd184440%_)
                    (if (gx#stx-null? _%rest184439%_)
                        _%hd184440%_
                        (_%lp184417%_ _%rest184439%_)))))
            (if (pair? _%$%g184420184428%_)
                (let ((_%$%hd184425184445%_ (##car _%$%g184420184428%_))
                      (_%$%tl184426184447%_ (##cdr _%$%g184420184428%_)))
                  (let* ((_%hd184450%_ _%$%hd184425184445%_)
                         (_%rest184452%_ _%$%tl184426184447%_))
                    (_%$%K184424184442%_ _%rest184452%_ _%hd184450%_)))
                (_%$%else184422184436%_))))))
    (define gx#stx-last-pair
      (lambda (_%stx184386%_)
        (let _%lp184388%_ ((_%hd184390%_ _%stx184386%_))
          (let* ((_%$%g184391184398%_ (gx#syntax-e _%hd184390%_))
                 (_%$%E184393184402%_
                  (lambda ()
                    (error '"No clause matching"
                           _%$%g184391184398%_
                           '([_ . rest]))
                    '#!void))
                 (_%$%K184394184407%_
                  (lambda (_%rest184405%_)
                    (if (gx#stx-pair? _%rest184405%_)
                        (_%lp184388%_ _%rest184405%_)
                        _%hd184390%_))))
            (if (pair? _%$%g184391184398%_)
                (let* ((_%$%tl184396184410%_ (##cdr _%$%g184391184398%_))
                       (_%rest184413%_ _%$%tl184396184410%_))
                  (_%$%K184394184407%_ _%rest184413%_))
                (_%$%E184393184402%_))))))
    (define gx#stx-list-tail
      (lambda (_%stx184355%_ _%k184356%_)
        (let _%lp184358%_ ((_%rest184360%_ _%stx184355%_)
                           (_%k184361%_ _%k184356%_))
          (if (fxpositive? _%k184361%_)
              (let* ((_%$%g184362184369%_ (gx#syntax-e _%rest184360%_))
                     (_%$%E184364184373%_
                      (lambda ()
                        (error '"No clause matching"
                               _%$%g184362184369%_
                               '([_ . rest]))
                        '#!void))
                     (_%$%K184365184378%_
                      (lambda (_%rest184376%_)
                        (_%lp184358%_ _%rest184376%_ (##fx- _%k184361%_ '1)))))
                (if (pair? _%$%g184362184369%_)
                    (let* ((_%$%tl184367184381%_ (##cdr _%$%g184362184369%_))
                           (_%rest184384%_ _%$%tl184367184381%_))
                      (_%$%K184365184378%_ _%rest184384%_))
                    (_%$%E184364184373%_)))
              _%rest184360%_))))
    (define gx#stx-list-ref
      (lambda (_%stx184352%_ _%k184353%_)
        (gx#stx-car (gx#stx-list-tail _%stx184352%_ _%k184353%_))))
    (define gx#stx-plist?__%
      (lambda (_%stx184264%_ _%key?184265%_)
        (if (procedure? _%key?184265%_)
            '#!void
            (error '"expected procedure" _%key?184265%_))
        (let _%lp184267%_ ((_%rest184269%_ _%stx184264%_))
          (let* ((_%$%g184270184280%_ (gx#stx-e _%rest184269%_))
                 (_%$%else184273184288%_ (lambda () '#f)))
            (let ((_%$%K184276184330%_
                   (lambda (_%rest184299%_ _%hd184300%_)
                     (if (_%key?184265%_ _%hd184300%_)
                         (let* ((_%$%g184301184309%_ (gx#stx-e _%rest184299%_))
                                (_%$%else184303184317%_ (lambda () '#f))
                                (_%$%K184305184322%_
                                 (lambda (_%rest184320%_)
                                   (_%lp184267%_ _%rest184320%_))))
                           (if (pair? _%$%g184301184309%_)
                               (let* ((_%$%tl184307184325%_
                                       (##cdr _%$%g184301184309%_))
                                      (_%rest184328%_ _%$%tl184307184325%_))
                                 (_%lp184267%_ _%rest184328%_))
                               (_%$%else184303184317%_)))
                         '#f)))
                  (_%$%K184275184293%_ (lambda () '#t)))
              (let ((_%$%try-match184272184296%_
                     (lambda ()
                       (if (null? _%$%g184270184280%_)
                           (_%$%K184275184293%_)
                           (_%$%else184273184288%_)))))
                (if (pair? _%$%g184270184280%_)
                    (let ((_%$%tl184278184335%_ (##cdr _%$%g184270184280%_))
                          (_%$%hd184277184333%_ (##car _%$%g184270184280%_)))
                      (let ((_%hd184338%_ _%$%hd184277184333%_)
                            (_%rest184340%_ _%$%tl184278184335%_))
                        (_%$%K184276184330%_ _%rest184340%_ _%hd184338%_)))
                    (_%$%try-match184272184296%_))))))))
    (define gx#stx-plist?__0
      (lambda (_%stx184345%_)
        (let ((_%key?184347%_ gx#stx-keyword?))
          (gx#stx-plist?__% _%stx184345%_ _%key?184347%_))))
    (define gx#stx-plist?
      (lambda _g185499_
        (let ((_g185500_ (##length _g185499_)))
          (cond ((##fx= _g185500_ 1) (apply gx#stx-plist?__0 _g185499_))
                ((##fx= _g185500_ 2) (apply gx#stx-plist?__% _g185499_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#stx-plist?
                  _g185499_))))))
    (define gx#stx-getq__%
      (lambda (_%key184182%_ _%stx184183%_ _%key=?184184%_)
        (if (procedure? _%key=?184184%_)
            '#!void
            (error '"expected procedure" _%key=?184184%_))
        (let _%lp184186%_ ((_%rest184188%_ _%stx184183%_))
          (let* ((_%$%g184189184197%_ (gx#syntax-e _%rest184188%_))
                 (_%$%else184191184205%_ (lambda () '#f))
                 (_%$%K184193184239%_
                  (lambda (_%rest184208%_ _%hd184209%_)
                    (let* ((_%$%g184210184217%_ (gx#syntax-e _%rest184208%_))
                           (_%$%E184212184221%_
                            (lambda ()
                              (error '"No clause matching"
                                     _%$%g184210184217%_
                                     '([val . rest]))
                              '#!void))
                           (_%$%K184213184227%_
                            (lambda (_%rest184224%_ _%val184225%_)
                              (if (_%key=?184184%_ _%hd184209%_ _%key184182%_)
                                  _%val184225%_
                                  (_%lp184186%_ _%rest184224%_)))))
                      (if (pair? _%$%g184210184217%_)
                          (let ((_%$%hd184214184230%_
                                 (##car _%$%g184210184217%_))
                                (_%$%tl184215184232%_
                                 (##cdr _%$%g184210184217%_)))
                            (let* ((_%val184235%_ _%$%hd184214184230%_)
                                   (_%rest184237%_ _%$%tl184215184232%_))
                              (_%$%K184213184227%_
                               _%rest184237%_
                               _%val184235%_)))
                          (_%$%E184212184221%_))))))
            (if (pair? _%$%g184189184197%_)
                (let ((_%$%hd184194184242%_ (##car _%$%g184189184197%_))
                      (_%$%tl184195184244%_ (##cdr _%$%g184189184197%_)))
                  (let* ((_%hd184247%_ _%$%hd184194184242%_)
                         (_%rest184249%_ _%$%tl184195184244%_))
                    (_%$%K184193184239%_ _%rest184249%_ _%hd184247%_)))
                (_%$%else184191184205%_))))))
    (define gx#stx-getq__0
      (lambda (_%key184254%_ _%stx184255%_)
        (let ((_%key=?184257%_ gx#stx-eq?))
          (gx#stx-getq__% _%key184254%_ _%stx184255%_ _%key=?184257%_))))
    (define gx#stx-getq
      (lambda _g185501_
        (let ((_g185502_ (##length _g185501_)))
          (cond ((##fx= _g185502_ 2) (apply gx#stx-getq__0 _g185501_))
                ((##fx= _g185502_ 3) (apply gx#stx-getq__% _g185501_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#stx-getq
                  _g185501_))))))
    (define gx#stx-plist-assq__%
      (lambda (_%key184100%_ _%stx184101%_ _%key=?184102%_)
        (if (procedure? _%key=?184102%_)
            '#!void
            (error '"expected procedure" _%key=?184102%_))
        (let _%lp184104%_ ((_%rest184106%_ _%stx184101%_))
          (let* ((_%$%g184107184115%_ (gx#syntax-e _%rest184106%_))
                 (_%$%else184109184123%_ (lambda () '#f))
                 (_%$%K184111184157%_
                  (lambda (_%rest184126%_ _%hd184127%_)
                    (let* ((_%$%g184128184135%_ (gx#syntax-e _%rest184126%_))
                           (_%$%E184130184139%_
                            (lambda ()
                              (error '"No clause matching"
                                     _%$%g184128184135%_
                                     '([val . rest]))
                              '#!void))
                           (_%$%K184131184145%_
                            (lambda (_%rest184142%_ _%val184143%_)
                              (if (_%key=?184102%_ _%hd184127%_ _%key184100%_)
                                  (cons _%hd184127%_ _%val184143%_)
                                  (_%lp184104%_ _%rest184142%_)))))
                      (if (pair? _%$%g184128184135%_)
                          (let ((_%$%hd184132184148%_
                                 (##car _%$%g184128184135%_))
                                (_%$%tl184133184150%_
                                 (##cdr _%$%g184128184135%_)))
                            (let* ((_%val184153%_ _%$%hd184132184148%_)
                                   (_%rest184155%_ _%$%tl184133184150%_))
                              (_%$%K184131184145%_
                               _%rest184155%_
                               _%val184153%_)))
                          (_%$%E184130184139%_))))))
            (if (pair? _%$%g184107184115%_)
                (let ((_%$%hd184112184160%_ (##car _%$%g184107184115%_))
                      (_%$%tl184113184162%_ (##cdr _%$%g184107184115%_)))
                  (let* ((_%hd184165%_ _%$%hd184112184160%_)
                         (_%rest184167%_ _%$%tl184113184162%_))
                    (_%$%K184111184157%_ _%rest184167%_ _%hd184165%_)))
                (_%$%else184109184123%_))))))
    (define gx#stx-plist-assq__0
      (lambda (_%key184172%_ _%stx184173%_)
        (let ((_%key=?184175%_ gx#stx-eq?))
          (gx#stx-plist-assq__% _%key184172%_ _%stx184173%_ _%key=?184175%_))))
    (define gx#stx-plist-assq
      (lambda _g185503_
        (let ((_g185504_ (##length _g185503_)))
          (cond ((##fx= _g185504_ 2) (apply gx#stx-plist-assq__0 _g185503_))
                ((##fx= _g185504_ 3) (apply gx#stx-plist-assq__% _g185503_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#stx-plist-assq
                  _g185503_))))))))
