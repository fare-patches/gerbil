(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/syntax::timestamp 1795039815)
  (begin
    (declare (not safe))
    (define SyntaxError::t
      (make-class-type
       'SyntaxError::t
       'SyntaxError
       (list Exception::t StackTrace::t)
       '(message irritants where context phi marks)
       (cons (cons 'final: '#t) '())
       '#f))
    (define SyntaxError? (__make-class-predicate SyntaxError::t))
    (define make-SyntaxError
      (lambda _%$args178198%_
        (apply make-instance SyntaxError::t _%$args178198%_)))
    (define SyntaxError-message
      (__make-class-slot-accessor SyntaxError::t 'message))
    (define SyntaxError-irritants
      (__make-class-slot-accessor SyntaxError::t 'irritants))
    (define SyntaxError-where
      (__make-class-slot-accessor SyntaxError::t 'where))
    (define SyntaxError-context
      (__make-class-slot-accessor SyntaxError::t 'context))
    (define SyntaxError-phi (__make-class-slot-accessor SyntaxError::t 'phi))
    (define SyntaxError-marks
      (__make-class-slot-accessor SyntaxError::t 'marks))
    (define SyntaxError-continuation
      (__make-class-slot-accessor SyntaxError::t 'continuation))
    (define SyntaxError-message-set!
      (__make-class-slot-mutator SyntaxError::t 'message))
    (define SyntaxError-irritants-set!
      (__make-class-slot-mutator SyntaxError::t 'irritants))
    (define SyntaxError-where-set!
      (__make-class-slot-mutator SyntaxError::t 'where))
    (define SyntaxError-context-set!
      (__make-class-slot-mutator SyntaxError::t 'context))
    (define SyntaxError-phi-set!
      (__make-class-slot-mutator SyntaxError::t 'phi))
    (define SyntaxError-marks-set!
      (__make-class-slot-mutator SyntaxError::t 'marks))
    (define SyntaxError-continuation-set!
      (__make-class-slot-mutator SyntaxError::t 'continuation))
    (define &SyntaxError-message
      (__make-class-slot-unchecked-accessor SyntaxError::t 'message))
    (define &SyntaxError-irritants
      (__make-class-slot-unchecked-accessor SyntaxError::t 'irritants))
    (define &SyntaxError-where
      (__make-class-slot-unchecked-accessor SyntaxError::t 'where))
    (define &SyntaxError-context
      (__make-class-slot-unchecked-accessor SyntaxError::t 'context))
    (define &SyntaxError-phi
      (__make-class-slot-unchecked-accessor SyntaxError::t 'phi))
    (define &SyntaxError-marks
      (__make-class-slot-unchecked-accessor SyntaxError::t 'marks))
    (define &SyntaxError-continuation
      (__make-class-slot-unchecked-accessor SyntaxError::t 'continuation))
    (define &SyntaxError-message-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'message))
    (define &SyntaxError-irritants-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'irritants))
    (define &SyntaxError-where-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'where))
    (define &SyntaxError-context-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'context))
    (define &SyntaxError-phi-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'phi))
    (define &SyntaxError-marks-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'marks))
    (define &SyntaxError-continuation-set!
      (__make-class-slot-unchecked-mutator SyntaxError::t 'continuation))
    (define SyntaxError::display-exception
      (lambda (_%self177917%_ _%port177918%_)
        (let ((_%self177921%_ _%self177917%_))
          (letrec ((_%location177932%_
                    (lambda ()
                      (letrec ((_%from-irritants178073%_
                                (lambda ()
                                  (let _%lp178158%_ ((_%rest178160%_
                                                      (##unchecked-structure-ref
                                                       _%self177921%_
                                                       '3
                                                       '#f
                                                       '#f)))
                                    (let* ((_%$%rest178161178169%_
                                            _%rest178160%_)
                                           (_%$%else178163178177%_
                                            (lambda () '#f))
                                           (_%$%K178165178186%_
                                            (lambda (_%rest178180%_
                                                     _%hd178181%_)
                                              (let ((_%$e178183%_
                                                     (__AST-source
                                                      _%hd178181%_)))
                                                (if _%$e178183%_
                                                    _%$e178183%_
                                                    (_%lp178158%_
                                                     _%rest178180%_))))))
                                      (if (pair? _%$%rest178161178169%_)
                                          (let ((_%$%hd178166178189%_
                                                 (##car _%$%rest178161178169%_))
                                                (_%$%tl178167178191%_
                                                 (##cdr _%$%rest178161178169%_)))
                                            (let* ((_%hd178194%_
                                                    _%$%hd178166178189%_)
                                                   (_%rest178196%_
                                                    _%$%tl178167178191%_))
                                              (_%$%K178165178186%_
                                               _%rest178196%_
                                               _%hd178194%_)))
                                          (_%$%else178163178177%_))))))
                               (_%from-context178074%_
                                (lambda ()
                                  (let _%lp178080%_ ((_%rest178082%_
                                                      (##unchecked-structure-ref
                                                       _%self177921%_
                                                       '4
                                                       '#f
                                                       '#f)))
                                    (let* ((_%$%rest178083178091%_
                                            _%rest178082%_)
                                           (_%$%else178085178099%_
                                            (lambda () '#f))
                                           (_%$%K178087178145%_
                                            (lambda (_%rest178102%_
                                                     _%hd178103%_)
                                              (let* ((_%$%hd178104178114%_
                                                      _%hd178103%_)
                                                     (_%$%else178106178122%_
                                                      (lambda ()
                                                        (_%lp178080%_
                                                         _%rest178102%_)))
                                                     (_%$%K178108178130%_
                                                      (lambda (_%loc178125%_)
                                                        (let ((_%$e178127%_
                                                               (__AST-source
                                                                _%loc178125%_)))
                                                          (if _%$e178127%_
                                                              _%$e178127%_
                                                              (_%lp178080%_
                                                               _%rest178102%_))))))
                                                (if (pair? _%$%hd178104178114%_)
                                                    (let ((_%$%hd178109178133%_
                                                           (##car _%$%hd178104178114%_))
                                                          (_%$%tl178110178135%_
                                                           (##cdr _%$%hd178104178114%_)))
                                                      (if (##eq? _%$%hd178109178133%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '@)
                  (if (pair? _%$%tl178110178135%_)
                      (let ((_%$%hd178111178138%_ (##car _%$%tl178110178135%_))
                            (_%$%tl178112178140%_
                             (##cdr _%$%tl178110178135%_)))
                        (let ((_%loc178143%_ _%$%hd178111178138%_))
                          (if (null? _%$%tl178112178140%_)
                              (_%$%K178108178130%_ _%loc178143%_)
                              (_%$%else178106178122%_))))
                      (_%$%else178106178122%_))
                  (_%$%else178106178122%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%else178106178122%_))))))
                                      (if (pair? _%$%rest178083178091%_)
                                          (let ((_%$%hd178088178148%_
                                                 (##car _%$%rest178083178091%_))
                                                (_%$%tl178089178150%_
                                                 (##cdr _%$%rest178083178091%_)))
                                            (let* ((_%hd178153%_
                                                    _%$%hd178088178148%_)
                                                   (_%rest178155%_
                                                    _%$%tl178089178150%_))
                                              (_%$%K178087178145%_
                                               _%rest178155%_
                                               _%hd178153%_)))
                                          (_%$%else178085178099%_)))))))
                        (let ((_%$e178076%_ (_%from-irritants178073%_)))
                          (if _%$e178076%_
                              _%$e178076%_
                              (_%from-context178074%_)))))))
            (call-with-parameters__1
             (lambda ()
               (newline)
               (display '"*** ERROR IN ")
               (let ((_%$e177935%_ (_%location177932%_)))
                 (if _%$e177935%_
                     (##display-locat _%$e177935%_ '#t _%port177918%_)
                     (display '"?")))
               (newline)
               (displayln
                '"--- Syntax Error: "
                (##unchecked-structure-ref _%self177921%_ '2 '#f '#f))
               (let ((_%$e177941%_
                      (##unchecked-structure-ref _%self177921%_ '4 '#f '#f)))
                 (if _%$e177941%_
                     (let ()
                       (displayln '"--- Context: ")
                       (let _%lp177946%_ ((_%rest177948%_ _%$e177941%_))
                         (let* ((_%$%rest177949177957%_ _%rest177948%_)
                                (_%$%else177951177965%_ (lambda () '#!void))
                                (_%$%K177953178015%_
                                 (lambda (_%rest177968%_ _%hd177969%_)
                                   (let* ((_%$%hd177970177980%_ _%hd177969%_)
                                          (_%$%else177972177988%_
                                           (lambda ()
                                             (displayln '" at " _%hd177969%_)
                                             (_%lp177946%_ _%rest177968%_)))
                                          (_%$%K177974178000%_
                                           (lambda (_%ctx177991%_)
                                             (let ((_%$e177993%_
                                                    (__AST-source
                                                     _%ctx177991%_)))
                                               (if _%$e177993%_
                                                   (let ()
                                                     (display '" at ")
                                                     (##display-locat
                                                      _%$e177993%_
                                                      '#t
                                                      _%port177918%_)
                                                     (newline)
                                                     (_%lp177946%_
                                                      _%rest177968%_))
                                                   (if (##structure-instance-of?
                                                        _%ctx177991%_
                                                        'gerbil#AST::t)
                                                       (let ()
                                                         (display '" at ")
                                                         (__pp-syntax
                                                          _%ctx177991%_)
                                                         (_%lp177946%_
                                                          _%rest177968%_))
                                                       (_%lp177946%_
                                                        _%rest177968%_)))))))
                                     (if (pair? _%$%hd177970177980%_)
                                         (let ((_%$%hd177975178003%_
                                                (##car _%$%hd177970177980%_))
                                               (_%$%tl177976178005%_
                                                (##cdr _%$%hd177970177980%_)))
                                           (if (##eq? _%$%hd177975178003%_ '@)
                                               (if (pair? _%$%tl177976178005%_)
                                                   (let ((_%$%hd177977178008%_
                                                          (##car _%$%tl177976178005%_))
                                                         (_%$%tl177978178010%_
                                                          (##cdr _%$%tl177976178005%_)))
                                                     (let ((_%ctx178013%_
                                                            _%$%hd177977178008%_))
                                                       (if (null? _%$%tl177978178010%_)
                                                           (_%$%K177974178000%_
                                                            _%ctx178013%_)
                                                           (_%$%else177972177988%_))))
                                                   (_%$%else177972177988%_))
                                               (_%$%else177972177988%_)))
                                         (_%$%else177972177988%_))))))
                           (if (pair? _%$%rest177949177957%_)
                               (let ((_%$%hd177954178018%_
                                      (##car _%$%rest177949177957%_))
                                     (_%$%tl177955178020%_
                                      (##cdr _%$%rest177949177957%_)))
                                 (let* ((_%hd178023%_ _%$%hd177954178018%_)
                                        (_%rest178025%_ _%$%tl177955178020%_))
                                   (_%$%K177953178015%_
                                    _%rest178025%_
                                    _%hd178023%_)))
                               '#!void))))
                     '#!void))
               (let* ((_%$%self.irritants178026178034%_
                       (##unchecked-structure-ref _%self177921%_ '3 '#f '#f))
                      (_%$%else178028178042%_ (lambda () '#!void))
                      (_%$%K178030178055%_
                       (lambda (_%rest178045%_ _%stx178046%_)
                         (display '"... form:   ")
                         (__pp-syntax _%stx178046%_)
                         (for-each
                          (lambda (_%detail178048%_)
                            (display '"... detail: ")
                            (##write (__AST->datum _%detail178048%_))
                            (let ((_%$e178050%_
                                   (__AST-source _%detail178048%_)))
                              (if _%$e178050%_
                                  (let ()
                                    (display '" at ")
                                    (##display-locat
                                     _%$e178050%_
                                     '#t
                                     _%port177918%_))
                                  '#!void))
                            (newline))
                          _%rest178045%_))))
                 (if (pair? _%$%self.irritants178026178034%_)
                     (let ((_%$%hd178031178058%_
                            (##car _%$%self.irritants178026178034%_))
                           (_%$%tl178032178060%_
                            (##cdr _%$%self.irritants178026178034%_)))
                       (let* ((_%stx178063%_ _%$%hd178031178058%_)
                              (_%rest178065%_ _%$%tl178032178060%_))
                         (_%$%K178030178055%_ _%rest178065%_ _%stx178063%_)))
                     '#!void))
               (if __DEBUG
                   (let ((_%$%cont178066178068%_
                          (##unchecked-structure-ref
                           _%self177921%_
                           '1
                           '#f
                           '#f)))
                     (if _%$%cont178066178068%_
                         (let ((_%cont178070%_ _%$%cont178066178068%_))
                           (display '"--- continuation backtrace:")
                           (newline)
                           (display-continuation-backtrace _%cont178070%_))
                         '#f))
                   '#!void))
             current-output-port
             _%port177918%_)))))
    (__bind-method!__%
     SyntaxError::t
     'display-exception
     SyntaxError::display-exception
     '#f)
    (let* ((_%klass177780%_ SyntaxError::t) (_%klass177785%_ _%klass177780%_))
      (__seal-class! _%klass177785%_))
    (define make-syntax-error
      (lambda (_%message177773%_
               _%irritants177774%_
               _%where177775%_
               _%context177776%_
               _%marks177777%_
               _%phi177778%_)
        (let ((__obj178295
               (##structure SyntaxError::t '#f '#f '#f '#f '#f '#f '#f)))
          (##unchecked-structure-set! __obj178295 _%message177773%_ '2 '#f '#f)
          (##unchecked-structure-set!
           __obj178295
           _%irritants177774%_
           '3
           '#f
           '#f)
          (##unchecked-structure-set! __obj178295 _%where177775%_ '4 '#f '#f)
          (##unchecked-structure-set! __obj178295 _%context177776%_ '5 '#f '#f)
          (##unchecked-structure-set! __obj178295 _%marks177777%_ '7 '#f '#f)
          (##unchecked-structure-set! __obj178295 _%phi177778%_ '6 '#f '#f)
          __obj178295)))
    (define syntax-error? SyntaxError?)
    (define __raise-syntax-error
      (lambda (_%where177768%_
               _%message177769%_
               _%stx177770%_
               .
               _%details177771%_)
        (raise (make-syntax-error
                _%message177769%_
                (cons _%stx177770%_ _%details177771%_)
                _%where177768%_
                '#f
                '#f
                '#f))))
    (define AST::t
      (make-class-type
       'gerbil#AST::t
       'syntax
       (list)
       '(e source)
       (cons (cons 'struct: '#t) '((print: e)))
       '#f))
    (define AST? (__make-class-predicate AST::t))
    (define make-AST
      (lambda _%$args177765%_ (apply make-instance AST::t _%$args177765%_)))
    (define AST-e (__make-class-slot-accessor AST::t 'e))
    (define AST-source (__make-class-slot-accessor AST::t 'source))
    (define AST-e-set! (__make-class-slot-mutator AST::t 'e))
    (define AST-source-set! (__make-class-slot-mutator AST::t 'source))
    (define &AST-e (__make-class-slot-unchecked-accessor AST::t 'e))
    (define &AST-source (__make-class-slot-unchecked-accessor AST::t 'source))
    (define &AST-e-set! (__make-class-slot-unchecked-mutator AST::t 'e))
    (define &AST-source-set!
      (__make-class-slot-unchecked-mutator AST::t 'source))
    (define __AST-e
      (lambda (_%stx177763%_)
        (if (##structure-instance-of? _%stx177763%_ 'gerbil#AST::t)
            (##unchecked-structure-ref _%stx177763%_ '1 '#f '#f)
            _%stx177763%_)))
    (define __AST-source
      (lambda (_%stx177754%_)
        (let _%lp177756%_ ((_%src177758%_ _%stx177754%_))
          (if (##structure-instance-of? _%src177758%_ 'gerbil#AST::t)
              (_%lp177756%_
               (##unchecked-structure-ref _%src177758%_ '2 '#f '#f))
              (if (##locat? _%src177758%_) _%src177758%_ '#f)))))
    (define __AST
      (lambda (_%e177746%_ _%src-stx177747%_)
        (let ((_%src177749%_ (__AST-source _%src-stx177747%_)))
          (if (or (##structure-instance-of? _%e177746%_ 'gerbil#AST::t)
                  (not _%src177749%_))
              _%e177746%_
              (##structure AST::t _%e177746%_ _%src177749%_)))))
    (define __AST-eq?
      (lambda (_%stx177743%_ _%obj177744%_)
        (eq? (__AST-e _%stx177743%_) _%obj177744%_)))
    (define __AST-pair?
      (lambda (_%stx177741%_) (pair? (__AST-e _%stx177741%_))))
    (define __AST-null?
      (lambda (_%stx177739%_) (null? (__AST-e _%stx177739%_))))
    (define __AST-datum?
      (lambda (_%stx177720%_)
        (let* ((_%e177722%_ (__AST-e _%stx177720%_))
               (_%$e177724%_ (number? _%e177722%_)))
          (if _%$e177724%_
              _%$e177724%_
              (let ((_%$e177727%_ (string? _%e177722%_)))
                (if _%$e177727%_
                    _%$e177727%_
                    (let ((_%$e177730%_ (char? _%e177722%_)))
                      (if _%$e177730%_
                          _%$e177730%_
                          (let ((_%$e177733%_ (keyword? _%e177722%_)))
                            (if _%$e177733%_
                                _%$e177733%_
                                (let ((_%$e177736%_ (boolean? _%e177722%_)))
                                  (if _%$e177736%_
                                      _%$e177736%_
                                      (eq? _%e177722%_ '#!void)))))))))))))
    (define __AST-id?
      (lambda (_%stx177718%_) (symbol? (__AST-e _%stx177718%_))))
    (define __AST-id-list?__%
      (lambda (_%stx177669%_ _%tail?177670%_)
        (let _%lp177672%_ ((_%rest177674%_ _%stx177669%_))
          (let* ((_%$e177676%_ _%rest177674%_)
                 (_%$%$E177678177691%_
                  (lambda ()
                    (let* ((_%$%$E177679177686%_
                            (lambda ()
                              (__raise-syntax-error
                               '#f
                               '"Bad syntax; malformed ast clause"
                               _%$e177676%_)))
                           (_%rest177689%_ _%$e177676%_))
                      (_%tail?177670%_ _%rest177689%_)))))
            (if (__AST-pair? _%$e177676%_)
                (let* ((_%$%$tgt177680177694%_ (__AST-e _%$e177676%_))
                       (_%$%$hd177681177697%_ (##car _%$%$tgt177680177694%_))
                       (_%$%$tl177682177700%_ (##cdr _%$%$tgt177680177694%_))
                       (_%hd177704%_ _%$%$hd177681177697%_)
                       (_%rest177706%_ _%$%$tl177682177700%_))
                  (if (__AST-id? _%hd177704%_)
                      (_%lp177672%_ _%rest177706%_)
                      '#f))
                (_%$%$E177678177691%_))))))
    (define __AST-id-list?__0
      (lambda (_%stx177711%_)
        (let ((_%tail?177713%_ __AST-null?))
          (__AST-id-list?__% _%stx177711%_ _%tail?177713%_))))
    (define __AST-id-list?
      (lambda _g178297_
        (let ((_g178298_ (##length _g178297_)))
          (cond ((##fx= _g178298_ 1) (apply __AST-id-list?__0 _g178297_))
                ((##fx= _g178298_ 2) (apply __AST-id-list?__% _g178297_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __AST-id-list?
                  _g178297_))))))
    (define __AST-bind-list?
      (lambda (_%stx177661%_)
        (__AST-id-list?__%
         _%stx177661%_
         (lambda (_%e177663%_)
           (let ((_%$e177665%_ (__AST-null? _%e177663%_)))
             (if _%$e177665%_ _%$e177665%_ (__AST-id? _%e177663%_)))))))
    (define __AST-list?__%
      (lambda (_%stx177614%_ _%tail?177615%_)
        (let _%lp177617%_ ((_%rest177619%_ _%stx177614%_))
          (let* ((_%$e177621%_ _%rest177619%_)
                 (_%$%$E177623177636%_
                  (lambda ()
                    (let* ((_%$%$E177624177631%_
                            (lambda ()
                              (__raise-syntax-error
                               '#f
                               '"Bad syntax; malformed ast clause"
                               _%$e177621%_)))
                           (_%rest177634%_ _%$e177621%_))
                      (_%tail?177615%_ _%rest177634%_)))))
            (if (__AST-pair? _%$e177621%_)
                (let* ((_%$%$tgt177625177639%_ (__AST-e _%$e177621%_))
                       (_%$%$hd177626177642%_ (##car _%$%$tgt177625177639%_))
                       (_%$%$tl177627177645%_ (##cdr _%$%$tgt177625177639%_))
                       (_%rest177649%_ _%$%$tl177627177645%_))
                  (_%lp177617%_ _%rest177649%_))
                (_%$%$E177623177636%_))))))
    (define __AST-list?__0
      (lambda (_%stx177654%_)
        (let ((_%tail?177656%_ __AST-null?))
          (__AST-list?__% _%stx177654%_ _%tail?177656%_))))
    (define __AST-list?
      (lambda _g178299_
        (let ((_g178300_ (##length _g178299_)))
          (cond ((##fx= _g178300_ 1) (apply __AST-list?__0 _g178299_))
                ((##fx= _g178300_ 2) (apply __AST-list?__% _g178299_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __AST-list?
                  _g178299_))))))
    (define __AST->list
      (lambda (_%stx177579%_)
        (let* ((_%$e177581%_ _%stx177579%_)
               (_%$%$E177583177596%_
                (lambda ()
                  (let* ((_%$%$E177584177591%_
                          (lambda ()
                            (__raise-syntax-error
                             '#f
                             '"Bad syntax; malformed ast clause"
                             _%$e177581%_)))
                         (_%rest177594%_ _%$e177581%_))
                    (__AST-e _%rest177594%_)))))
          (if (__AST-pair? _%$e177581%_)
              (let* ((_%$%$tgt177585177599%_ (__AST-e _%$e177581%_))
                     (_%$%$hd177586177602%_ (##car _%$%$tgt177585177599%_))
                     (_%$%$tl177587177605%_ (##cdr _%$%$tgt177585177599%_))
                     (_%hd177609%_ _%$%$hd177586177602%_)
                     (_%rest177611%_ _%$%$tl177587177605%_))
                (cons _%hd177609%_ (__AST->list _%rest177611%_)))
              (_%$%$E177583177596%_)))))
    (define __AST->datum
      (lambda (_%stx177572%_)
        (if (##structure-instance-of? _%stx177572%_ 'gerbil#AST::t)
            (__AST->datum (__AST-e _%stx177572%_))
            (if (pair? _%stx177572%_)
                (cons (__AST->datum (##car _%stx177572%_))
                      (__AST->datum (##cdr _%stx177572%_)))
                (if (vector? _%stx177572%_)
                    (vector-map __AST->datum _%stx177572%_)
                    (if (box? _%stx177572%_)
                        (box (__AST->datum (unbox _%stx177572%_)))
                        _%stx177572%_))))))
    (define get-readenv
      (lambda (_%port177570%_)
        (##make-readenv
         _%port177570%_
         (current-readtable)
         __wrap-syntax
         __unwrap-syntax
         '#f
         '()
         '#f)))
    (define read-syntax__%
      (lambda (_%in177558%_)
        (let ((_%e177560%_ (##read-datum-or-eof (get-readenv _%in177558%_))))
          (if (eof-object? (__AST-e _%e177560%_))
              (__AST-e _%e177560%_)
              _%e177560%_))))
    (define read-syntax__0
      (lambda ()
        (let ((_%in177566%_ (current-input-port)))
          (read-syntax__% _%in177566%_))))
    (define read-syntax
      (lambda _g178301_
        (let ((_g178302_ (##length _g178301_)))
          (cond ((##fx= _g178302_ 0) (apply read-syntax__0 _g178301_))
                ((##fx= _g178302_ 1) (apply read-syntax__% _g178301_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  read-syntax
                  _g178301_))))))
    (define read-syntax-from-file
      (lambda (_%path177553%_)
        (let ((_%r177555%_
               (##read-all-as-a-begin-expr-from-path
                (path-normalize _%path177553%_)
                (current-readtable)
                __wrap-syntax
                __unwrap-syntax)))
          (if (vector? _%r177555%_)
              (cdr (__AST-e (vector-ref _%r177555%_ '1)))
              (error (err-code->string _%r177555%_) _%path177553%_)))))
    (define __wrap-syntax
      (lambda (_%re177550%_ _%e177551%_)
        (if (eof-object? _%e177551%_)
            _%e177551%_
            (##structure AST::t _%e177551%_ (##readenv->locat _%re177550%_)))))
    (define __unwrap-syntax
      (lambda (_%re177547%_ _%e177548%_) (__AST-e _%e177548%_)))
    (define __pp-syntax
      (lambda (_%stx177545%_) (pp (__AST->datum _%stx177545%_))))
    (define __make-readtable
      (lambda ()
        (let ((_%rt177543%_ (##make-standard-readtable)))
          (macro-readtable-write-extended-read-macros?-set! _%rt177543%_ '#t)
          (macro-readtable-bracket-handler-set! _%rt177543%_ '@list)
          (macro-readtable-brace-handler-set! _%rt177543%_ '@method)
          (##readtable-char-sharp-handler-set!
           _%rt177543%_
           '#\!
           __read-sharp-bang)
          _%rt177543%_)))
    (define __readtable-bracket-keyword-set!
      (lambda (_%rt177539%_ _%kw177540%_)
        (macro-readtable-bracket-handler-set! _%rt177539%_ _%kw177540%_)))
    (define __readtable-brace-keyword-set!
      (lambda (_%rt177536%_ _%kw177537%_)
        (macro-readtable-brace-handler-set! _%rt177536%_ _%kw177537%_)))
    (define __read-sharp-bang
      (lambda (_%re177527%_ _%next177528%_ _%start-pos177529%_)
        (if (eq? _%start-pos177529%_ '0)
            (let* ((_%line177531%_
                    (##read-line
                     (macro-readenv-port _%re177527%_)
                     '#\newline
                     '#f
                     (##greatest-fixnum)))
                   (_%script-line177533%_
                    (substring
                     _%line177531%_
                     '1
                     (string-length _%line177531%_))))
              (macro-readenv-script-line-set!
               _%re177527%_
               _%script-line177533%_)
              (##script-marker))
            (##read-sharp-bang
             _%re177527%_
             _%next177528%_
             _%start-pos177529%_))))
    (set! ##readtable-setup-for-language! void)
    (define __*readtable* (__make-readtable))
    (define source-location? ##locat?)
    (define source-location-path?
      (lambda (_%obj177525%_)
        (if (source-location? _%obj177525%_)
            (string? (##locat-container _%obj177525%_))
            '#f)))
    (define source-location-path
      (lambda (_%obj177523%_)
        (if (##locat? _%obj177523%_)
            (##container->path (##locat-container _%obj177523%_))
            '#f)))))
