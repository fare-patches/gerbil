(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/error::timestamp 1795039814)
  (begin
    (define Exception::t
      (let ((__tmp151762 (list)))
        (declare (not safe))
        (make-class-type 'Exception::t 'Exception __tmp151762 '() '() '#f)))
    (define Exception?
      (let () (declare (not safe)) (__make-class-predicate Exception::t)))
    (define make-Exception
      (lambda _%$args151680%_
        (apply make-instance Exception::t _%$args151680%_)))
    (define StackTrace::t
      (let ((__tmp151763 (list)))
        (declare (not safe))
        (make-class-type
         'StackTrace::t
         'StackTrace
         __tmp151763
         '(continuation)
         '((transparent: . #t))
         '#f)))
    (define StackTrace?
      (let () (declare (not safe)) (__make-class-predicate StackTrace::t)))
    (define make-StackTrace
      (lambda _%$args151677%_
        (apply make-instance StackTrace::t _%$args151677%_)))
    (define StackTrace-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor StackTrace::t 'continuation)))
    (define StackTrace-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator StackTrace::t 'continuation)))
    (define &StackTrace-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor StackTrace::t 'continuation)))
    (define &StackTrace-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator StackTrace::t 'continuation)))
    (define Error::t
      (let ((__tmp151764 (list StackTrace::t Exception::t)))
        (declare (not safe))
        (make-class-type
         'Error::t
         'Error
         __tmp151764
         '(message irritants where)
         '((transparent: . #t))
         ':init!)))
    (define Error?
      (let () (declare (not safe)) (__make-class-predicate Error::t)))
    (define make-Error
      (lambda _%$args151674%_ (apply make-instance Error::t _%$args151674%_)))
    (define Error-message
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor Error::t 'message)))
    (define Error-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor Error::t 'irritants)))
    (define Error-where
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor Error::t 'where)))
    (define Error-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor Error::t 'continuation)))
    (define Error-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator Error::t 'message)))
    (define Error-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator Error::t 'irritants)))
    (define Error-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator Error::t 'where)))
    (define Error-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator Error::t 'continuation)))
    (define &Error-message
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor Error::t 'message)))
    (define &Error-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor Error::t 'irritants)))
    (define &Error-where
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor Error::t 'where)))
    (define &Error-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor Error::t 'continuation)))
    (define &Error-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator Error::t 'message)))
    (define &Error-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator Error::t 'irritants)))
    (define &Error-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator Error::t 'where)))
    (define &Error-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator Error::t 'continuation)))
    (define ContractViolation::t
      (let ((__tmp151765 (list Error::t)))
        (declare (not safe))
        (make-class-type
         'ContractViolation::t
         'ContractViolation
         __tmp151765
         '()
         '()
         ':init!)))
    (define ContractViolation?
      (let ()
        (declare (not safe))
        (__make-class-predicate ContractViolation::t)))
    (define make-ContractViolation
      (lambda _%$args151671%_
        (apply make-instance ContractViolation::t _%$args151671%_)))
    (define ContractViolation-message
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor ContractViolation::t 'message)))
    (define ContractViolation-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor ContractViolation::t 'irritants)))
    (define ContractViolation-where
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor ContractViolation::t 'where)))
    (define ContractViolation-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor ContractViolation::t 'continuation)))
    (define ContractViolation-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator ContractViolation::t 'message)))
    (define ContractViolation-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator ContractViolation::t 'irritants)))
    (define ContractViolation-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator ContractViolation::t 'where)))
    (define ContractViolation-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator ContractViolation::t 'continuation)))
    (define &ContractViolation-message
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor ContractViolation::t 'message)))
    (define &ContractViolation-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         ContractViolation::t
         'irritants)))
    (define &ContractViolation-where
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor ContractViolation::t 'where)))
    (define &ContractViolation-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         ContractViolation::t
         'continuation)))
    (define &ContractViolation-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator ContractViolation::t 'message)))
    (define &ContractViolation-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator ContractViolation::t 'irritants)))
    (define &ContractViolation-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator ContractViolation::t 'where)))
    (define &ContractViolation-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         ContractViolation::t
         'continuation)))
    (define RuntimeException::t
      (let ((__tmp151766 (list StackTrace::t Exception::t)))
        (declare (not safe))
        (make-class-type
         'RuntimeException::t
         'RuntimeException
         __tmp151766
         '(exception)
         '((transparent: . #t))
         '#f)))
    (define RuntimeException?
      (let ()
        (declare (not safe))
        (__make-class-predicate RuntimeException::t)))
    (define make-RuntimeException
      (lambda _%$args151668%_
        (apply make-instance RuntimeException::t _%$args151668%_)))
    (define RuntimeException-exception
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor RuntimeException::t 'exception)))
    (define RuntimeException-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor RuntimeException::t 'continuation)))
    (define RuntimeException-exception-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator RuntimeException::t 'exception)))
    (define RuntimeException-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator RuntimeException::t 'continuation)))
    (define &RuntimeException-exception
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor RuntimeException::t 'exception)))
    (define &RuntimeException-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         RuntimeException::t
         'continuation)))
    (define &RuntimeException-exception-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator RuntimeException::t 'exception)))
    (define &RuntimeException-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         RuntimeException::t
         'continuation)))
    (define gerbil-exception-handler-hook
      (lambda (_%exn151663%_ _%continue151664%_)
        (let ((_%exn151666%_ (wrap-runtime-exception _%exn151663%_)))
          (declare (not safe))
          (##repl-exception-handler-hook _%exn151666%_ _%continue151664%_))))
    (let ()
      (declare (not safe))
      (##primordial-exception-handler-hook-set! gerbil-exception-handler-hook))
    (define raise
      (lambda (_%exn151659%_)
        (if (let ()
              (declare (not safe))
              (class-instance? StackTrace::t _%exn151659%_))
            (if (let ()
                  (declare (not safe))
                  (unchecked-slot-ref _%exn151659%_ 'continuation))
                '#!void
                (let ((__tmp151767
                       (lambda (_%cont151661%_)
                         (let ()
                           (declare (not safe))
                           (unchecked-slot-set!
                            _%exn151659%_
                            'continuation
                            _%cont151661%_)))))
                  (declare (not safe))
                  (##continuation-capture __tmp151767)))
            '#!void)
        (let () (declare (not safe)) (##raise _%exn151659%_))))
    (define error
      (lambda (_%message151656%_ . _%irritants151657%_)
        (raise (let ((__obj151759
                      (let ()
                        (declare (not safe))
                        (##structure Error::t '#f '#f '#f '#f))))
                 (Error:::init!
                  __obj151759
                  _%message151656%_
                  'irritants:
                  _%irritants151657%_)
                 __obj151759))))
    (define __raise-contract-violation-error__%
      (lambda (_%@@keywords151631%_
               _%$%ctx151626151632%_
               _%$%contract-expr151627151633%_
               _%$%value151628151634%_
               _%message151635%_)
        (let* ((_%ctx151637%_
                (if (eq? _%$%ctx151626151632%_ absent-value)
                    '#f
                    _%$%ctx151626151632%_))
               (_%contract-expr151639%_
                (if (eq? _%$%contract-expr151627151633%_ absent-value)
                    '#f
                    _%$%contract-expr151627151633%_))
               (_%value151641%_
                (if (eq? _%$%value151628151634%_ absent-value)
                    '#f
                    _%$%value151628151634%_)))
          (raise (let ((__obj151760
                        (let ()
                          (declare (not safe))
                          (##structure ContractViolation::t '#f '#f '#f '#f))))
                   (ContractViolation:::init!
                    __obj151760
                    _%message151635%_
                    'where:
                    _%ctx151637%_
                    'irritants:
                    (cons 'contract:
                          (cons _%contract-expr151639%_
                                (cons 'value: (cons _%value151641%_ '())))))
                   __obj151760)))))
    (define __raise-contract-violation-error__@
      (lambda (_%@@keywords151646%_ . _%args151647%_)
        (apply __raise-contract-violation-error__%
               _%@@keywords151646%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords151646%_
                  'context:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords151646%_
                  'contract:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords151646%_
                  'value:
                  absent-value))
               _%args151647%_)))
    (define __raise-contract-violation-error
      (lambda _%$%args151629151653%_
        (apply keyword-dispatch
               '#(context: #f value: contract:)
               __raise-contract-violation-error__@
               _%$%args151629151653%_)))
    (set! raise-contract-violation-error __raise-contract-violation-error)
    (define contract-violation-error? ContractViolation?)
    (define __with-exception-handler
      (lambda (_%handler151600%_ _%thunk151601%_)
        (let* ((_%handler151604%_ _%handler151600%_)
               (_%thunk151612%_ _%thunk151601%_)
               (__tmp151768
                (lambda (_%exn151621%_)
                  (let ((_%exn151623%_ (wrap-runtime-exception _%exn151621%_)))
                    (declare (not safe))
                    (_%handler151604%_ _%exn151623%_)))))
          (declare (not safe))
          (##with-exception-handler __tmp151768 _%thunk151612%_))))
    (define with-exception-handler
      (lambda (_%handler151575%_ _%thunk151576%_)
        (if (procedure? _%handler151575%_)
            (let ((_%handler151580%_ _%handler151575%_))
              (if (procedure? _%thunk151576%_)
                  (let ((_%thunk151590%_ _%thunk151576%_))
                    (__with-exception-handler
                     _%handler151580%_
                     _%thunk151590%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/error.ss\"@60.54-60.59"
                     'contract:
                     'procedure?
                     'value:
                     _%thunk151576%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/error.ss\"@60.31-60.38"
               'contract:
               'procedure?
               'value:
               _%handler151575%_)
              '#!void))))
    (define __with-catch
      (lambda (_%handler151517%_ _%thunk151518%_)
        (let* ((_%handler151521%_ _%handler151517%_)
               (_%thunk151529%_ _%thunk151518%_)
               (__tmp151769
                (lambda (_%cont151538%_)
                  (let* ((_%handler151542%_
                          (lambda (_%exn151540%_)
                            (let ()
                              (declare (not safe))
                              (##continuation-graft
                               _%cont151538%_
                               _%handler151521%_
                               _%exn151540%_))))
                         (_%thunk151545%_ _%thunk151529%_)
                         (_%handler151550%_ _%handler151542%_)
                         (_%thunk151565%_ _%thunk151545%_))
                    (__with-exception-handler
                     _%handler151550%_
                     _%thunk151565%_)))))
          (declare (not safe))
          (##continuation-capture __tmp151769))))
    (define with-catch
      (lambda (_%handler151492%_ _%thunk151493%_)
        (if (procedure? _%handler151492%_)
            (let ((_%handler151497%_ _%handler151492%_))
              (if (procedure? _%thunk151493%_)
                  (let ((_%thunk151507%_ _%thunk151493%_))
                    (__with-catch _%handler151497%_ _%thunk151507%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/error.ss\"@67.42-67.47"
                     'contract:
                     'procedure?
                     'value:
                     _%thunk151493%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/error.ss\"@67.19-67.26"
               'contract:
               'procedure?
               'value:
               _%handler151492%_)
              '#!void))))
    (define with-exception-catcher with-catch)
    (define wrap-runtime-exception
      (lambda (_%exn151479%_)
        (if (or (heap-overflow-exception? _%exn151479%_)
                (stack-overflow-exception? _%exn151479%_))
            _%exn151479%_
            (if (let ()
                  (declare (not safe))
                  (class-instance? Exception::t _%exn151479%_))
                _%exn151479%_
                (if (macro-exception? _%exn151479%_)
                    (let ((_%rte151487%_
                           (let ((__obj151761
                                  (let ()
                                    (declare (not safe))
                                    (##structure
                                     RuntimeException::t
                                     '#f
                                     '#f))))
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-set!
                                __obj151761
                                _%exn151479%_
                                '2
                                '#f
                                '#f))
                             __obj151761)))
                      (let ((__tmp151770
                             (lambda (_%cont151489%_)
                               (let ((__tmp151771
                                      (let ()
                                        (declare (not safe))
                                        (##continuation-next _%cont151489%_))))
                                 (declare (not safe))
                                 (unchecked-slot-set!
                                  _%rte151487%_
                                  'continuation
                                  __tmp151771)))))
                        (declare (not safe))
                        (##continuation-capture __tmp151770))
                      _%rte151487%_)
                    _%exn151479%_)))))
    (define exception? Exception?)
    (define error? Error?)
    (define error-object?
      (lambda (_%obj151474%_)
        (let ((_%$e151476%_
               (let ()
                 (declare (not safe))
                 (class-instance? Error::t _%obj151474%_))))
          (if _%$e151476%_ _%$e151476%_ (error-exception? _%obj151474%_)))))
    (define error-message
      (lambda (_%obj151433%_)
        (let ((_%$e151469%_
               (let* ((_%obj151435%_ _%obj151433%_)
                      (_%slot151438%_ 'message)
                      (_%E151441%_ false)
                      (_%slot151446%_ _%slot151438%_)
                      (_%E151459%_ _%E151441%_))
                 (declare (not safe))
                 (__slot-ref__% _%obj151435%_ _%slot151446%_ _%E151459%_))))
          (if _%$e151469%_
              _%$e151469%_
              (if (error-exception? _%obj151433%_)
                  (error-exception-message _%obj151433%_)
                  '#f)))))
    (define error-irritants
      (lambda (_%obj151428%_)
        (if (let ()
              (declare (not safe))
              (class-instance? Error::t _%obj151428%_))
            (let ()
              (declare (not safe))
              (unchecked-slot-ref _%obj151428%_ 'irritants))
            (if (error-exception? _%obj151428%_)
                (error-exception-parameters _%obj151428%_)
                '#f))))
    (define error-trace
      (lambda (_%obj151426%_)
        (if (let ()
              (declare (not safe))
              (class-instance? Error::t _%obj151426%_))
            (let ()
              (declare (not safe))
              (unchecked-slot-ref _%obj151426%_ 'where))
            '#f)))
    (define display-exception__%
      (lambda (_%e151387%_ _%port151388%_)
        (let ((_%$e151410%_
               (let* ((_%obj151390%_ _%e151387%_)
                      (_%id151393%_ 'display-exception)
                      (_%id151398%_ _%id151393%_))
                 (declare (not safe))
                 (__method-ref _%obj151390%_ _%id151398%_))))
          (if _%$e151410%_
              (_%$e151410%_ _%e151387%_ _%port151388%_)
              (let ()
                (declare (not safe))
                (##default-display-exception _%e151387%_ _%port151388%_))))))
    (define display-exception__0
      (lambda (_%e151419%_)
        (let ((_%port151421%_ (current-error-port)))
          (display-exception__% _%e151419%_ _%port151421%_))))
    (define display-exception
      (lambda _g151772_
        (let ((_g151773_ (let () (declare (not safe)) (##length _g151772_))))
          (cond ((let () (declare (not safe)) (##fx= _g151773_ 1))
                 (apply display-exception__0 _g151772_))
                ((let () (declare (not safe)) (##fx= _g151773_ 2))
                 (apply display-exception__% _g151772_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  display-exception
                  _g151772_))))))
    (let ()
      (declare (not safe))
      (##display-exception-hook-set! display-exception))
    (define Error:::init!
      (lambda (_%self151365%_ _%message151366%_ . _%rest151367%_)
        (let* ((_%self151370%_ _%self151365%_)
               (_%message151384%_
                (if (string? _%message151366%_)
                    _%message151366%_
                    (call-with-output-string
                     '""
                     (lambda (_%$%g151379151381%_)
                       (display _%message151366%_ _%$%g151379151381%_))))))
          (let ()
            (declare (not safe))
            (unchecked-slot-set! _%self151370%_ 'message _%message151384%_))
          (apply class-instance-init! _%self151370%_ _%rest151367%_))))
    (define Error:::init!::specialize
      (lambda (__klass151682 __method-table151683)
        (let ((__message151684
               (let ((__slot151685
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151682 'message))))
                 (if __slot151685
                     __slot151685
                     (error '"Unknown slot" 'message)))))
          (lambda (_%self151365%_ _%message151366%_ . _%rest151367%_)
            (let* ((_%self151370%_ _%self151365%_)
                   (_%message151384%_
                    (if (string? _%message151366%_)
                        _%message151366%_
                        (call-with-output-string
                         '""
                         (lambda (_%$%g151379151381%_)
                           (display _%message151366%_ _%$%g151379151381%_))))))
              (let ()
                (declare (not safe))
                (##unchecked-structure-set!
                 _%self151370%_
                 _%message151384%_
                 __message151684
                 '#f
                 '#f))
              (apply class-instance-init! _%self151370%_ _%rest151367%_))))))
    (let ()
      (declare (not safe))
      (bind-specializer! Error:::init! Error:::init!::specialize))
    (let ()
      (declare (not safe))
      (__bind-method!__% Error::t ':init! Error:::init! '#f))
    (define ContractViolation:::init! Error:::init!)
    (let ()
      (declare (not safe))
      (__bind-method!__%
       ContractViolation::t
       ':init!
       ContractViolation:::init!
       '#f))
    (define dump-stack-trace? (make-parameter '#f))
    (define Error::display-exception
      (lambda (_%self151070%_ _%port151071%_)
        (let ((_%self151074%_ _%self151070%_))
          (let ((_%tmp-port151084%_ (open-output-string))
                (_%display-error-newline151085%_
                 (> (output-port-column _%port151071%_) '0)))
            (fix-port-width! _%tmp-port151084%_)
            (let ((__tmp151774
                   (lambda ()
                     (if _%display-error-newline151085%_ (newline) '#!void)
                     (display '"*** ERROR IN ")
                     (let ((_%$e151088%_
                            (let ()
                              (declare (not safe))
                              (unchecked-slot-ref _%self151074%_ 'where))))
                       (if _%$e151088%_ (display _%$e151088%_) (display '"?")))
                     (let ((__tmp151775
                            (let ((__tmp151776
                                   (let ((_%obj151092%_ _%self151074%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (object? _%obj151092%_))
                                         (let ((_%obj151097%_ _%obj151092%_))
                                           (declare (not safe))
                                           (__object-class _%obj151097%_))
                                         (begin
                                           (raise-contract-violation-error
                                            '"contract violation"
                                            'context:
                                            'gerbil/runtime/error
                                            'contract:
                                            'object?
                                            'value:
                                            _%obj151092%_)
                                           '#!void)))))
                              (declare (not safe))
                              (##type-name __tmp151776))))
                       (declare (not safe))
                       (display* '" [" __tmp151775 '"]: "))
                     (let ((__tmp151777
                            (let ()
                              (declare (not safe))
                              (unchecked-slot-ref _%self151074%_ 'message))))
                       (declare (not safe))
                       (displayln __tmp151777))
                     (let ((_%irritants151112%_
                            (let ()
                              (declare (not safe))
                              (unchecked-slot-ref _%self151074%_ 'irritants))))
                       (if (null? _%irritants151112%_)
                           '#!void
                           (begin
                             (display '"--- irritants: ")
                             (for-each
                              (lambda (_%obj151114%_)
                                (if (u8vector? _%obj151114%_)
                                    (let ((__tmp151778
                                           (cons '<u8vector>
                                                 (cons (let ()
                                                         (declare (not safe))
                                                         (##u8vector-length
                                                          _%obj151114%_))
                                                       '()))))
                                      (declare (not safe))
                                      (##write __tmp151778))
                                    (let ()
                                      (declare (not safe))
                                      (##write _%obj151114%_)))
                                (let ()
                                  (declare (not safe))
                                  (##write-char '#\space)))
                              _%irritants151112%_)
                             (newline))))
                     (if (let () (declare (not safe)) (dump-stack-trace?))
                         (let ((_%$%cont151115151117%_
                                (let ()
                                  (declare (not safe))
                                  (unchecked-slot-ref
                                   _%self151074%_
                                   'continuation))))
                           (if _%$%cont151115151117%_
                               (let ((_%cont151119%_ _%$%cont151115151117%_))
                                 (let ()
                                   (declare (not safe))
                                   (displayln '"--- continuation backtrace:"))
                                 (display-continuation-backtrace
                                  _%cont151119%_))
                               '#f))
                         '#!void))))
              (declare (not safe))
              (call-with-parameters__1
               __tmp151774
               current-output-port
               _%tmp-port151084%_))
            (let ((__tmp151779 (get-output-string _%tmp-port151084%_)))
              (declare (not safe))
              (##write-string __tmp151779 _%port151071%_))))))
    (define Error::display-exception::specialize
      (lambda (__klass151686 __method-table151687)
        (let ((__where151688
               (let ((__slot151692
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151686 'where))))
                 (if __slot151692
                     __slot151692
                     (error '"Unknown slot" 'where))))
              (__irritants151689
               (let ((__slot151693
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151686 'irritants))))
                 (if __slot151693
                     __slot151693
                     (error '"Unknown slot" 'irritants))))
              (__continuation151690
               (let ((__slot151694
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151686 'continuation))))
                 (if __slot151694
                     __slot151694
                     (error '"Unknown slot" 'continuation))))
              (__message151691
               (let ((__slot151695
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151686 'message))))
                 (if __slot151695
                     __slot151695
                     (error '"Unknown slot" 'message)))))
          (lambda (_%self151070%_ _%port151071%_)
            (let ((_%self151074%_ _%self151070%_))
              (let ((_%tmp-port151084%_ (open-output-string))
                    (_%display-error-newline151085%_
                     (> (output-port-column _%port151071%_) '0)))
                (fix-port-width! _%tmp-port151084%_)
                (let ((__tmp151780
                       (lambda ()
                         (if _%display-error-newline151085%_ (newline) '#!void)
                         (display '"*** ERROR IN ")
                         (let ((_%$e151088%_
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%self151074%_
                                   __where151688
                                   '#f
                                   '#f))))
                           (if _%$e151088%_
                               (display _%$e151088%_)
                               (display '"?")))
                         (let ((__tmp151781
                                (let ((__tmp151782
                                       (let ((_%obj151092%_ _%self151074%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (object? _%obj151092%_))
                                             (let ((_%obj151097%_
                                                    _%obj151092%_))
                                               (declare (not safe))
                                               (__object-class _%obj151097%_))
                                             (begin
                                               (raise-contract-violation-error
                                                '"contract violation"
                                                'context:
                                                'gerbil/runtime/error
                                                'contract:
                                                'object?
                                                'value:
                                                _%obj151092%_)
                                               '#!void)))))
                                  (declare (not safe))
                                  (##type-name __tmp151782))))
                           (declare (not safe))
                           (display* '" [" __tmp151781 '"]: "))
                         (let ((__tmp151783
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%self151074%_
                                   __message151691
                                   '#f
                                   '#f))))
                           (declare (not safe))
                           (displayln __tmp151783))
                         (let ((_%irritants151112%_
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%self151074%_
                                   __irritants151689
                                   '#f
                                   '#f))))
                           (if (null? _%irritants151112%_)
                               '#!void
                               (begin
                                 (display '"--- irritants: ")
                                 (for-each
                                  (lambda (_%obj151114%_)
                                    (if (u8vector? _%obj151114%_)
                                        (let ((__tmp151784
                                               (cons '<u8vector>
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (##u8vector-length
                                                              _%obj151114%_))
                                                           '()))))
                                          (declare (not safe))
                                          (##write __tmp151784))
                                        (let ()
                                          (declare (not safe))
                                          (##write _%obj151114%_)))
                                    (let ()
                                      (declare (not safe))
                                      (##write-char '#\space)))
                                  _%irritants151112%_)
                                 (newline))))
                         (if (let () (declare (not safe)) (dump-stack-trace?))
                             (let ((_%$%cont151115151117%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%self151074%_
                                       __continuation151690
                                       '#f
                                       '#f))))
                               (if _%$%cont151115151117%_
                                   (let ((_%cont151119%_
                                          _%$%cont151115151117%_))
                                     (let ()
                                       (declare (not safe))
                                       (displayln
                                        '"--- continuation backtrace:"))
                                     (display-continuation-backtrace
                                      _%cont151119%_))
                                   '#f))
                             '#!void))))
                  (declare (not safe))
                  (call-with-parameters__1
                   __tmp151780
                   current-output-port
                   _%tmp-port151084%_))
                (let ((__tmp151785 (get-output-string _%tmp-port151084%_)))
                  (declare (not safe))
                  (##write-string __tmp151785 _%port151071%_))))))))
    (let ()
      (declare (not safe))
      (bind-specializer!
       Error::display-exception
       Error::display-exception::specialize))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       Error::t
       'display-exception
       Error::display-exception
       '#t))
    (define RuntimeException::display-exception
      (lambda (_%self150927%_ _%port150928%_)
        (let* ((_%self150931%_ _%self150927%_)
               (_%tmp-port150941%_ (open-output-string)))
          (fix-port-width! _%tmp-port150941%_)
          (let ((__tmp151786
                 (let ()
                   (declare (not safe))
                   (unchecked-slot-ref _%self150931%_ 'exception))))
            (declare (not safe))
            (##default-display-exception __tmp151786 _%tmp-port150941%_))
          (if (let () (declare (not safe)) (dump-stack-trace?))
              (let ((_%$%cont150942150944%_
                     (let ()
                       (declare (not safe))
                       (unchecked-slot-ref _%self150931%_ 'continuation))))
                (if _%$%cont150942150944%_
                    (let ((_%cont150946%_ _%$%cont150942150944%_))
                      (display '"--- continuation backtrace:"
                               _%tmp-port150941%_)
                      (newline _%tmp-port150941%_)
                      (display-continuation-backtrace
                       _%cont150946%_
                       _%tmp-port150941%_))
                    '#f))
              '#!void)
          (let ((__tmp151787 (get-output-string _%tmp-port150941%_)))
            (declare (not safe))
            (##write-string __tmp151787 _%port150928%_)))))
    (define RuntimeException::display-exception::specialize
      (lambda (__klass151696 __method-table151697)
        (let ((__exception151698
               (let ((__slot151700
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151696 'exception))))
                 (if __slot151700
                     __slot151700
                     (error '"Unknown slot" 'exception))))
              (__continuation151699
               (let ((__slot151701
                      (let ()
                        (declare (not safe))
                        (class-slot-offset __klass151696 'continuation))))
                 (if __slot151701
                     __slot151701
                     (error '"Unknown slot" 'continuation)))))
          (lambda (_%self150927%_ _%port150928%_)
            (let* ((_%self150931%_ _%self150927%_)
                   (_%tmp-port150941%_ (open-output-string)))
              (fix-port-width! _%tmp-port150941%_)
              (let ((__tmp151788
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref
                        _%self150931%_
                        __exception151698
                        '#f
                        '#f))))
                (declare (not safe))
                (##default-display-exception __tmp151788 _%tmp-port150941%_))
              (if (let () (declare (not safe)) (dump-stack-trace?))
                  (let ((_%$%cont150942150944%_
                         (let ()
                           (declare (not safe))
                           (##unchecked-structure-ref
                            _%self150931%_
                            __continuation151699
                            '#f
                            '#f))))
                    (if _%$%cont150942150944%_
                        (let ((_%cont150946%_ _%$%cont150942150944%_))
                          (display '"--- continuation backtrace:"
                                   _%tmp-port150941%_)
                          (newline _%tmp-port150941%_)
                          (display-continuation-backtrace
                           _%cont150946%_
                           _%tmp-port150941%_))
                        '#f))
                  '#!void)
              (let ((__tmp151789 (get-output-string _%tmp-port150941%_)))
                (declare (not safe))
                (##write-string __tmp151789 _%port150928%_)))))))
    (let ()
      (declare (not safe))
      (bind-specializer!
       RuntimeException::display-exception
       RuntimeException::display-exception::specialize))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       RuntimeException::t
       'display-exception
       RuntimeException::display-exception
       '#f))
    (define fix-port-width!
      (lambda (_%port150799%_)
        (if (macro-character-port? _%port150799%_)
            (let ((_%old-width150801%_
                   (macro-character-port-output-width _%port150799%_)))
              (macro-character-port-output-width-set!
               _%port150799%_
               (lambda (_%port150803%_) '512))
              _%old-width150801%_)
            '#!void)))
    (define reset-port-width!
      (lambda (_%port150796%_ _%old-width150797%_)
        (if (macro-character-port? _%port150796%_)
            (macro-character-port-output-width-set!
             _%port150796%_
             _%old-width150797%_)
            '#!void)))
    (define datum-parsing-exception-filepos
      (lambda (_%e150794%_)
        (macro-readenv-filepos (datum-parsing-exception-readenv _%e150794%_))))
    (define abandoned-mutex-exception?
      (lambda (_%exn150788%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150788%_))
            (let ((_%e150791%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150788%_ 'exception))))
              (macro-abandoned-mutex-exception? _%e150791%_))
            (macro-abandoned-mutex-exception? _%exn150788%_))))
    (define cfun-conversion-exception?
      (lambda (_%exn150784%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150784%_))
            (let ((_%e150786%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150784%_ 'exception))))
              (macro-cfun-conversion-exception? _%e150786%_))
            (macro-cfun-conversion-exception? _%exn150784%_))))
    (define cfun-conversion-exception-arguments
      (lambda (_%exn150780%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150780%_))
            (let ((_%e150782%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150780%_ 'exception))))
              (if (macro-cfun-conversion-exception? _%e150782%_)
                  (macro-cfun-conversion-exception-arguments _%e150782%_)
                  (error '"not an instance"
                         'cfun-conversion-exception?
                         (cons 'cfun-conversion-exception-arguments
                               (cons _%e150782%_ '())))))
            (if (macro-cfun-conversion-exception? _%exn150780%_)
                (macro-cfun-conversion-exception-arguments _%exn150780%_)
                (error '"not an instance"
                       'cfun-conversion-exception?
                       (cons 'cfun-conversion-exception-arguments
                             (cons _%exn150780%_ '())))))))
    (define cfun-conversion-exception-code
      (lambda (_%exn150776%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150776%_))
            (let ((_%e150778%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150776%_ 'exception))))
              (if (macro-cfun-conversion-exception? _%e150778%_)
                  (macro-cfun-conversion-exception-code _%e150778%_)
                  (error '"not an instance"
                         'cfun-conversion-exception?
                         (cons 'cfun-conversion-exception-code
                               (cons _%e150778%_ '())))))
            (if (macro-cfun-conversion-exception? _%exn150776%_)
                (macro-cfun-conversion-exception-code _%exn150776%_)
                (error '"not an instance"
                       'cfun-conversion-exception?
                       (cons 'cfun-conversion-exception-code
                             (cons _%exn150776%_ '())))))))
    (define cfun-conversion-exception-message
      (lambda (_%exn150772%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150772%_))
            (let ((_%e150774%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150772%_ 'exception))))
              (if (macro-cfun-conversion-exception? _%e150774%_)
                  (macro-cfun-conversion-exception-message _%e150774%_)
                  (error '"not an instance"
                         'cfun-conversion-exception?
                         (cons 'cfun-conversion-exception-message
                               (cons _%e150774%_ '())))))
            (if (macro-cfun-conversion-exception? _%exn150772%_)
                (macro-cfun-conversion-exception-message _%exn150772%_)
                (error '"not an instance"
                       'cfun-conversion-exception?
                       (cons 'cfun-conversion-exception-message
                             (cons _%exn150772%_ '())))))))
    (define cfun-conversion-exception-procedure
      (lambda (_%exn150766%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150766%_))
            (let ((_%e150769%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150766%_ 'exception))))
              (if (macro-cfun-conversion-exception? _%e150769%_)
                  (macro-cfun-conversion-exception-procedure _%e150769%_)
                  (error '"not an instance"
                         'cfun-conversion-exception?
                         (cons 'cfun-conversion-exception-procedure
                               (cons _%e150769%_ '())))))
            (if (macro-cfun-conversion-exception? _%exn150766%_)
                (macro-cfun-conversion-exception-procedure _%exn150766%_)
                (error '"not an instance"
                       'cfun-conversion-exception?
                       (cons 'cfun-conversion-exception-procedure
                             (cons _%exn150766%_ '())))))))
    (define datum-parsing-exception?
      (lambda (_%exn150762%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150762%_))
            (let ((_%e150764%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150762%_ 'exception))))
              (macro-datum-parsing-exception? _%e150764%_))
            (macro-datum-parsing-exception? _%exn150762%_))))
    (define datum-parsing-exception-kind
      (lambda (_%exn150758%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150758%_))
            (let ((_%e150760%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150758%_ 'exception))))
              (if (macro-datum-parsing-exception? _%e150760%_)
                  (macro-datum-parsing-exception-kind _%e150760%_)
                  (error '"not an instance"
                         'datum-parsing-exception?
                         (cons 'datum-parsing-exception-kind
                               (cons _%e150760%_ '())))))
            (if (macro-datum-parsing-exception? _%exn150758%_)
                (macro-datum-parsing-exception-kind _%exn150758%_)
                (error '"not an instance"
                       'datum-parsing-exception?
                       (cons 'datum-parsing-exception-kind
                             (cons _%exn150758%_ '())))))))
    (define datum-parsing-exception-parameters
      (lambda (_%exn150754%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150754%_))
            (let ((_%e150756%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150754%_ 'exception))))
              (if (macro-datum-parsing-exception? _%e150756%_)
                  (macro-datum-parsing-exception-parameters _%e150756%_)
                  (error '"not an instance"
                         'datum-parsing-exception?
                         (cons 'datum-parsing-exception-parameters
                               (cons _%e150756%_ '())))))
            (if (macro-datum-parsing-exception? _%exn150754%_)
                (macro-datum-parsing-exception-parameters _%exn150754%_)
                (error '"not an instance"
                       'datum-parsing-exception?
                       (cons 'datum-parsing-exception-parameters
                             (cons _%exn150754%_ '())))))))
    (define datum-parsing-exception-readenv
      (lambda (_%exn150748%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150748%_))
            (let ((_%e150751%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150748%_ 'exception))))
              (if (macro-datum-parsing-exception? _%e150751%_)
                  (macro-datum-parsing-exception-readenv _%e150751%_)
                  (error '"not an instance"
                         'datum-parsing-exception?
                         (cons 'datum-parsing-exception-readenv
                               (cons _%e150751%_ '())))))
            (if (macro-datum-parsing-exception? _%exn150748%_)
                (macro-datum-parsing-exception-readenv _%exn150748%_)
                (error '"not an instance"
                       'datum-parsing-exception?
                       (cons 'datum-parsing-exception-readenv
                             (cons _%exn150748%_ '())))))))
    (define deadlock-exception?
      (lambda (_%exn150742%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150742%_))
            (let ((_%e150745%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150742%_ 'exception))))
              (macro-deadlock-exception? _%e150745%_))
            (macro-deadlock-exception? _%exn150742%_))))
    (define divide-by-zero-exception?
      (lambda (_%exn150738%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150738%_))
            (let ((_%e150740%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150738%_ 'exception))))
              (macro-divide-by-zero-exception? _%e150740%_))
            (macro-divide-by-zero-exception? _%exn150738%_))))
    (define divide-by-zero-exception-arguments
      (lambda (_%exn150734%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150734%_))
            (let ((_%e150736%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150734%_ 'exception))))
              (if (macro-divide-by-zero-exception? _%e150736%_)
                  (macro-divide-by-zero-exception-arguments _%e150736%_)
                  (error '"not an instance"
                         'divide-by-zero-exception?
                         (cons 'divide-by-zero-exception-arguments
                               (cons _%e150736%_ '())))))
            (if (macro-divide-by-zero-exception? _%exn150734%_)
                (macro-divide-by-zero-exception-arguments _%exn150734%_)
                (error '"not an instance"
                       'divide-by-zero-exception?
                       (cons 'divide-by-zero-exception-arguments
                             (cons _%exn150734%_ '())))))))
    (define divide-by-zero-exception-procedure
      (lambda (_%exn150728%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150728%_))
            (let ((_%e150731%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150728%_ 'exception))))
              (if (macro-divide-by-zero-exception? _%e150731%_)
                  (macro-divide-by-zero-exception-procedure _%e150731%_)
                  (error '"not an instance"
                         'divide-by-zero-exception?
                         (cons 'divide-by-zero-exception-procedure
                               (cons _%e150731%_ '())))))
            (if (macro-divide-by-zero-exception? _%exn150728%_)
                (macro-divide-by-zero-exception-procedure _%exn150728%_)
                (error '"not an instance"
                       'divide-by-zero-exception?
                       (cons 'divide-by-zero-exception-procedure
                             (cons _%exn150728%_ '())))))))
    (define error-exception?
      (lambda (_%exn150724%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150724%_))
            (let ((_%e150726%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150724%_ 'exception))))
              (macro-error-exception? _%e150726%_))
            (macro-error-exception? _%exn150724%_))))
    (define error-exception-message
      (lambda (_%exn150720%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150720%_))
            (let ((_%e150722%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150720%_ 'exception))))
              (if (macro-error-exception? _%e150722%_)
                  (macro-error-exception-message _%e150722%_)
                  (error '"not an instance"
                         'error-exception?
                         (cons 'error-exception-message
                               (cons _%e150722%_ '())))))
            (if (macro-error-exception? _%exn150720%_)
                (macro-error-exception-message _%exn150720%_)
                (error '"not an instance"
                       'error-exception?
                       (cons 'error-exception-message
                             (cons _%exn150720%_ '())))))))
    (define error-exception-parameters
      (lambda (_%exn150714%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150714%_))
            (let ((_%e150717%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150714%_ 'exception))))
              (if (macro-error-exception? _%e150717%_)
                  (macro-error-exception-parameters _%e150717%_)
                  (error '"not an instance"
                         'error-exception?
                         (cons 'error-exception-parameters
                               (cons _%e150717%_ '())))))
            (if (macro-error-exception? _%exn150714%_)
                (macro-error-exception-parameters _%exn150714%_)
                (error '"not an instance"
                       'error-exception?
                       (cons 'error-exception-parameters
                             (cons _%exn150714%_ '())))))))
    (define expression-parsing-exception?
      (lambda (_%exn150710%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150710%_))
            (let ((_%e150712%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150710%_ 'exception))))
              (macro-expression-parsing-exception? _%e150712%_))
            (macro-expression-parsing-exception? _%exn150710%_))))
    (define expression-parsing-exception-kind
      (lambda (_%exn150706%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150706%_))
            (let ((_%e150708%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150706%_ 'exception))))
              (if (macro-expression-parsing-exception? _%e150708%_)
                  (macro-expression-parsing-exception-kind _%e150708%_)
                  (error '"not an instance"
                         'expression-parsing-exception?
                         (cons 'expression-parsing-exception-kind
                               (cons _%e150708%_ '())))))
            (if (macro-expression-parsing-exception? _%exn150706%_)
                (macro-expression-parsing-exception-kind _%exn150706%_)
                (error '"not an instance"
                       'expression-parsing-exception?
                       (cons 'expression-parsing-exception-kind
                             (cons _%exn150706%_ '())))))))
    (define expression-parsing-exception-parameters
      (lambda (_%exn150702%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150702%_))
            (let ((_%e150704%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150702%_ 'exception))))
              (if (macro-expression-parsing-exception? _%e150704%_)
                  (macro-expression-parsing-exception-parameters _%e150704%_)
                  (error '"not an instance"
                         'expression-parsing-exception?
                         (cons 'expression-parsing-exception-parameters
                               (cons _%e150704%_ '())))))
            (if (macro-expression-parsing-exception? _%exn150702%_)
                (macro-expression-parsing-exception-parameters _%exn150702%_)
                (error '"not an instance"
                       'expression-parsing-exception?
                       (cons 'expression-parsing-exception-parameters
                             (cons _%exn150702%_ '())))))))
    (define expression-parsing-exception-source
      (lambda (_%exn150696%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150696%_))
            (let ((_%e150699%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150696%_ 'exception))))
              (if (macro-expression-parsing-exception? _%e150699%_)
                  (macro-expression-parsing-exception-source _%e150699%_)
                  (error '"not an instance"
                         'expression-parsing-exception?
                         (cons 'expression-parsing-exception-source
                               (cons _%e150699%_ '())))))
            (if (macro-expression-parsing-exception? _%exn150696%_)
                (macro-expression-parsing-exception-source _%exn150696%_)
                (error '"not an instance"
                       'expression-parsing-exception?
                       (cons 'expression-parsing-exception-source
                             (cons _%exn150696%_ '())))))))
    (define file-exists-exception?
      (lambda (_%exn150692%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150692%_))
            (let ((_%e150694%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150692%_ 'exception))))
              (macro-file-exists-exception? _%e150694%_))
            (macro-file-exists-exception? _%exn150692%_))))
    (define file-exists-exception-arguments
      (lambda (_%exn150688%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150688%_))
            (let ((_%e150690%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150688%_ 'exception))))
              (if (macro-file-exists-exception? _%e150690%_)
                  (macro-file-exists-exception-arguments _%e150690%_)
                  (error '"not an instance"
                         'file-exists-exception?
                         (cons 'file-exists-exception-arguments
                               (cons _%e150690%_ '())))))
            (if (macro-file-exists-exception? _%exn150688%_)
                (macro-file-exists-exception-arguments _%exn150688%_)
                (error '"not an instance"
                       'file-exists-exception?
                       (cons 'file-exists-exception-arguments
                             (cons _%exn150688%_ '())))))))
    (define file-exists-exception-procedure
      (lambda (_%exn150682%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150682%_))
            (let ((_%e150685%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150682%_ 'exception))))
              (if (macro-file-exists-exception? _%e150685%_)
                  (macro-file-exists-exception-procedure _%e150685%_)
                  (error '"not an instance"
                         'file-exists-exception?
                         (cons 'file-exists-exception-procedure
                               (cons _%e150685%_ '())))))
            (if (macro-file-exists-exception? _%exn150682%_)
                (macro-file-exists-exception-procedure _%exn150682%_)
                (error '"not an instance"
                       'file-exists-exception?
                       (cons 'file-exists-exception-procedure
                             (cons _%exn150682%_ '())))))))
    (define fixnum-overflow-exception?
      (lambda (_%exn150678%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150678%_))
            (let ((_%e150680%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150678%_ 'exception))))
              (macro-fixnum-overflow-exception? _%e150680%_))
            (macro-fixnum-overflow-exception? _%exn150678%_))))
    (define fixnum-overflow-exception-arguments
      (lambda (_%exn150674%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150674%_))
            (let ((_%e150676%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150674%_ 'exception))))
              (if (macro-fixnum-overflow-exception? _%e150676%_)
                  (macro-fixnum-overflow-exception-arguments _%e150676%_)
                  (error '"not an instance"
                         'fixnum-overflow-exception?
                         (cons 'fixnum-overflow-exception-arguments
                               (cons _%e150676%_ '())))))
            (if (macro-fixnum-overflow-exception? _%exn150674%_)
                (macro-fixnum-overflow-exception-arguments _%exn150674%_)
                (error '"not an instance"
                       'fixnum-overflow-exception?
                       (cons 'fixnum-overflow-exception-arguments
                             (cons _%exn150674%_ '())))))))
    (define fixnum-overflow-exception-procedure
      (lambda (_%exn150668%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150668%_))
            (let ((_%e150671%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150668%_ 'exception))))
              (if (macro-fixnum-overflow-exception? _%e150671%_)
                  (macro-fixnum-overflow-exception-procedure _%e150671%_)
                  (error '"not an instance"
                         'fixnum-overflow-exception?
                         (cons 'fixnum-overflow-exception-procedure
                               (cons _%e150671%_ '())))))
            (if (macro-fixnum-overflow-exception? _%exn150668%_)
                (macro-fixnum-overflow-exception-procedure _%exn150668%_)
                (error '"not an instance"
                       'fixnum-overflow-exception?
                       (cons 'fixnum-overflow-exception-procedure
                             (cons _%exn150668%_ '())))))))
    (define heap-overflow-exception?
      (lambda (_%exn150662%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150662%_))
            (let ((_%e150665%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150662%_ 'exception))))
              (macro-heap-overflow-exception? _%e150665%_))
            (macro-heap-overflow-exception? _%exn150662%_))))
    (define inactive-thread-exception?
      (lambda (_%exn150658%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150658%_))
            (let ((_%e150660%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150658%_ 'exception))))
              (macro-inactive-thread-exception? _%e150660%_))
            (macro-inactive-thread-exception? _%exn150658%_))))
    (define inactive-thread-exception-arguments
      (lambda (_%exn150654%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150654%_))
            (let ((_%e150656%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150654%_ 'exception))))
              (if (macro-inactive-thread-exception? _%e150656%_)
                  (macro-inactive-thread-exception-arguments _%e150656%_)
                  (error '"not an instance"
                         'inactive-thread-exception?
                         (cons 'inactive-thread-exception-arguments
                               (cons _%e150656%_ '())))))
            (if (macro-inactive-thread-exception? _%exn150654%_)
                (macro-inactive-thread-exception-arguments _%exn150654%_)
                (error '"not an instance"
                       'inactive-thread-exception?
                       (cons 'inactive-thread-exception-arguments
                             (cons _%exn150654%_ '())))))))
    (define inactive-thread-exception-procedure
      (lambda (_%exn150648%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150648%_))
            (let ((_%e150651%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150648%_ 'exception))))
              (if (macro-inactive-thread-exception? _%e150651%_)
                  (macro-inactive-thread-exception-procedure _%e150651%_)
                  (error '"not an instance"
                         'inactive-thread-exception?
                         (cons 'inactive-thread-exception-procedure
                               (cons _%e150651%_ '())))))
            (if (macro-inactive-thread-exception? _%exn150648%_)
                (macro-inactive-thread-exception-procedure _%exn150648%_)
                (error '"not an instance"
                       'inactive-thread-exception?
                       (cons 'inactive-thread-exception-procedure
                             (cons _%exn150648%_ '())))))))
    (define initialized-thread-exception?
      (lambda (_%exn150644%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150644%_))
            (let ((_%e150646%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150644%_ 'exception))))
              (macro-initialized-thread-exception? _%e150646%_))
            (macro-initialized-thread-exception? _%exn150644%_))))
    (define initialized-thread-exception-arguments
      (lambda (_%exn150640%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150640%_))
            (let ((_%e150642%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150640%_ 'exception))))
              (if (macro-initialized-thread-exception? _%e150642%_)
                  (macro-initialized-thread-exception-arguments _%e150642%_)
                  (error '"not an instance"
                         'initialized-thread-exception?
                         (cons 'initialized-thread-exception-arguments
                               (cons _%e150642%_ '())))))
            (if (macro-initialized-thread-exception? _%exn150640%_)
                (macro-initialized-thread-exception-arguments _%exn150640%_)
                (error '"not an instance"
                       'initialized-thread-exception?
                       (cons 'initialized-thread-exception-arguments
                             (cons _%exn150640%_ '())))))))
    (define initialized-thread-exception-procedure
      (lambda (_%exn150634%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150634%_))
            (let ((_%e150637%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150634%_ 'exception))))
              (if (macro-initialized-thread-exception? _%e150637%_)
                  (macro-initialized-thread-exception-procedure _%e150637%_)
                  (error '"not an instance"
                         'initialized-thread-exception?
                         (cons 'initialized-thread-exception-procedure
                               (cons _%e150637%_ '())))))
            (if (macro-initialized-thread-exception? _%exn150634%_)
                (macro-initialized-thread-exception-procedure _%exn150634%_)
                (error '"not an instance"
                       'initialized-thread-exception?
                       (cons 'initialized-thread-exception-procedure
                             (cons _%exn150634%_ '())))))))
    (define invalid-hash-number-exception?
      (lambda (_%exn150630%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150630%_))
            (let ((_%e150632%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150630%_ 'exception))))
              (macro-invalid-hash-number-exception? _%e150632%_))
            (macro-invalid-hash-number-exception? _%exn150630%_))))
    (define invalid-hash-number-exception-arguments
      (lambda (_%exn150626%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150626%_))
            (let ((_%e150628%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150626%_ 'exception))))
              (if (macro-invalid-hash-number-exception? _%e150628%_)
                  (macro-invalid-hash-number-exception-arguments _%e150628%_)
                  (error '"not an instance"
                         'invalid-hash-number-exception?
                         (cons 'invalid-hash-number-exception-arguments
                               (cons _%e150628%_ '())))))
            (if (macro-invalid-hash-number-exception? _%exn150626%_)
                (macro-invalid-hash-number-exception-arguments _%exn150626%_)
                (error '"not an instance"
                       'invalid-hash-number-exception?
                       (cons 'invalid-hash-number-exception-arguments
                             (cons _%exn150626%_ '())))))))
    (define invalid-hash-number-exception-procedure
      (lambda (_%exn150620%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150620%_))
            (let ((_%e150623%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150620%_ 'exception))))
              (if (macro-invalid-hash-number-exception? _%e150623%_)
                  (macro-invalid-hash-number-exception-procedure _%e150623%_)
                  (error '"not an instance"
                         'invalid-hash-number-exception?
                         (cons 'invalid-hash-number-exception-procedure
                               (cons _%e150623%_ '())))))
            (if (macro-invalid-hash-number-exception? _%exn150620%_)
                (macro-invalid-hash-number-exception-procedure _%exn150620%_)
                (error '"not an instance"
                       'invalid-hash-number-exception?
                       (cons 'invalid-hash-number-exception-procedure
                             (cons _%exn150620%_ '())))))))
    (define invalid-utf8-encoding-exception?
      (lambda (_%exn150616%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150616%_))
            (let ((_%e150618%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150616%_ 'exception))))
              (macro-invalid-utf8-encoding-exception? _%e150618%_))
            (macro-invalid-utf8-encoding-exception? _%exn150616%_))))
    (define invalid-utf8-encoding-exception-arguments
      (lambda (_%exn150612%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150612%_))
            (let ((_%e150614%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150612%_ 'exception))))
              (if (macro-invalid-utf8-encoding-exception? _%e150614%_)
                  (macro-invalid-utf8-encoding-exception-arguments _%e150614%_)
                  (error '"not an instance"
                         'invalid-utf8-encoding-exception?
                         (cons 'invalid-utf8-encoding-exception-arguments
                               (cons _%e150614%_ '())))))
            (if (macro-invalid-utf8-encoding-exception? _%exn150612%_)
                (macro-invalid-utf8-encoding-exception-arguments _%exn150612%_)
                (error '"not an instance"
                       'invalid-utf8-encoding-exception?
                       (cons 'invalid-utf8-encoding-exception-arguments
                             (cons _%exn150612%_ '())))))))
    (define invalid-utf8-encoding-exception-procedure
      (lambda (_%exn150606%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150606%_))
            (let ((_%e150609%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150606%_ 'exception))))
              (if (macro-invalid-utf8-encoding-exception? _%e150609%_)
                  (macro-invalid-utf8-encoding-exception-procedure _%e150609%_)
                  (error '"not an instance"
                         'invalid-utf8-encoding-exception?
                         (cons 'invalid-utf8-encoding-exception-procedure
                               (cons _%e150609%_ '())))))
            (if (macro-invalid-utf8-encoding-exception? _%exn150606%_)
                (macro-invalid-utf8-encoding-exception-procedure _%exn150606%_)
                (error '"not an instance"
                       'invalid-utf8-encoding-exception?
                       (cons 'invalid-utf8-encoding-exception-procedure
                             (cons _%exn150606%_ '())))))))
    (define join-timeout-exception?
      (lambda (_%exn150602%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150602%_))
            (let ((_%e150604%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150602%_ 'exception))))
              (macro-join-timeout-exception? _%e150604%_))
            (macro-join-timeout-exception? _%exn150602%_))))
    (define join-timeout-exception-arguments
      (lambda (_%exn150598%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150598%_))
            (let ((_%e150600%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150598%_ 'exception))))
              (if (macro-join-timeout-exception? _%e150600%_)
                  (macro-join-timeout-exception-arguments _%e150600%_)
                  (error '"not an instance"
                         'join-timeout-exception?
                         (cons 'join-timeout-exception-arguments
                               (cons _%e150600%_ '())))))
            (if (macro-join-timeout-exception? _%exn150598%_)
                (macro-join-timeout-exception-arguments _%exn150598%_)
                (error '"not an instance"
                       'join-timeout-exception?
                       (cons 'join-timeout-exception-arguments
                             (cons _%exn150598%_ '())))))))
    (define join-timeout-exception-procedure
      (lambda (_%exn150592%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150592%_))
            (let ((_%e150595%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150592%_ 'exception))))
              (if (macro-join-timeout-exception? _%e150595%_)
                  (macro-join-timeout-exception-procedure _%e150595%_)
                  (error '"not an instance"
                         'join-timeout-exception?
                         (cons 'join-timeout-exception-procedure
                               (cons _%e150595%_ '())))))
            (if (macro-join-timeout-exception? _%exn150592%_)
                (macro-join-timeout-exception-procedure _%exn150592%_)
                (error '"not an instance"
                       'join-timeout-exception?
                       (cons 'join-timeout-exception-procedure
                             (cons _%exn150592%_ '())))))))
    (define keyword-expected-exception?
      (lambda (_%exn150588%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150588%_))
            (let ((_%e150590%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150588%_ 'exception))))
              (macro-keyword-expected-exception? _%e150590%_))
            (macro-keyword-expected-exception? _%exn150588%_))))
    (define keyword-expected-exception-arguments
      (lambda (_%exn150584%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150584%_))
            (let ((_%e150586%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150584%_ 'exception))))
              (if (macro-keyword-expected-exception? _%e150586%_)
                  (macro-keyword-expected-exception-arguments _%e150586%_)
                  (error '"not an instance"
                         'keyword-expected-exception?
                         (cons 'keyword-expected-exception-arguments
                               (cons _%e150586%_ '())))))
            (if (macro-keyword-expected-exception? _%exn150584%_)
                (macro-keyword-expected-exception-arguments _%exn150584%_)
                (error '"not an instance"
                       'keyword-expected-exception?
                       (cons 'keyword-expected-exception-arguments
                             (cons _%exn150584%_ '())))))))
    (define keyword-expected-exception-procedure
      (lambda (_%exn150578%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150578%_))
            (let ((_%e150581%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150578%_ 'exception))))
              (if (macro-keyword-expected-exception? _%e150581%_)
                  (macro-keyword-expected-exception-procedure _%e150581%_)
                  (error '"not an instance"
                         'keyword-expected-exception?
                         (cons 'keyword-expected-exception-procedure
                               (cons _%e150581%_ '())))))
            (if (macro-keyword-expected-exception? _%exn150578%_)
                (macro-keyword-expected-exception-procedure _%exn150578%_)
                (error '"not an instance"
                       'keyword-expected-exception?
                       (cons 'keyword-expected-exception-procedure
                             (cons _%exn150578%_ '())))))))
    (define length-mismatch-exception?
      (lambda (_%exn150574%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150574%_))
            (let ((_%e150576%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150574%_ 'exception))))
              (macro-length-mismatch-exception? _%e150576%_))
            (macro-length-mismatch-exception? _%exn150574%_))))
    (define length-mismatch-exception-arg-id
      (lambda (_%exn150570%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150570%_))
            (let ((_%e150572%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150570%_ 'exception))))
              (if (macro-length-mismatch-exception? _%e150572%_)
                  (macro-length-mismatch-exception-arg-id _%e150572%_)
                  (error '"not an instance"
                         'length-mismatch-exception?
                         (cons 'length-mismatch-exception-arg-id
                               (cons _%e150572%_ '())))))
            (if (macro-length-mismatch-exception? _%exn150570%_)
                (macro-length-mismatch-exception-arg-id _%exn150570%_)
                (error '"not an instance"
                       'length-mismatch-exception?
                       (cons 'length-mismatch-exception-arg-id
                             (cons _%exn150570%_ '())))))))
    (define length-mismatch-exception-arguments
      (lambda (_%exn150566%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150566%_))
            (let ((_%e150568%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150566%_ 'exception))))
              (if (macro-length-mismatch-exception? _%e150568%_)
                  (macro-length-mismatch-exception-arguments _%e150568%_)
                  (error '"not an instance"
                         'length-mismatch-exception?
                         (cons 'length-mismatch-exception-arguments
                               (cons _%e150568%_ '())))))
            (if (macro-length-mismatch-exception? _%exn150566%_)
                (macro-length-mismatch-exception-arguments _%exn150566%_)
                (error '"not an instance"
                       'length-mismatch-exception?
                       (cons 'length-mismatch-exception-arguments
                             (cons _%exn150566%_ '())))))))
    (define length-mismatch-exception-procedure
      (lambda (_%exn150560%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150560%_))
            (let ((_%e150563%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150560%_ 'exception))))
              (if (macro-length-mismatch-exception? _%e150563%_)
                  (macro-length-mismatch-exception-procedure _%e150563%_)
                  (error '"not an instance"
                         'length-mismatch-exception?
                         (cons 'length-mismatch-exception-procedure
                               (cons _%e150563%_ '())))))
            (if (macro-length-mismatch-exception? _%exn150560%_)
                (macro-length-mismatch-exception-procedure _%exn150560%_)
                (error '"not an instance"
                       'length-mismatch-exception?
                       (cons 'length-mismatch-exception-procedure
                             (cons _%exn150560%_ '())))))))
    (define mailbox-receive-timeout-exception?
      (lambda (_%exn150556%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150556%_))
            (let ((_%e150558%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150556%_ 'exception))))
              (macro-mailbox-receive-timeout-exception? _%e150558%_))
            (macro-mailbox-receive-timeout-exception? _%exn150556%_))))
    (define mailbox-receive-timeout-exception-arguments
      (lambda (_%exn150552%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150552%_))
            (let ((_%e150554%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150552%_ 'exception))))
              (if (macro-mailbox-receive-timeout-exception? _%e150554%_)
                  (macro-mailbox-receive-timeout-exception-arguments
                   _%e150554%_)
                  (error '"not an instance"
                         'mailbox-receive-timeout-exception?
                         (cons 'mailbox-receive-timeout-exception-arguments
                               (cons _%e150554%_ '())))))
            (if (macro-mailbox-receive-timeout-exception? _%exn150552%_)
                (macro-mailbox-receive-timeout-exception-arguments
                 _%exn150552%_)
                (error '"not an instance"
                       'mailbox-receive-timeout-exception?
                       (cons 'mailbox-receive-timeout-exception-arguments
                             (cons _%exn150552%_ '())))))))
    (define mailbox-receive-timeout-exception-procedure
      (lambda (_%exn150546%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150546%_))
            (let ((_%e150549%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150546%_ 'exception))))
              (if (macro-mailbox-receive-timeout-exception? _%e150549%_)
                  (macro-mailbox-receive-timeout-exception-procedure
                   _%e150549%_)
                  (error '"not an instance"
                         'mailbox-receive-timeout-exception?
                         (cons 'mailbox-receive-timeout-exception-procedure
                               (cons _%e150549%_ '())))))
            (if (macro-mailbox-receive-timeout-exception? _%exn150546%_)
                (macro-mailbox-receive-timeout-exception-procedure
                 _%exn150546%_)
                (error '"not an instance"
                       'mailbox-receive-timeout-exception?
                       (cons 'mailbox-receive-timeout-exception-procedure
                             (cons _%exn150546%_ '())))))))
    (define module-not-found-exception?
      (lambda (_%exn150542%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150542%_))
            (let ((_%e150544%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150542%_ 'exception))))
              (macro-module-not-found-exception? _%e150544%_))
            (macro-module-not-found-exception? _%exn150542%_))))
    (define module-not-found-exception-arguments
      (lambda (_%exn150538%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150538%_))
            (let ((_%e150540%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150538%_ 'exception))))
              (if (macro-module-not-found-exception? _%e150540%_)
                  (macro-module-not-found-exception-arguments _%e150540%_)
                  (error '"not an instance"
                         'module-not-found-exception?
                         (cons 'module-not-found-exception-arguments
                               (cons _%e150540%_ '())))))
            (if (macro-module-not-found-exception? _%exn150538%_)
                (macro-module-not-found-exception-arguments _%exn150538%_)
                (error '"not an instance"
                       'module-not-found-exception?
                       (cons 'module-not-found-exception-arguments
                             (cons _%exn150538%_ '())))))))
    (define module-not-found-exception-procedure
      (lambda (_%exn150532%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150532%_))
            (let ((_%e150535%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150532%_ 'exception))))
              (if (macro-module-not-found-exception? _%e150535%_)
                  (macro-module-not-found-exception-procedure _%e150535%_)
                  (error '"not an instance"
                         'module-not-found-exception?
                         (cons 'module-not-found-exception-procedure
                               (cons _%e150535%_ '())))))
            (if (macro-module-not-found-exception? _%exn150532%_)
                (macro-module-not-found-exception-procedure _%exn150532%_)
                (error '"not an instance"
                       'module-not-found-exception?
                       (cons 'module-not-found-exception-procedure
                             (cons _%exn150532%_ '())))))))
    (define multiple-c-return-exception?
      (lambda (_%exn150526%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150526%_))
            (let ((_%e150529%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150526%_ 'exception))))
              (macro-multiple-c-return-exception? _%e150529%_))
            (macro-multiple-c-return-exception? _%exn150526%_))))
    (define no-such-file-or-directory-exception?
      (lambda (_%exn150522%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150522%_))
            (let ((_%e150524%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150522%_ 'exception))))
              (macro-no-such-file-or-directory-exception? _%e150524%_))
            (macro-no-such-file-or-directory-exception? _%exn150522%_))))
    (define no-such-file-or-directory-exception-arguments
      (lambda (_%exn150518%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150518%_))
            (let ((_%e150520%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150518%_ 'exception))))
              (if (macro-no-such-file-or-directory-exception? _%e150520%_)
                  (macro-no-such-file-or-directory-exception-arguments
                   _%e150520%_)
                  (error '"not an instance"
                         'no-such-file-or-directory-exception?
                         (cons 'no-such-file-or-directory-exception-arguments
                               (cons _%e150520%_ '())))))
            (if (macro-no-such-file-or-directory-exception? _%exn150518%_)
                (macro-no-such-file-or-directory-exception-arguments
                 _%exn150518%_)
                (error '"not an instance"
                       'no-such-file-or-directory-exception?
                       (cons 'no-such-file-or-directory-exception-arguments
                             (cons _%exn150518%_ '())))))))
    (define no-such-file-or-directory-exception-procedure
      (lambda (_%exn150512%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150512%_))
            (let ((_%e150515%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150512%_ 'exception))))
              (if (macro-no-such-file-or-directory-exception? _%e150515%_)
                  (macro-no-such-file-or-directory-exception-procedure
                   _%e150515%_)
                  (error '"not an instance"
                         'no-such-file-or-directory-exception?
                         (cons 'no-such-file-or-directory-exception-procedure
                               (cons _%e150515%_ '())))))
            (if (macro-no-such-file-or-directory-exception? _%exn150512%_)
                (macro-no-such-file-or-directory-exception-procedure
                 _%exn150512%_)
                (error '"not an instance"
                       'no-such-file-or-directory-exception?
                       (cons 'no-such-file-or-directory-exception-procedure
                             (cons _%exn150512%_ '())))))))
    (define noncontinuable-exception?
      (lambda (_%exn150508%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150508%_))
            (let ((_%e150510%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150508%_ 'exception))))
              (macro-noncontinuable-exception? _%e150510%_))
            (macro-noncontinuable-exception? _%exn150508%_))))
    (define noncontinuable-exception-reason
      (lambda (_%exn150502%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150502%_))
            (let ((_%e150505%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150502%_ 'exception))))
              (if (macro-noncontinuable-exception? _%e150505%_)
                  (macro-noncontinuable-exception-reason _%e150505%_)
                  (error '"not an instance"
                         'noncontinuable-exception?
                         (cons 'noncontinuable-exception-reason
                               (cons _%e150505%_ '())))))
            (if (macro-noncontinuable-exception? _%exn150502%_)
                (macro-noncontinuable-exception-reason _%exn150502%_)
                (error '"not an instance"
                       'noncontinuable-exception?
                       (cons 'noncontinuable-exception-reason
                             (cons _%exn150502%_ '())))))))
    (define nonempty-input-port-character-buffer-exception?
      (lambda (_%exn150498%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150498%_))
            (let ((_%e150500%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150498%_ 'exception))))
              (macro-nonempty-input-port-character-buffer-exception?
               _%e150500%_))
            (macro-nonempty-input-port-character-buffer-exception?
             _%exn150498%_))))
    (define nonempty-input-port-character-buffer-exception-arguments
      (lambda (_%exn150494%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150494%_))
            (let ((_%e150496%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150494%_ 'exception))))
              (if (macro-nonempty-input-port-character-buffer-exception?
                   _%e150496%_)
                  (macro-nonempty-input-port-character-buffer-exception-arguments
                   _%e150496%_)
                  (error '"not an instance"
                         'nonempty-input-port-character-buffer-exception?
                         (cons 'nonempty-input-port-character-buffer-exception-arguments
                               (cons _%e150496%_ '())))))
            (if (macro-nonempty-input-port-character-buffer-exception?
                 _%exn150494%_)
                (macro-nonempty-input-port-character-buffer-exception-arguments
                 _%exn150494%_)
                (error '"not an instance"
                       'nonempty-input-port-character-buffer-exception?
                       (cons 'nonempty-input-port-character-buffer-exception-arguments
                             (cons _%exn150494%_ '())))))))
    (define nonempty-input-port-character-buffer-exception-procedure
      (lambda (_%exn150488%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150488%_))
            (let ((_%e150491%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150488%_ 'exception))))
              (if (macro-nonempty-input-port-character-buffer-exception?
                   _%e150491%_)
                  (macro-nonempty-input-port-character-buffer-exception-procedure
                   _%e150491%_)
                  (error '"not an instance"
                         'nonempty-input-port-character-buffer-exception?
                         (cons 'nonempty-input-port-character-buffer-exception-procedure
                               (cons _%e150491%_ '())))))
            (if (macro-nonempty-input-port-character-buffer-exception?
                 _%exn150488%_)
                (macro-nonempty-input-port-character-buffer-exception-procedure
                 _%exn150488%_)
                (error '"not an instance"
                       'nonempty-input-port-character-buffer-exception?
                       (cons 'nonempty-input-port-character-buffer-exception-procedure
                             (cons _%exn150488%_ '())))))))
    (define nonprocedure-operator-exception?
      (lambda (_%exn150484%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150484%_))
            (let ((_%e150486%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150484%_ 'exception))))
              (macro-nonprocedure-operator-exception? _%e150486%_))
            (macro-nonprocedure-operator-exception? _%exn150484%_))))
    (define nonprocedure-operator-exception-arguments
      (lambda (_%exn150480%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150480%_))
            (let ((_%e150482%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150480%_ 'exception))))
              (if (macro-nonprocedure-operator-exception? _%e150482%_)
                  (macro-nonprocedure-operator-exception-arguments _%e150482%_)
                  (error '"not an instance"
                         'nonprocedure-operator-exception?
                         (cons 'nonprocedure-operator-exception-arguments
                               (cons _%e150482%_ '())))))
            (if (macro-nonprocedure-operator-exception? _%exn150480%_)
                (macro-nonprocedure-operator-exception-arguments _%exn150480%_)
                (error '"not an instance"
                       'nonprocedure-operator-exception?
                       (cons 'nonprocedure-operator-exception-arguments
                             (cons _%exn150480%_ '())))))))
    (define nonprocedure-operator-exception-code
      (lambda (_%exn150476%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150476%_))
            (let ((_%e150478%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150476%_ 'exception))))
              (if (macro-nonprocedure-operator-exception? _%e150478%_)
                  (macro-nonprocedure-operator-exception-code _%e150478%_)
                  (error '"not an instance"
                         'nonprocedure-operator-exception?
                         (cons 'nonprocedure-operator-exception-code
                               (cons _%e150478%_ '())))))
            (if (macro-nonprocedure-operator-exception? _%exn150476%_)
                (macro-nonprocedure-operator-exception-code _%exn150476%_)
                (error '"not an instance"
                       'nonprocedure-operator-exception?
                       (cons 'nonprocedure-operator-exception-code
                             (cons _%exn150476%_ '())))))))
    (define nonprocedure-operator-exception-operator
      (lambda (_%exn150472%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150472%_))
            (let ((_%e150474%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150472%_ 'exception))))
              (if (macro-nonprocedure-operator-exception? _%e150474%_)
                  (macro-nonprocedure-operator-exception-operator _%e150474%_)
                  (error '"not an instance"
                         'nonprocedure-operator-exception?
                         (cons 'nonprocedure-operator-exception-operator
                               (cons _%e150474%_ '())))))
            (if (macro-nonprocedure-operator-exception? _%exn150472%_)
                (macro-nonprocedure-operator-exception-operator _%exn150472%_)
                (error '"not an instance"
                       'nonprocedure-operator-exception?
                       (cons 'nonprocedure-operator-exception-operator
                             (cons _%exn150472%_ '())))))))
    (define nonprocedure-operator-exception-rte
      (lambda (_%exn150466%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150466%_))
            (let ((_%e150469%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150466%_ 'exception))))
              (if (macro-nonprocedure-operator-exception? _%e150469%_)
                  (macro-nonprocedure-operator-exception-rte _%e150469%_)
                  (error '"not an instance"
                         'nonprocedure-operator-exception?
                         (cons 'nonprocedure-operator-exception-rte
                               (cons _%e150469%_ '())))))
            (if (macro-nonprocedure-operator-exception? _%exn150466%_)
                (macro-nonprocedure-operator-exception-rte _%exn150466%_)
                (error '"not an instance"
                       'nonprocedure-operator-exception?
                       (cons 'nonprocedure-operator-exception-rte
                             (cons _%exn150466%_ '())))))))
    (define not-in-compilation-context-exception?
      (lambda (_%exn150462%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150462%_))
            (let ((_%e150464%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150462%_ 'exception))))
              (macro-not-in-compilation-context-exception? _%e150464%_))
            (macro-not-in-compilation-context-exception? _%exn150462%_))))
    (define not-in-compilation-context-exception-arguments
      (lambda (_%exn150458%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150458%_))
            (let ((_%e150460%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150458%_ 'exception))))
              (if (macro-not-in-compilation-context-exception? _%e150460%_)
                  (macro-not-in-compilation-context-exception-arguments
                   _%e150460%_)
                  (error '"not an instance"
                         'not-in-compilation-context-exception?
                         (cons 'not-in-compilation-context-exception-arguments
                               (cons _%e150460%_ '())))))
            (if (macro-not-in-compilation-context-exception? _%exn150458%_)
                (macro-not-in-compilation-context-exception-arguments
                 _%exn150458%_)
                (error '"not an instance"
                       'not-in-compilation-context-exception?
                       (cons 'not-in-compilation-context-exception-arguments
                             (cons _%exn150458%_ '())))))))
    (define not-in-compilation-context-exception-procedure
      (lambda (_%exn150452%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150452%_))
            (let ((_%e150455%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150452%_ 'exception))))
              (if (macro-not-in-compilation-context-exception? _%e150455%_)
                  (macro-not-in-compilation-context-exception-procedure
                   _%e150455%_)
                  (error '"not an instance"
                         'not-in-compilation-context-exception?
                         (cons 'not-in-compilation-context-exception-procedure
                               (cons _%e150455%_ '())))))
            (if (macro-not-in-compilation-context-exception? _%exn150452%_)
                (macro-not-in-compilation-context-exception-procedure
                 _%exn150452%_)
                (error '"not an instance"
                       'not-in-compilation-context-exception?
                       (cons 'not-in-compilation-context-exception-procedure
                             (cons _%exn150452%_ '())))))))
    (define number-of-arguments-limit-exception?
      (lambda (_%exn150448%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150448%_))
            (let ((_%e150450%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150448%_ 'exception))))
              (macro-number-of-arguments-limit-exception? _%e150450%_))
            (macro-number-of-arguments-limit-exception? _%exn150448%_))))
    (define number-of-arguments-limit-exception-arguments
      (lambda (_%exn150444%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150444%_))
            (let ((_%e150446%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150444%_ 'exception))))
              (if (macro-number-of-arguments-limit-exception? _%e150446%_)
                  (macro-number-of-arguments-limit-exception-arguments
                   _%e150446%_)
                  (error '"not an instance"
                         'number-of-arguments-limit-exception?
                         (cons 'number-of-arguments-limit-exception-arguments
                               (cons _%e150446%_ '())))))
            (if (macro-number-of-arguments-limit-exception? _%exn150444%_)
                (macro-number-of-arguments-limit-exception-arguments
                 _%exn150444%_)
                (error '"not an instance"
                       'number-of-arguments-limit-exception?
                       (cons 'number-of-arguments-limit-exception-arguments
                             (cons _%exn150444%_ '())))))))
    (define number-of-arguments-limit-exception-procedure
      (lambda (_%exn150438%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150438%_))
            (let ((_%e150441%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150438%_ 'exception))))
              (if (macro-number-of-arguments-limit-exception? _%e150441%_)
                  (macro-number-of-arguments-limit-exception-procedure
                   _%e150441%_)
                  (error '"not an instance"
                         'number-of-arguments-limit-exception?
                         (cons 'number-of-arguments-limit-exception-procedure
                               (cons _%e150441%_ '())))))
            (if (macro-number-of-arguments-limit-exception? _%exn150438%_)
                (macro-number-of-arguments-limit-exception-procedure
                 _%exn150438%_)
                (error '"not an instance"
                       'number-of-arguments-limit-exception?
                       (cons 'number-of-arguments-limit-exception-procedure
                             (cons _%exn150438%_ '())))))))
    (define os-exception?
      (lambda (_%exn150434%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150434%_))
            (let ((_%e150436%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150434%_ 'exception))))
              (macro-os-exception? _%e150436%_))
            (macro-os-exception? _%exn150434%_))))
    (define os-exception-arguments
      (lambda (_%exn150430%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150430%_))
            (let ((_%e150432%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150430%_ 'exception))))
              (if (macro-os-exception? _%e150432%_)
                  (macro-os-exception-arguments _%e150432%_)
                  (error '"not an instance"
                         'os-exception?
                         (cons 'os-exception-arguments
                               (cons _%e150432%_ '())))))
            (if (macro-os-exception? _%exn150430%_)
                (macro-os-exception-arguments _%exn150430%_)
                (error '"not an instance"
                       'os-exception?
                       (cons 'os-exception-arguments
                             (cons _%exn150430%_ '())))))))
    (define os-exception-code
      (lambda (_%exn150426%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150426%_))
            (let ((_%e150428%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150426%_ 'exception))))
              (if (macro-os-exception? _%e150428%_)
                  (macro-os-exception-code _%e150428%_)
                  (error '"not an instance"
                         'os-exception?
                         (cons 'os-exception-code (cons _%e150428%_ '())))))
            (if (macro-os-exception? _%exn150426%_)
                (macro-os-exception-code _%exn150426%_)
                (error '"not an instance"
                       'os-exception?
                       (cons 'os-exception-code (cons _%exn150426%_ '())))))))
    (define os-exception-message
      (lambda (_%exn150422%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150422%_))
            (let ((_%e150424%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150422%_ 'exception))))
              (if (macro-os-exception? _%e150424%_)
                  (macro-os-exception-message _%e150424%_)
                  (error '"not an instance"
                         'os-exception?
                         (cons 'os-exception-message (cons _%e150424%_ '())))))
            (if (macro-os-exception? _%exn150422%_)
                (macro-os-exception-message _%exn150422%_)
                (error '"not an instance"
                       'os-exception?
                       (cons 'os-exception-message
                             (cons _%exn150422%_ '())))))))
    (define os-exception-procedure
      (lambda (_%exn150416%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150416%_))
            (let ((_%e150419%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150416%_ 'exception))))
              (if (macro-os-exception? _%e150419%_)
                  (macro-os-exception-procedure _%e150419%_)
                  (error '"not an instance"
                         'os-exception?
                         (cons 'os-exception-procedure
                               (cons _%e150419%_ '())))))
            (if (macro-os-exception? _%exn150416%_)
                (macro-os-exception-procedure _%exn150416%_)
                (error '"not an instance"
                       'os-exception?
                       (cons 'os-exception-procedure
                             (cons _%exn150416%_ '())))))))
    (define permission-denied-exception?
      (lambda (_%exn150412%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150412%_))
            (let ((_%e150414%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150412%_ 'exception))))
              (macro-permission-denied-exception? _%e150414%_))
            (macro-permission-denied-exception? _%exn150412%_))))
    (define permission-denied-exception-arguments
      (lambda (_%exn150408%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150408%_))
            (let ((_%e150410%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150408%_ 'exception))))
              (if (macro-permission-denied-exception? _%e150410%_)
                  (macro-permission-denied-exception-arguments _%e150410%_)
                  (error '"not an instance"
                         'permission-denied-exception?
                         (cons 'permission-denied-exception-arguments
                               (cons _%e150410%_ '())))))
            (if (macro-permission-denied-exception? _%exn150408%_)
                (macro-permission-denied-exception-arguments _%exn150408%_)
                (error '"not an instance"
                       'permission-denied-exception?
                       (cons 'permission-denied-exception-arguments
                             (cons _%exn150408%_ '())))))))
    (define permission-denied-exception-procedure
      (lambda (_%exn150402%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150402%_))
            (let ((_%e150405%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150402%_ 'exception))))
              (if (macro-permission-denied-exception? _%e150405%_)
                  (macro-permission-denied-exception-procedure _%e150405%_)
                  (error '"not an instance"
                         'permission-denied-exception?
                         (cons 'permission-denied-exception-procedure
                               (cons _%e150405%_ '())))))
            (if (macro-permission-denied-exception? _%exn150402%_)
                (macro-permission-denied-exception-procedure _%exn150402%_)
                (error '"not an instance"
                       'permission-denied-exception?
                       (cons 'permission-denied-exception-procedure
                             (cons _%exn150402%_ '())))))))
    (define range-exception?
      (lambda (_%exn150398%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150398%_))
            (let ((_%e150400%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150398%_ 'exception))))
              (macro-range-exception? _%e150400%_))
            (macro-range-exception? _%exn150398%_))))
    (define range-exception-arg-id
      (lambda (_%exn150394%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150394%_))
            (let ((_%e150396%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150394%_ 'exception))))
              (if (macro-range-exception? _%e150396%_)
                  (macro-range-exception-arg-id _%e150396%_)
                  (error '"not an instance"
                         'range-exception?
                         (cons 'range-exception-arg-id
                               (cons _%e150396%_ '())))))
            (if (macro-range-exception? _%exn150394%_)
                (macro-range-exception-arg-id _%exn150394%_)
                (error '"not an instance"
                       'range-exception?
                       (cons 'range-exception-arg-id
                             (cons _%exn150394%_ '())))))))
    (define range-exception-arguments
      (lambda (_%exn150390%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150390%_))
            (let ((_%e150392%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150390%_ 'exception))))
              (if (macro-range-exception? _%e150392%_)
                  (macro-range-exception-arguments _%e150392%_)
                  (error '"not an instance"
                         'range-exception?
                         (cons 'range-exception-arguments
                               (cons _%e150392%_ '())))))
            (if (macro-range-exception? _%exn150390%_)
                (macro-range-exception-arguments _%exn150390%_)
                (error '"not an instance"
                       'range-exception?
                       (cons 'range-exception-arguments
                             (cons _%exn150390%_ '())))))))
    (define range-exception-procedure
      (lambda (_%exn150384%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150384%_))
            (let ((_%e150387%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150384%_ 'exception))))
              (if (macro-range-exception? _%e150387%_)
                  (macro-range-exception-procedure _%e150387%_)
                  (error '"not an instance"
                         'range-exception?
                         (cons 'range-exception-procedure
                               (cons _%e150387%_ '())))))
            (if (macro-range-exception? _%exn150384%_)
                (macro-range-exception-procedure _%exn150384%_)
                (error '"not an instance"
                       'range-exception?
                       (cons 'range-exception-procedure
                             (cons _%exn150384%_ '())))))))
    (define rpc-remote-error-exception?
      (lambda (_%exn150380%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150380%_))
            (let ((_%e150382%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150380%_ 'exception))))
              (macro-rpc-remote-error-exception? _%e150382%_))
            (macro-rpc-remote-error-exception? _%exn150380%_))))
    (define rpc-remote-error-exception-arguments
      (lambda (_%exn150376%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150376%_))
            (let ((_%e150378%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150376%_ 'exception))))
              (if (macro-rpc-remote-error-exception? _%e150378%_)
                  (macro-rpc-remote-error-exception-arguments _%e150378%_)
                  (error '"not an instance"
                         'rpc-remote-error-exception?
                         (cons 'rpc-remote-error-exception-arguments
                               (cons _%e150378%_ '())))))
            (if (macro-rpc-remote-error-exception? _%exn150376%_)
                (macro-rpc-remote-error-exception-arguments _%exn150376%_)
                (error '"not an instance"
                       'rpc-remote-error-exception?
                       (cons 'rpc-remote-error-exception-arguments
                             (cons _%exn150376%_ '())))))))
    (define rpc-remote-error-exception-message
      (lambda (_%exn150372%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150372%_))
            (let ((_%e150374%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150372%_ 'exception))))
              (if (macro-rpc-remote-error-exception? _%e150374%_)
                  (macro-rpc-remote-error-exception-message _%e150374%_)
                  (error '"not an instance"
                         'rpc-remote-error-exception?
                         (cons 'rpc-remote-error-exception-message
                               (cons _%e150374%_ '())))))
            (if (macro-rpc-remote-error-exception? _%exn150372%_)
                (macro-rpc-remote-error-exception-message _%exn150372%_)
                (error '"not an instance"
                       'rpc-remote-error-exception?
                       (cons 'rpc-remote-error-exception-message
                             (cons _%exn150372%_ '())))))))
    (define rpc-remote-error-exception-procedure
      (lambda (_%exn150366%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150366%_))
            (let ((_%e150369%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150366%_ 'exception))))
              (if (macro-rpc-remote-error-exception? _%e150369%_)
                  (macro-rpc-remote-error-exception-procedure _%e150369%_)
                  (error '"not an instance"
                         'rpc-remote-error-exception?
                         (cons 'rpc-remote-error-exception-procedure
                               (cons _%e150369%_ '())))))
            (if (macro-rpc-remote-error-exception? _%exn150366%_)
                (macro-rpc-remote-error-exception-procedure _%exn150366%_)
                (error '"not an instance"
                       'rpc-remote-error-exception?
                       (cons 'rpc-remote-error-exception-procedure
                             (cons _%exn150366%_ '())))))))
    (define scheduler-exception?
      (lambda (_%exn150362%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150362%_))
            (let ((_%e150364%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150362%_ 'exception))))
              (macro-scheduler-exception? _%e150364%_))
            (macro-scheduler-exception? _%exn150362%_))))
    (define scheduler-exception-reason
      (lambda (_%exn150356%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150356%_))
            (let ((_%e150359%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150356%_ 'exception))))
              (if (macro-scheduler-exception? _%e150359%_)
                  (macro-scheduler-exception-reason _%e150359%_)
                  (error '"not an instance"
                         'scheduler-exception?
                         (cons 'scheduler-exception-reason
                               (cons _%e150359%_ '())))))
            (if (macro-scheduler-exception? _%exn150356%_)
                (macro-scheduler-exception-reason _%exn150356%_)
                (error '"not an instance"
                       'scheduler-exception?
                       (cons 'scheduler-exception-reason
                             (cons _%exn150356%_ '())))))))
    (define sfun-conversion-exception?
      (lambda (_%exn150352%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150352%_))
            (let ((_%e150354%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150352%_ 'exception))))
              (macro-sfun-conversion-exception? _%e150354%_))
            (macro-sfun-conversion-exception? _%exn150352%_))))
    (define sfun-conversion-exception-arguments
      (lambda (_%exn150348%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150348%_))
            (let ((_%e150350%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150348%_ 'exception))))
              (if (macro-sfun-conversion-exception? _%e150350%_)
                  (macro-sfun-conversion-exception-arguments _%e150350%_)
                  (error '"not an instance"
                         'sfun-conversion-exception?
                         (cons 'sfun-conversion-exception-arguments
                               (cons _%e150350%_ '())))))
            (if (macro-sfun-conversion-exception? _%exn150348%_)
                (macro-sfun-conversion-exception-arguments _%exn150348%_)
                (error '"not an instance"
                       'sfun-conversion-exception?
                       (cons 'sfun-conversion-exception-arguments
                             (cons _%exn150348%_ '())))))))
    (define sfun-conversion-exception-code
      (lambda (_%exn150344%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150344%_))
            (let ((_%e150346%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150344%_ 'exception))))
              (if (macro-sfun-conversion-exception? _%e150346%_)
                  (macro-sfun-conversion-exception-code _%e150346%_)
                  (error '"not an instance"
                         'sfun-conversion-exception?
                         (cons 'sfun-conversion-exception-code
                               (cons _%e150346%_ '())))))
            (if (macro-sfun-conversion-exception? _%exn150344%_)
                (macro-sfun-conversion-exception-code _%exn150344%_)
                (error '"not an instance"
                       'sfun-conversion-exception?
                       (cons 'sfun-conversion-exception-code
                             (cons _%exn150344%_ '())))))))
    (define sfun-conversion-exception-message
      (lambda (_%exn150340%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150340%_))
            (let ((_%e150342%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150340%_ 'exception))))
              (if (macro-sfun-conversion-exception? _%e150342%_)
                  (macro-sfun-conversion-exception-message _%e150342%_)
                  (error '"not an instance"
                         'sfun-conversion-exception?
                         (cons 'sfun-conversion-exception-message
                               (cons _%e150342%_ '())))))
            (if (macro-sfun-conversion-exception? _%exn150340%_)
                (macro-sfun-conversion-exception-message _%exn150340%_)
                (error '"not an instance"
                       'sfun-conversion-exception?
                       (cons 'sfun-conversion-exception-message
                             (cons _%exn150340%_ '())))))))
    (define sfun-conversion-exception-procedure
      (lambda (_%exn150334%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150334%_))
            (let ((_%e150337%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150334%_ 'exception))))
              (if (macro-sfun-conversion-exception? _%e150337%_)
                  (macro-sfun-conversion-exception-procedure _%e150337%_)
                  (error '"not an instance"
                         'sfun-conversion-exception?
                         (cons 'sfun-conversion-exception-procedure
                               (cons _%e150337%_ '())))))
            (if (macro-sfun-conversion-exception? _%exn150334%_)
                (macro-sfun-conversion-exception-procedure _%exn150334%_)
                (error '"not an instance"
                       'sfun-conversion-exception?
                       (cons 'sfun-conversion-exception-procedure
                             (cons _%exn150334%_ '())))))))
    (define stack-overflow-exception?
      (lambda (_%exn150328%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150328%_))
            (let ((_%e150331%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150328%_ 'exception))))
              (macro-stack-overflow-exception? _%e150331%_))
            (macro-stack-overflow-exception? _%exn150328%_))))
    (define started-thread-exception?
      (lambda (_%exn150324%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150324%_))
            (let ((_%e150326%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150324%_ 'exception))))
              (macro-started-thread-exception? _%e150326%_))
            (macro-started-thread-exception? _%exn150324%_))))
    (define started-thread-exception-arguments
      (lambda (_%exn150320%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150320%_))
            (let ((_%e150322%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150320%_ 'exception))))
              (if (macro-started-thread-exception? _%e150322%_)
                  (macro-started-thread-exception-arguments _%e150322%_)
                  (error '"not an instance"
                         'started-thread-exception?
                         (cons 'started-thread-exception-arguments
                               (cons _%e150322%_ '())))))
            (if (macro-started-thread-exception? _%exn150320%_)
                (macro-started-thread-exception-arguments _%exn150320%_)
                (error '"not an instance"
                       'started-thread-exception?
                       (cons 'started-thread-exception-arguments
                             (cons _%exn150320%_ '())))))))
    (define started-thread-exception-procedure
      (lambda (_%exn150314%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150314%_))
            (let ((_%e150317%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150314%_ 'exception))))
              (if (macro-started-thread-exception? _%e150317%_)
                  (macro-started-thread-exception-procedure _%e150317%_)
                  (error '"not an instance"
                         'started-thread-exception?
                         (cons 'started-thread-exception-procedure
                               (cons _%e150317%_ '())))))
            (if (macro-started-thread-exception? _%exn150314%_)
                (macro-started-thread-exception-procedure _%exn150314%_)
                (error '"not an instance"
                       'started-thread-exception?
                       (cons 'started-thread-exception-procedure
                             (cons _%exn150314%_ '())))))))
    (define terminated-thread-exception?
      (lambda (_%exn150310%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150310%_))
            (let ((_%e150312%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150310%_ 'exception))))
              (macro-terminated-thread-exception? _%e150312%_))
            (macro-terminated-thread-exception? _%exn150310%_))))
    (define terminated-thread-exception-arguments
      (lambda (_%exn150306%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150306%_))
            (let ((_%e150308%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150306%_ 'exception))))
              (if (macro-terminated-thread-exception? _%e150308%_)
                  (macro-terminated-thread-exception-arguments _%e150308%_)
                  (error '"not an instance"
                         'terminated-thread-exception?
                         (cons 'terminated-thread-exception-arguments
                               (cons _%e150308%_ '())))))
            (if (macro-terminated-thread-exception? _%exn150306%_)
                (macro-terminated-thread-exception-arguments _%exn150306%_)
                (error '"not an instance"
                       'terminated-thread-exception?
                       (cons 'terminated-thread-exception-arguments
                             (cons _%exn150306%_ '())))))))
    (define terminated-thread-exception-procedure
      (lambda (_%exn150300%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150300%_))
            (let ((_%e150303%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150300%_ 'exception))))
              (if (macro-terminated-thread-exception? _%e150303%_)
                  (macro-terminated-thread-exception-procedure _%e150303%_)
                  (error '"not an instance"
                         'terminated-thread-exception?
                         (cons 'terminated-thread-exception-procedure
                               (cons _%e150303%_ '())))))
            (if (macro-terminated-thread-exception? _%exn150300%_)
                (macro-terminated-thread-exception-procedure _%exn150300%_)
                (error '"not an instance"
                       'terminated-thread-exception?
                       (cons 'terminated-thread-exception-procedure
                             (cons _%exn150300%_ '())))))))
    (define type-exception?
      (lambda (_%exn150296%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150296%_))
            (let ((_%e150298%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150296%_ 'exception))))
              (macro-type-exception? _%e150298%_))
            (macro-type-exception? _%exn150296%_))))
    (define type-exception-arg-id
      (lambda (_%exn150292%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150292%_))
            (let ((_%e150294%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150292%_ 'exception))))
              (if (macro-type-exception? _%e150294%_)
                  (macro-type-exception-arg-id _%e150294%_)
                  (error '"not an instance"
                         'type-exception?
                         (cons 'type-exception-arg-id
                               (cons _%e150294%_ '())))))
            (if (macro-type-exception? _%exn150292%_)
                (macro-type-exception-arg-id _%exn150292%_)
                (error '"not an instance"
                       'type-exception?
                       (cons 'type-exception-arg-id
                             (cons _%exn150292%_ '())))))))
    (define type-exception-arguments
      (lambda (_%exn150288%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150288%_))
            (let ((_%e150290%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150288%_ 'exception))))
              (if (macro-type-exception? _%e150290%_)
                  (macro-type-exception-arguments _%e150290%_)
                  (error '"not an instance"
                         'type-exception?
                         (cons 'type-exception-arguments
                               (cons _%e150290%_ '())))))
            (if (macro-type-exception? _%exn150288%_)
                (macro-type-exception-arguments _%exn150288%_)
                (error '"not an instance"
                       'type-exception?
                       (cons 'type-exception-arguments
                             (cons _%exn150288%_ '())))))))
    (define type-exception-procedure
      (lambda (_%exn150284%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150284%_))
            (let ((_%e150286%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150284%_ 'exception))))
              (if (macro-type-exception? _%e150286%_)
                  (macro-type-exception-procedure _%e150286%_)
                  (error '"not an instance"
                         'type-exception?
                         (cons 'type-exception-procedure
                               (cons _%e150286%_ '())))))
            (if (macro-type-exception? _%exn150284%_)
                (macro-type-exception-procedure _%exn150284%_)
                (error '"not an instance"
                       'type-exception?
                       (cons 'type-exception-procedure
                             (cons _%exn150284%_ '())))))))
    (define type-exception-type-id
      (lambda (_%exn150278%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150278%_))
            (let ((_%e150281%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150278%_ 'exception))))
              (if (macro-type-exception? _%e150281%_)
                  (macro-type-exception-type-id _%e150281%_)
                  (error '"not an instance"
                         'type-exception?
                         (cons 'type-exception-type-id
                               (cons _%e150281%_ '())))))
            (if (macro-type-exception? _%exn150278%_)
                (macro-type-exception-type-id _%exn150278%_)
                (error '"not an instance"
                       'type-exception?
                       (cons 'type-exception-type-id
                             (cons _%exn150278%_ '())))))))
    (define unbound-global-exception?
      (lambda (_%exn150274%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150274%_))
            (let ((_%e150276%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150274%_ 'exception))))
              (macro-unbound-global-exception? _%e150276%_))
            (macro-unbound-global-exception? _%exn150274%_))))
    (define unbound-global-exception-code
      (lambda (_%exn150270%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150270%_))
            (let ((_%e150272%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150270%_ 'exception))))
              (if (macro-unbound-global-exception? _%e150272%_)
                  (macro-unbound-global-exception-code _%e150272%_)
                  (error '"not an instance"
                         'unbound-global-exception?
                         (cons 'unbound-global-exception-code
                               (cons _%e150272%_ '())))))
            (if (macro-unbound-global-exception? _%exn150270%_)
                (macro-unbound-global-exception-code _%exn150270%_)
                (error '"not an instance"
                       'unbound-global-exception?
                       (cons 'unbound-global-exception-code
                             (cons _%exn150270%_ '())))))))
    (define unbound-global-exception-rte
      (lambda (_%exn150266%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150266%_))
            (let ((_%e150268%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150266%_ 'exception))))
              (if (macro-unbound-global-exception? _%e150268%_)
                  (macro-unbound-global-exception-rte _%e150268%_)
                  (error '"not an instance"
                         'unbound-global-exception?
                         (cons 'unbound-global-exception-rte
                               (cons _%e150268%_ '())))))
            (if (macro-unbound-global-exception? _%exn150266%_)
                (macro-unbound-global-exception-rte _%exn150266%_)
                (error '"not an instance"
                       'unbound-global-exception?
                       (cons 'unbound-global-exception-rte
                             (cons _%exn150266%_ '())))))))
    (define unbound-global-exception-variable
      (lambda (_%exn150260%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150260%_))
            (let ((_%e150263%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150260%_ 'exception))))
              (if (macro-unbound-global-exception? _%e150263%_)
                  (macro-unbound-global-exception-variable _%e150263%_)
                  (error '"not an instance"
                         'unbound-global-exception?
                         (cons 'unbound-global-exception-variable
                               (cons _%e150263%_ '())))))
            (if (macro-unbound-global-exception? _%exn150260%_)
                (macro-unbound-global-exception-variable _%exn150260%_)
                (error '"not an instance"
                       'unbound-global-exception?
                       (cons 'unbound-global-exception-variable
                             (cons _%exn150260%_ '())))))))
    (define unbound-key-exception?
      (lambda (_%exn150256%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150256%_))
            (let ((_%e150258%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150256%_ 'exception))))
              (macro-unbound-key-exception? _%e150258%_))
            (macro-unbound-key-exception? _%exn150256%_))))
    (define unbound-key-exception-arguments
      (lambda (_%exn150252%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150252%_))
            (let ((_%e150254%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150252%_ 'exception))))
              (if (macro-unbound-key-exception? _%e150254%_)
                  (macro-unbound-key-exception-arguments _%e150254%_)
                  (error '"not an instance"
                         'unbound-key-exception?
                         (cons 'unbound-key-exception-arguments
                               (cons _%e150254%_ '())))))
            (if (macro-unbound-key-exception? _%exn150252%_)
                (macro-unbound-key-exception-arguments _%exn150252%_)
                (error '"not an instance"
                       'unbound-key-exception?
                       (cons 'unbound-key-exception-arguments
                             (cons _%exn150252%_ '())))))))
    (define unbound-key-exception-procedure
      (lambda (_%exn150246%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150246%_))
            (let ((_%e150249%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150246%_ 'exception))))
              (if (macro-unbound-key-exception? _%e150249%_)
                  (macro-unbound-key-exception-procedure _%e150249%_)
                  (error '"not an instance"
                         'unbound-key-exception?
                         (cons 'unbound-key-exception-procedure
                               (cons _%e150249%_ '())))))
            (if (macro-unbound-key-exception? _%exn150246%_)
                (macro-unbound-key-exception-procedure _%exn150246%_)
                (error '"not an instance"
                       'unbound-key-exception?
                       (cons 'unbound-key-exception-procedure
                             (cons _%exn150246%_ '())))))))
    (define unbound-os-environment-variable-exception?
      (lambda (_%exn150242%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150242%_))
            (let ((_%e150244%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150242%_ 'exception))))
              (macro-unbound-os-environment-variable-exception? _%e150244%_))
            (macro-unbound-os-environment-variable-exception? _%exn150242%_))))
    (define unbound-os-environment-variable-exception-arguments
      (lambda (_%exn150238%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150238%_))
            (let ((_%e150240%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150238%_ 'exception))))
              (if (macro-unbound-os-environment-variable-exception?
                   _%e150240%_)
                  (macro-unbound-os-environment-variable-exception-arguments
                   _%e150240%_)
                  (error '"not an instance"
                         'unbound-os-environment-variable-exception?
                         (cons 'unbound-os-environment-variable-exception-arguments
                               (cons _%e150240%_ '())))))
            (if (macro-unbound-os-environment-variable-exception?
                 _%exn150238%_)
                (macro-unbound-os-environment-variable-exception-arguments
                 _%exn150238%_)
                (error '"not an instance"
                       'unbound-os-environment-variable-exception?
                       (cons 'unbound-os-environment-variable-exception-arguments
                             (cons _%exn150238%_ '())))))))
    (define unbound-os-environment-variable-exception-procedure
      (lambda (_%exn150232%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150232%_))
            (let ((_%e150235%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150232%_ 'exception))))
              (if (macro-unbound-os-environment-variable-exception?
                   _%e150235%_)
                  (macro-unbound-os-environment-variable-exception-procedure
                   _%e150235%_)
                  (error '"not an instance"
                         'unbound-os-environment-variable-exception?
                         (cons 'unbound-os-environment-variable-exception-procedure
                               (cons _%e150235%_ '())))))
            (if (macro-unbound-os-environment-variable-exception?
                 _%exn150232%_)
                (macro-unbound-os-environment-variable-exception-procedure
                 _%exn150232%_)
                (error '"not an instance"
                       'unbound-os-environment-variable-exception?
                       (cons 'unbound-os-environment-variable-exception-procedure
                             (cons _%exn150232%_ '())))))))
    (define unbound-serial-number-exception?
      (lambda (_%exn150228%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150228%_))
            (let ((_%e150230%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150228%_ 'exception))))
              (macro-unbound-serial-number-exception? _%e150230%_))
            (macro-unbound-serial-number-exception? _%exn150228%_))))
    (define unbound-serial-number-exception-arguments
      (lambda (_%exn150224%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150224%_))
            (let ((_%e150226%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150224%_ 'exception))))
              (if (macro-unbound-serial-number-exception? _%e150226%_)
                  (macro-unbound-serial-number-exception-arguments _%e150226%_)
                  (error '"not an instance"
                         'unbound-serial-number-exception?
                         (cons 'unbound-serial-number-exception-arguments
                               (cons _%e150226%_ '())))))
            (if (macro-unbound-serial-number-exception? _%exn150224%_)
                (macro-unbound-serial-number-exception-arguments _%exn150224%_)
                (error '"not an instance"
                       'unbound-serial-number-exception?
                       (cons 'unbound-serial-number-exception-arguments
                             (cons _%exn150224%_ '())))))))
    (define unbound-serial-number-exception-procedure
      (lambda (_%exn150218%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150218%_))
            (let ((_%e150221%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150218%_ 'exception))))
              (if (macro-unbound-serial-number-exception? _%e150221%_)
                  (macro-unbound-serial-number-exception-procedure _%e150221%_)
                  (error '"not an instance"
                         'unbound-serial-number-exception?
                         (cons 'unbound-serial-number-exception-procedure
                               (cons _%e150221%_ '())))))
            (if (macro-unbound-serial-number-exception? _%exn150218%_)
                (macro-unbound-serial-number-exception-procedure _%exn150218%_)
                (error '"not an instance"
                       'unbound-serial-number-exception?
                       (cons 'unbound-serial-number-exception-procedure
                             (cons _%exn150218%_ '())))))))
    (define uncaught-exception?
      (lambda (_%exn150214%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150214%_))
            (let ((_%e150216%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150214%_ 'exception))))
              (macro-uncaught-exception? _%e150216%_))
            (macro-uncaught-exception? _%exn150214%_))))
    (define uncaught-exception-arguments
      (lambda (_%exn150210%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150210%_))
            (let ((_%e150212%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150210%_ 'exception))))
              (if (macro-uncaught-exception? _%e150212%_)
                  (macro-uncaught-exception-arguments _%e150212%_)
                  (error '"not an instance"
                         'uncaught-exception?
                         (cons 'uncaught-exception-arguments
                               (cons _%e150212%_ '())))))
            (if (macro-uncaught-exception? _%exn150210%_)
                (macro-uncaught-exception-arguments _%exn150210%_)
                (error '"not an instance"
                       'uncaught-exception?
                       (cons 'uncaught-exception-arguments
                             (cons _%exn150210%_ '())))))))
    (define uncaught-exception-procedure
      (lambda (_%exn150206%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150206%_))
            (let ((_%e150208%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150206%_ 'exception))))
              (if (macro-uncaught-exception? _%e150208%_)
                  (macro-uncaught-exception-procedure _%e150208%_)
                  (error '"not an instance"
                         'uncaught-exception?
                         (cons 'uncaught-exception-procedure
                               (cons _%e150208%_ '())))))
            (if (macro-uncaught-exception? _%exn150206%_)
                (macro-uncaught-exception-procedure _%exn150206%_)
                (error '"not an instance"
                       'uncaught-exception?
                       (cons 'uncaught-exception-procedure
                             (cons _%exn150206%_ '())))))))
    (define uncaught-exception-reason
      (lambda (_%exn150200%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150200%_))
            (let ((_%e150203%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150200%_ 'exception))))
              (if (macro-uncaught-exception? _%e150203%_)
                  (macro-uncaught-exception-reason _%e150203%_)
                  (error '"not an instance"
                         'uncaught-exception?
                         (cons 'uncaught-exception-reason
                               (cons _%e150203%_ '())))))
            (if (macro-uncaught-exception? _%exn150200%_)
                (macro-uncaught-exception-reason _%exn150200%_)
                (error '"not an instance"
                       'uncaught-exception?
                       (cons 'uncaught-exception-reason
                             (cons _%exn150200%_ '())))))))
    (define uninitialized-thread-exception?
      (lambda (_%exn150196%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150196%_))
            (let ((_%e150198%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150196%_ 'exception))))
              (macro-uninitialized-thread-exception? _%e150198%_))
            (macro-uninitialized-thread-exception? _%exn150196%_))))
    (define uninitialized-thread-exception-arguments
      (lambda (_%exn150192%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150192%_))
            (let ((_%e150194%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150192%_ 'exception))))
              (if (macro-uninitialized-thread-exception? _%e150194%_)
                  (macro-uninitialized-thread-exception-arguments _%e150194%_)
                  (error '"not an instance"
                         'uninitialized-thread-exception?
                         (cons 'uninitialized-thread-exception-arguments
                               (cons _%e150194%_ '())))))
            (if (macro-uninitialized-thread-exception? _%exn150192%_)
                (macro-uninitialized-thread-exception-arguments _%exn150192%_)
                (error '"not an instance"
                       'uninitialized-thread-exception?
                       (cons 'uninitialized-thread-exception-arguments
                             (cons _%exn150192%_ '())))))))
    (define uninitialized-thread-exception-procedure
      (lambda (_%exn150186%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150186%_))
            (let ((_%e150189%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150186%_ 'exception))))
              (if (macro-uninitialized-thread-exception? _%e150189%_)
                  (macro-uninitialized-thread-exception-procedure _%e150189%_)
                  (error '"not an instance"
                         'uninitialized-thread-exception?
                         (cons 'uninitialized-thread-exception-procedure
                               (cons _%e150189%_ '())))))
            (if (macro-uninitialized-thread-exception? _%exn150186%_)
                (macro-uninitialized-thread-exception-procedure _%exn150186%_)
                (error '"not an instance"
                       'uninitialized-thread-exception?
                       (cons 'uninitialized-thread-exception-procedure
                             (cons _%exn150186%_ '())))))))
    (define unknown-keyword-argument-exception?
      (lambda (_%exn150182%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150182%_))
            (let ((_%e150184%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150182%_ 'exception))))
              (macro-unknown-keyword-argument-exception? _%e150184%_))
            (macro-unknown-keyword-argument-exception? _%exn150182%_))))
    (define unknown-keyword-argument-exception-arguments
      (lambda (_%exn150178%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150178%_))
            (let ((_%e150180%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150178%_ 'exception))))
              (if (macro-unknown-keyword-argument-exception? _%e150180%_)
                  (macro-unknown-keyword-argument-exception-arguments
                   _%e150180%_)
                  (error '"not an instance"
                         'unknown-keyword-argument-exception?
                         (cons 'unknown-keyword-argument-exception-arguments
                               (cons _%e150180%_ '())))))
            (if (macro-unknown-keyword-argument-exception? _%exn150178%_)
                (macro-unknown-keyword-argument-exception-arguments
                 _%exn150178%_)
                (error '"not an instance"
                       'unknown-keyword-argument-exception?
                       (cons 'unknown-keyword-argument-exception-arguments
                             (cons _%exn150178%_ '())))))))
    (define unknown-keyword-argument-exception-procedure
      (lambda (_%exn150172%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150172%_))
            (let ((_%e150175%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150172%_ 'exception))))
              (if (macro-unknown-keyword-argument-exception? _%e150175%_)
                  (macro-unknown-keyword-argument-exception-procedure
                   _%e150175%_)
                  (error '"not an instance"
                         'unknown-keyword-argument-exception?
                         (cons 'unknown-keyword-argument-exception-procedure
                               (cons _%e150175%_ '())))))
            (if (macro-unknown-keyword-argument-exception? _%exn150172%_)
                (macro-unknown-keyword-argument-exception-procedure
                 _%exn150172%_)
                (error '"not an instance"
                       'unknown-keyword-argument-exception?
                       (cons 'unknown-keyword-argument-exception-procedure
                             (cons _%exn150172%_ '())))))))
    (define unterminated-process-exception?
      (lambda (_%exn150168%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150168%_))
            (let ((_%e150170%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150168%_ 'exception))))
              (macro-unterminated-process-exception? _%e150170%_))
            (macro-unterminated-process-exception? _%exn150168%_))))
    (define unterminated-process-exception-arguments
      (lambda (_%exn150164%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150164%_))
            (let ((_%e150166%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150164%_ 'exception))))
              (if (macro-unterminated-process-exception? _%e150166%_)
                  (macro-unterminated-process-exception-arguments _%e150166%_)
                  (error '"not an instance"
                         'unterminated-process-exception?
                         (cons 'unterminated-process-exception-arguments
                               (cons _%e150166%_ '())))))
            (if (macro-unterminated-process-exception? _%exn150164%_)
                (macro-unterminated-process-exception-arguments _%exn150164%_)
                (error '"not an instance"
                       'unterminated-process-exception?
                       (cons 'unterminated-process-exception-arguments
                             (cons _%exn150164%_ '())))))))
    (define unterminated-process-exception-procedure
      (lambda (_%exn150158%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150158%_))
            (let ((_%e150161%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150158%_ 'exception))))
              (if (macro-unterminated-process-exception? _%e150161%_)
                  (macro-unterminated-process-exception-procedure _%e150161%_)
                  (error '"not an instance"
                         'unterminated-process-exception?
                         (cons 'unterminated-process-exception-procedure
                               (cons _%e150161%_ '())))))
            (if (macro-unterminated-process-exception? _%exn150158%_)
                (macro-unterminated-process-exception-procedure _%exn150158%_)
                (error '"not an instance"
                       'unterminated-process-exception?
                       (cons 'unterminated-process-exception-procedure
                             (cons _%exn150158%_ '())))))))
    (define wrong-number-of-arguments-exception?
      (lambda (_%exn150154%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150154%_))
            (let ((_%e150156%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150154%_ 'exception))))
              (macro-wrong-number-of-arguments-exception? _%e150156%_))
            (macro-wrong-number-of-arguments-exception? _%exn150154%_))))
    (define wrong-number-of-arguments-exception-arguments
      (lambda (_%exn150150%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150150%_))
            (let ((_%e150152%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150150%_ 'exception))))
              (if (macro-wrong-number-of-arguments-exception? _%e150152%_)
                  (macro-wrong-number-of-arguments-exception-arguments
                   _%e150152%_)
                  (error '"not an instance"
                         'wrong-number-of-arguments-exception?
                         (cons 'wrong-number-of-arguments-exception-arguments
                               (cons _%e150152%_ '())))))
            (if (macro-wrong-number-of-arguments-exception? _%exn150150%_)
                (macro-wrong-number-of-arguments-exception-arguments
                 _%exn150150%_)
                (error '"not an instance"
                       'wrong-number-of-arguments-exception?
                       (cons 'wrong-number-of-arguments-exception-arguments
                             (cons _%exn150150%_ '())))))))
    (define wrong-number-of-arguments-exception-procedure
      (lambda (_%exn150144%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150144%_))
            (let ((_%e150147%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150144%_ 'exception))))
              (if (macro-wrong-number-of-arguments-exception? _%e150147%_)
                  (macro-wrong-number-of-arguments-exception-procedure
                   _%e150147%_)
                  (error '"not an instance"
                         'wrong-number-of-arguments-exception?
                         (cons 'wrong-number-of-arguments-exception-procedure
                               (cons _%e150147%_ '())))))
            (if (macro-wrong-number-of-arguments-exception? _%exn150144%_)
                (macro-wrong-number-of-arguments-exception-procedure
                 _%exn150144%_)
                (error '"not an instance"
                       'wrong-number-of-arguments-exception?
                       (cons 'wrong-number-of-arguments-exception-procedure
                             (cons _%exn150144%_ '())))))))
    (define wrong-number-of-values-exception?
      (lambda (_%exn150140%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150140%_))
            (let ((_%e150142%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150140%_ 'exception))))
              (macro-wrong-number-of-values-exception? _%e150142%_))
            (macro-wrong-number-of-values-exception? _%exn150140%_))))
    (define wrong-number-of-values-exception-code
      (lambda (_%exn150136%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150136%_))
            (let ((_%e150138%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150136%_ 'exception))))
              (if (macro-wrong-number-of-values-exception? _%e150138%_)
                  (macro-wrong-number-of-values-exception-code _%e150138%_)
                  (error '"not an instance"
                         'wrong-number-of-values-exception?
                         (cons 'wrong-number-of-values-exception-code
                               (cons _%e150138%_ '())))))
            (if (macro-wrong-number-of-values-exception? _%exn150136%_)
                (macro-wrong-number-of-values-exception-code _%exn150136%_)
                (error '"not an instance"
                       'wrong-number-of-values-exception?
                       (cons 'wrong-number-of-values-exception-code
                             (cons _%exn150136%_ '())))))))
    (define wrong-number-of-values-exception-rte
      (lambda (_%exn150132%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150132%_))
            (let ((_%e150134%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150132%_ 'exception))))
              (if (macro-wrong-number-of-values-exception? _%e150134%_)
                  (macro-wrong-number-of-values-exception-rte _%e150134%_)
                  (error '"not an instance"
                         'wrong-number-of-values-exception?
                         (cons 'wrong-number-of-values-exception-rte
                               (cons _%e150134%_ '())))))
            (if (macro-wrong-number-of-values-exception? _%exn150132%_)
                (macro-wrong-number-of-values-exception-rte _%exn150132%_)
                (error '"not an instance"
                       'wrong-number-of-values-exception?
                       (cons 'wrong-number-of-values-exception-rte
                             (cons _%exn150132%_ '())))))))
    (define wrong-number-of-values-exception-vals
      (lambda (_%exn150126%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150126%_))
            (let ((_%e150129%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150126%_ 'exception))))
              (if (macro-wrong-number-of-values-exception? _%e150129%_)
                  (macro-wrong-number-of-values-exception-vals _%e150129%_)
                  (error '"not an instance"
                         'wrong-number-of-values-exception?
                         (cons 'wrong-number-of-values-exception-vals
                               (cons _%e150129%_ '())))))
            (if (macro-wrong-number-of-values-exception? _%exn150126%_)
                (macro-wrong-number-of-values-exception-vals _%exn150126%_)
                (error '"not an instance"
                       'wrong-number-of-values-exception?
                       (cons 'wrong-number-of-values-exception-vals
                             (cons _%exn150126%_ '())))))))
    (define wrong-processor-c-return-exception?
      (lambda (_%exn150120%_)
        (if (let ()
              (declare (not safe))
              (class-instance? RuntimeException::t _%exn150120%_))
            (let ((_%e150123%_
                   (let ()
                     (declare (not safe))
                     (unchecked-slot-ref _%exn150120%_ 'exception))))
              (macro-wrong-processor-c-return-exception? _%e150123%_))
            (macro-wrong-processor-c-return-exception? _%exn150120%_))))))
