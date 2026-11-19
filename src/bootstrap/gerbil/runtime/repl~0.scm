(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/repl::timestamp 1795039816)
  (define replx
    (lambda ()
      (letrec ((_%write-reason181025%_
                (lambda (_%exn181063%_)
                  (lambda (_%cont181065%_ _%port181066%_)
                    (let ()
                      (declare (not safe))
                      (##display-exception-in-context
                       _%exn181063%_
                       _%cont181065%_
                       _%port181066%_))
                    '#f))))
        (let* ((_%handler181031%_
                (lambda (_%exn181027%_)
                  (let ((__tmp181067
                         (lambda (_%cont181029%_)
                           (let ((__tmp181068
                                  (_%write-reason181025%_ _%exn181027%_)))
                             (declare (not safe))
                             (##repl-within
                              _%cont181029%_
                              __tmp181068
                              _%exn181027%_)))))
                    (declare (not safe))
                    (##continuation-capture __tmp181067))))
               (_%thunk181034%_ ##repl)
               (_%handler181039%_ _%handler181031%_))
          (if (procedure? _%thunk181034%_)
              (let ((_%thunk181053%_ _%thunk181034%_))
                (declare (not safe))
                (__with-exception-handler _%handler181039%_ _%thunk181053%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/repl
                 'contract:
                 'procedure?
                 'value:
                 _%thunk181034%_)
                '#!void)))))))
