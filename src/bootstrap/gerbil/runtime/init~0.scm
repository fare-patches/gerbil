(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/init::timestamp 1795039816)
  (begin
    (define __scheme-source (make-parameter '#f))
    (define __load-gxi
      (lambda ()
        (let () (declare (not safe)) (__current-compiler __compile-top))
        (let () (declare (not safe)) (__current-expander gx#core-expand))
        (set! __eval-module gx#core-eval-module)
        (letrec* ((_%+readtable+182635%_ __*readtable*))
          (let* ((_%core182637%_ (gx#import-module ':gerbil/core))
                 (_%pre182639%_ (gx#make-prelude-context _%core182637%_)))
            (gx#current-expander-module-prelude _%pre182639%_)
            (gx#core-bind-root-syntax! ':<core> _%pre182639%_ '#t)
            (gx#eval-syntax '(import :gerbil/core)))
          (gx#current-expander-compile __compile-top-source)
          (let () (declare (not safe)) (##expand-source-set! __expand-source))
          (let () (declare (not safe)) (##macro-descr-set! __macro-descr))
          (let () (declare (not safe)) (##main-readtable-set! __*readtable*))
          (let ((__tmp182646
                 (lambda (_%port182642%_)
                   (input-port-readtable-set!
                    _%port182642%_
                    _%+readtable+182635%_)))
                (__tmp182645 (list ##stdin-port ##console-port)))
            (declare (not safe))
            (##for-each __tmp182646 __tmp182645))
          (let ((__tmp182648
                 (lambda (_%port182644%_)
                   (output-port-readtable-set!
                    _%port182644%_
                    (readtable-sharing-allowed?-set
                     (output-port-readtable _%port182644%_)
                     '#t))))
                (__tmp182647 (list ##stdout-port ##console-port)))
            (declare (not safe))
            (##for-each __tmp182648 __tmp182647)))))
    (define __gxi-init-interactive! (lambda (_%cmdline182632%_) '#!void))
    (define load-scheme
      (lambda (_%path182627%_)
        (let ((__tmp182649
               (lambda ()
                 (let ((__tmp182650 (lambda _%args182630%_ '#f)))
                   (declare (not safe))
                   (##load _%path182627%_ __tmp182650 '#t '#t '#f)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp182649
           __scheme-source
           _%path182627%_))))
    (define __expand-source
      (lambda (_%src182609%_)
        (letrec ((_%expand182611%_
                  (lambda (_%src182625%_)
                    (__compile-top
                     (gx#core-expand (__source->syntax _%src182625%_)))))
                 (_%no-expand182612%_
                  (lambda (_%src182618%_)
                    (if (let () (declare (not safe)) (__scheme-source))
                        _%src182618%_
                        (if (let ()
                              (declare (not safe))
                              (##source? _%src182618%_))
                            (let ((_%code182622%_
                                   (let ()
                                     (declare (not safe))
                                     (##source-code _%src182618%_))))
                              (if (pair? _%code182622%_)
                                  (if (eq? '__noexpand:
                                           (let ()
                                             (declare (not safe))
                                             (##car _%code182622%_)))
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%code182622%_))
                                      '#f)
                                  '#f))
                            '#f)))))
          (let ((_%$e182614%_ (_%no-expand182612%_ _%src182609%_)))
            (if _%$e182614%_ _%$e182614%_ (_%expand182611%_ _%src182609%_))))))
    (define __macro-descr
      (lambda (_%src182595%_ _%def-syntax?182596%_)
        (letrec ((_%fail!182598%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (##raise-expression-parsing-exception
                       'ill-formed-macro-transformer
                       _%src182595%_))))
                 (_%make-descr182599%_
                  (lambda (_%size182603%_)
                    (let ((_%expander182606%_
                           (let ((__tmp182651
                                  (lambda ()
                                    (let ()
                                      (declare (not safe))
                                      (##eval-top
                                       _%src182595%_
                                       ##interaction-cte)))))
                             (declare (not safe))
                             (call-with-parameters__1
                              __tmp182651
                              __scheme-source
                              'macro))))
                      (if (procedure? _%expander182606%_)
                          (let ()
                            (declare (not safe))
                            (##make-macro-descr
                             _%def-syntax?182596%_
                             _%size182603%_
                             _%expander182606%_
                             _%src182595%_))
                          (_%fail!182598%_))))))
          (if _%def-syntax?182596%_
              (_%make-descr182599%_ '-1)
              (let ((_%code182601%_
                     (let ()
                       (declare (not safe))
                       (##source-code _%src182595%_))))
                (if (and (let () (declare (not safe)) (##pair? _%code182601%_))
                         (let ((__tmp182652
                                (let ((__tmp182653
                                       (let ((__tmp182654
                                              (let ()
                                                (declare (not safe))
                                                (##car _%code182601%_))))
                                         (declare (not safe))
                                         (##sourcify
                                          __tmp182654
                                          _%src182595%_))))
                                  (declare (not safe))
                                  (##source-code __tmp182653))))
                           (declare (not safe))
                           (##memq __tmp182652 '(##lambda lambda))))
                    (begin
                      (let ()
                        (declare (not safe))
                        (##shape _%src182595%_ _%src182595%_ '-3))
                      (_%make-descr182599%_
                       (let ((__tmp182655
                              (let ((__tmp182656
                                     (let ()
                                       (declare (not safe))
                                       (##cadr _%code182601%_))))
                                (declare (not safe))
                                (##sourcify __tmp182656 _%src182595%_))))
                         (declare (not safe))
                         (##form-size __tmp182655))))
                    (_%fail!182598%_)))))))
    (define __source->syntax
      (lambda (_%src182584%_)
        (let _%recur182586%_ ((_%e182588%_ _%src182584%_))
          (if (let () (declare (not safe)) (##source? _%e182588%_))
              (let ((__tmp182658
                     (_%recur182586%_
                      (let ()
                        (declare (not safe))
                        (##source-code _%e182588%_))))
                    (__tmp182657
                     (let ()
                       (declare (not safe))
                       (##source-locat _%e182588%_))))
                (declare (not safe))
                (##structure AST::t __tmp182658 __tmp182657))
              (if (pair? _%e182588%_)
                  (cons (_%recur182586%_
                         (let () (declare (not safe)) (##car _%e182588%_)))
                        (_%recur182586%_
                         (let () (declare (not safe)) (##cdr _%e182588%_))))
                  (if (vector? _%e182588%_)
                      (vector-map _%recur182586%_ _%e182588%_)
                      (if (box? _%e182588%_)
                          (box (_%recur182586%_ (unbox _%e182588%_)))
                          _%e182588%_)))))))
    (define __compile-top-source
      (lambda (_%stx182582%_)
        (cons '__noexpand: (__compile-top _%stx182582%_))))
    (define __compile-top
      (lambda (_%stx182580%_)
        (let ((__tmp182659 (gx#core-compile-top-syntax _%stx182580%_)))
          (declare (not safe))
          (__compile __tmp182659))))
    (define __modstate (let () (declare (not safe)) (make-hash-table-eq)))
    (define __modstate-mx (make-mutex 'import))
    (define __modstate-cv (make-condition-variable 'import))
    (define __eval-import
      (lambda (_%in182413%_)
        (letrec ((_%import1182415%_
                  (lambda (_%in182565%_ _%phi182566%_)
                    (if (gx#module-import? _%in182565%_)
                        (let ((_%iphi182569%_
                               (fx+ _%phi182566%_
                                    (gx#module-import-phi _%in182565%_))))
                          (if (let ()
                                (declare (not safe))
                                (##fxzero? _%iphi182569%_))
                              (_%eval1182416%_
                               (gx#module-export-context
                                (gx#module-import-source _%in182565%_)))
                              '#!void))
                        (if (gx#module-context? _%in182565%_)
                            (if (fxzero? _%phi182566%_)
                                (_%eval1182416%_ _%in182565%_)
                                '#!void)
                            (if (gx#import-set? _%in182565%_)
                                (let ((_%iphi182573%_
                                       (fx+ _%phi182566%_
                                            (gx#import-set-phi _%in182565%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (##fxzero? _%iphi182573%_))
                                      (_%eval1182416%_
                                       (gx#import-set-source _%in182565%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (##fxpositive? _%iphi182573%_))
                                          (for-each
                                           (lambda (_%in182577%_)
                                             (_%import1182415%_
                                              _%in182577%_
                                              _%iphi182573%_))
                                           (gx#module-context-import
                                            (gx#import-set-source
                                             _%in182565%_)))
                                          '#!void)))
                                (let ()
                                  (declare (not safe))
                                  (error '"Unexpected import"
                                         _%in182565%_)))))))
                 (_%eval1182416%_
                  (lambda (_%ctx182420%_)
                    (mutex-lock! __modstate-mx)
                    (let ((_%$e182445%_
                           (let* ((_%h182422%_ __modstate)
                                  (_%key182425%_ _%ctx182420%_)
                                  (_%h182429%_ _%h182422%_)
                                  (_%h182431%_ _%h182429%_))
                             (declare (not safe))
                             (__hash-get _%h182431%_ _%key182425%_))))
                      (if _%$e182445%_
                          (let ((_%$e182450%_ (car _%$e182445%_)))
                            (if (eq? 'forcing _%$e182450%_)
                                (begin
                                  (mutex-unlock! __modstate-mx __modstate-cv)
                                  (_%eval1182416%_ _%ctx182420%_))
                                (if (eq? 'ready _%$e182450%_)
                                    (begin
                                      (mutex-unlock! __modstate-mx)
                                      (cadr _%$e182445%_))
                                    (if (eq? 'error _%$e182450%_)
                                        (begin
                                          (mutex-unlock! __modstate-mx)
                                          (let ((__tmp182660
                                                 (cadr _%$e182445%_)))
                                            (declare (not safe))
                                            (raise __tmp182660)))
                                        (begin
                                          (mutex-unlock! __modstate-mx)
                                          (let ()
                                            (declare (not safe))
                                            (error '"internal error; unexpected module state"
                                                   _%$e182445%_)))))))
                          (let ()
                            (let* ((_%h182454%_ __modstate)
                                   (_%key182457%_ _%ctx182420%_)
                                   (_%value182460%_ '(forcing))
                                   (_%h182464%_ _%h182454%_)
                                   (_%h182466%_ _%h182464%_))
                              (declare (not safe))
                              (__hash-put!
                               _%h182466%_
                               _%key182457%_
                               _%value182460%_))
                            (mutex-unlock! __modstate-mx)
                            (let* ((_%handler182507%_
                                    (lambda (_%exn182480%_)
                                      (mutex-lock! __modstate-mx)
                                      (let* ((_%h182482%_ __modstate)
                                             (_%key182485%_ _%ctx182420%_)
                                             (_%value182488%_
                                              (list 'error _%exn182480%_))
                                             (_%h182492%_ _%h182482%_)
                                             (_%h182494%_ _%h182492%_))
                                        (declare (not safe))
                                        (__hash-put!
                                         _%h182494%_
                                         _%key182485%_
                                         _%value182488%_))
                                      (condition-variable-broadcast!
                                       __modstate-cv)
                                      (mutex-unlock! __modstate-mx)
                                      (let ()
                                        (declare (not safe))
                                        (raise _%exn182480%_))))
                                   (_%thunk182540%_
                                    (lambda ()
                                      (let ((_%result182511%_
                                             (__eval-module _%ctx182420%_)))
                                        (mutex-lock! __modstate-mx)
                                        (let* ((_%h182513%_ __modstate)
                                               (_%key182516%_ _%ctx182420%_)
                                               (_%value182519%_
                                                (list 'ready _%result182511%_))
                                               (_%h182523%_ _%h182513%_)
                                               (_%h182525%_ _%h182523%_))
                                          (declare (not safe))
                                          (__hash-put!
                                           _%h182525%_
                                           _%key182516%_
                                           _%value182519%_))
                                        (condition-variable-broadcast!
                                         __modstate-cv)
                                        (mutex-unlock! __modstate-mx)
                                        _%result182511%_)))
                                   (_%handler182545%_ _%handler182507%_)
                                   (_%thunk182555%_ _%thunk182540%_))
                              (declare (not safe))
                              (__with-catch
                               _%handler182545%_
                               _%thunk182555%_))))))))
          (if (pair? _%in182413%_)
              (let ((__tmp182661
                     (lambda (_%in182418%_)
                       (_%import1182415%_ _%in182418%_ '0))))
                (declare (not safe))
                (##for-each __tmp182661 _%in182413%_))
              (_%import1182415%_ _%in182413%_ '0)))))
    (define __eval-module
      (lambda (_%obj182411%_) (gx#core-eval-module _%obj182411%_)))
    (define __interrupt-handler
      (lambda ()
        (if __DEBUG
            (begin
              (newline (current-error-port))
              (display '"--- continuation backtrace:" (current-error-port))
              (newline (current-error-port))
              (let* ((_%stack-trace-head182407%_
                      (let ((_%$e182404%_
                             (string->number
                              (let ()
                                (declare (not safe))
                                (##getenv '"GERBIL_DEBUG_STACKTRACE" '"10")))))
                        (if _%$e182404%_ _%$e182404%_ '10)))
                     (__tmp182662
                      (lambda (_%cont182409%_)
                        (display-continuation-backtrace
                         _%cont182409%_
                         (current-error-port)
                         '1
                         '1
                         '0
                         _%stack-trace-head182407%_))))
                (declare (not safe))
                (##continuation-capture __tmp182662)))
            '#!void)
        (let () (declare (not safe)) (##default-user-interrupt-handler))))
    (define gerbil-runtime-init!
      (lambda (_%builtin-modules182261%_)
        (if __runtime-initialized
            '#!void
            (begin
              (let () (declare (not safe)) (dump-stack-trace? '#t))
              (let* ((_%home182263%_
                      (let () (declare (not safe)) (gerbil-home)))
                     (_%libdir182265%_ (path-expand '"lib" _%home182263%_))
                     (_%userpath182267%_
                      (path-expand
                       '"lib"
                       (let () (declare (not safe)) (gerbil-path))))
                     (_%loadpath182269%_
                      (if (let ()
                            (declare (not safe))
                            (##getenv '"GERBIL_BUILD_PREFIX" '#f))
                          (cons _%libdir182265%_ '())
                          (cons _%userpath182267%_
                                (cons _%libdir182265%_ '()))))
                     (_%loadpath182332%_
                      (let ((_%$e182271%_
                             (let ()
                               (declare (not safe))
                               (##getenv '"GERBIL_LOADPATH" '#f))))
                        (if _%$e182271%_
                            (let ((__tmp182663
                                   (let ((__tmp182665
                                          (lambda (_%x182276%_)
                                            (not (let ((_%str182278%_
                                                        _%x182276%_))
                                                   (if (string? _%str182278%_)
                                                       (let ((_%str182283%_
                                                              _%str182278%_))
                                                         (declare (not safe))
                                                         (__string-empty?
                                                          _%str182283%_))
                                                       (begin
                                                         (raise-contract-violation-error
                                                          '"contract violation"
                                                          'context:
                                                          'gerbil/runtime/init
                                                          'contract:
                                                          'string?
                                                          'value:
                                                          _%str182278%_)
                                                         '#!void))))))
                                         (__tmp182664
                                          (let* ((_%str182302%_ _%$e182271%_)
                                                 (_%char182305%_ '#\:))
                                            (if (string? _%str182302%_)
                                                (let* ((_%str182310%_
                                                        _%str182302%_)
                                                       (_%char182321%_
                                                        _%char182305%_))
                                                  (declare (not safe))
                                                  (__string-split
                                                   _%str182310%_
                                                   _%char182321%_))
                                                (begin
                                                  (raise-contract-violation-error
                                                   '"contract violation"
                                                   'context:
                                                   'gerbil/runtime/init
                                                   'contract:
                                                   'string?
                                                   'value:
                                                   _%str182302%_)
                                                  '#!void)))))
                                     (declare (not safe))
                                     (##filter __tmp182665 __tmp182664))))
                              (declare (not safe))
                              (##append __tmp182663 _%loadpath182269%_))
                            _%loadpath182269%_)))
                     (_%paths182335%_ _%loadpath182332%_)
                     (_%paths182340%_ _%paths182335%_))
                (declare (not safe))
                (__set-load-path! _%paths182340%_))
              (for-each
               (lambda (_%mod182352%_)
                 (let* ((_%h182354%_ __modules)
                        (_%key182357%_ _%mod182352%_)
                        (_%value182360%_ 'builtin)
                        (_%h182364%_ _%h182354%_)
                        (_%h182366%_ _%h182364%_))
                   (declare (not safe))
                   (__hash-put! _%h182366%_ _%key182357%_ _%value182360%_))
                 (let* ((_%h182379%_ __modules)
                        (_%key182382%_
                         (let ()
                           (declare (not safe))
                           (##string-append _%mod182352%_ '"~0")))
                        (_%value182385%_ 'builtin)
                        (_%h182389%_ _%h182379%_)
                        (_%h182391%_ _%h182389%_))
                   (declare (not safe))
                   (__hash-put! _%h182391%_ _%key182382%_ _%value182385%_)))
               _%builtin-modules182261%_)
              (current-user-interrupt-handler __interrupt-handler)
              (current-readtable __*readtable*)
              (random-source-randomize! default-random-source)
              (set! __runtime-initialized '#t)))))
    (define __expander-loaded '#f)
    (define __runtime-initialized '#f)
    (define gerbil-load-expander!
      (lambda ()
        (if __runtime-initialized
            '#!void
            (let ()
              (declare (not safe))
              (error '"runtime has not been initialized")))
        (if __expander-loaded
            '#!void
            (begin (__load-gxi) (set! __expander-loaded '#t)))))))
