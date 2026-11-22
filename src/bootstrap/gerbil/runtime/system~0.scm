(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/system::timestamp 1795039813)
  (begin
    (define gerbil-version-string (lambda () '"v0.19-dev-94-ge7d7bb1cf"))
    (define gerbil-system-manifest
      (cons (cons '"Gerbil" (gerbil-version-string))
            (cons (cons '"Gambit" (system-version-string)) '())))
    (define __build-manifest gerbil-system-manifest)
    (define build-manifest (lambda () __build-manifest))
    (define __build-manifest-set!
      (lambda (_%new-value129205%_)
        (let ((_%new-value129208%_ _%new-value129205%_))
          (set! __build-manifest _%new-value129208%_))))
    (define build-manifest-set!
      (lambda (_%new-value129190%_)
        (if (list? _%new-value129190%_)
            (let ((_%new-value129195%_ _%new-value129190%_))
              (__build-manifest-set! _%new-value129195%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/runtime/system
               'contract:
               'list?
               'value:
               _%new-value129190%_)
              '#!void))))
    (define __display-build-manifest__%
      (lambda (_%manifest129113%_ _%port129114%_)
        (let* ((_%manifest129117%_ _%manifest129113%_)
               (_%port129125%_ _%port129114%_))
          (let ((_%p129138%_
                 (lambda (_%$%g129133129135%_)
                   (display _%$%g129133129135%_ _%port129125%_)))
                (_%l129139%_
                 (let () (declare (not safe)) (##length _%manifest129117%_)))
                (_%i129140%_ '0))
            (let ((__tmp129322
                   (lambda (_%layer129142%_)
                     (if (zero? _%i129140%_)
                         '#!void
                         (if (= _%i129140%_ '1)
                             (_%p129138%_ '" on ")
                             (_%p129138%_ '", ")))
                     (let* ((_%$%layer129146129153%_ _%layer129142%_)
                            (_%$%E129148129157%_
                             (lambda ()
                               (error '"No clause matching"
                                      _%$%layer129146129153%_
                                      '([name . version]))
                               '#!void))
                            (_%$%K129149129163%_
                             (lambda (_%version129160%_ _%name129161%_)
                               (_%p129138%_ _%name129161%_)
                               (_%p129138%_ '" ")
                               (_%p129138%_ _%version129160%_))))
                       (if (pair? _%$%layer129146129153%_)
                           (let ((_%$%hd129150129166%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%layer129146129153%_)))
                                 (_%$%tl129151129168%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%layer129146129153%_))))
                             (let* ((_%name129171%_ _%$%hd129150129166%_)
                                    (_%version129173%_ _%$%tl129151129168%_))
                               (_%$%K129149129163%_
                                _%version129173%_
                                _%name129171%_)))
                           (_%$%E129148129157%_)))
                     (set! _%i129140%_ (+ _%i129140%_ '1)))))
              (declare (not safe))
              (##for-each __tmp129322 _%manifest129117%_))))))
    (define __display-build-manifest__0
      (lambda ()
        (let* ((_%manifest129179%_ __build-manifest)
               (_%port129181%_ (current-output-port)))
          (__display-build-manifest__% _%manifest129179%_ _%port129181%_))))
    (define __display-build-manifest__1
      (lambda (_%manifest129183%_)
        (let ((_%port129185%_ (current-output-port)))
          (__display-build-manifest__% _%manifest129183%_ _%port129185%_))))
    (define __display-build-manifest
      (lambda _g129323_
        (let ((_g129324_ (let () (declare (not safe)) (##length _g129323_))))
          (cond ((let () (declare (not safe)) (##fx= _g129324_ 0))
                 (apply __display-build-manifest__0 _g129323_))
                ((let () (declare (not safe)) (##fx= _g129324_ 1))
                 (apply __display-build-manifest__1 _g129323_))
                ((let () (declare (not safe)) (##fx= _g129324_ 2))
                 (apply __display-build-manifest__% _g129323_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __display-build-manifest
                  _g129323_))))))
    (define display-build-manifest__%
      (lambda (_%manifest129072%_ _%port129073%_)
        (if (list? _%manifest129072%_)
            (let ((_%manifest129077%_ _%manifest129072%_))
              (if (port? _%port129073%_)
                  (let ((_%port129087%_ _%port129073%_))
                    (__display-build-manifest__%
                     _%manifest129077%_
                     _%port129087%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/system.ss\"@19.31-19.35"
                     'contract:
                     'port?
                     'value:
                     _%port129073%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/system.ss\"@18.31-18.39"
               'contract:
               'list?
               'value:
               _%manifest129072%_)
              '#!void))))
    (define display-build-manifest__0
      (lambda ()
        (let* ((_%manifest129101%_ __build-manifest)
               (_%port129103%_ (current-output-port)))
          (__display-build-manifest__% _%manifest129101%_ _%port129103%_))))
    (define display-build-manifest__1
      (lambda (_%manifest129105%_)
        (let ((_%port129107%_ (current-output-port)))
          (display-build-manifest__% _%manifest129105%_ _%port129107%_))))
    (define display-build-manifest
      (lambda _g129325_
        (let ((_g129326_ (let () (declare (not safe)) (##length _g129325_))))
          (cond ((let () (declare (not safe)) (##fx= _g129326_ 0))
                 (apply display-build-manifest__0 _g129325_))
                ((let () (declare (not safe)) (##fx= _g129326_ 1))
                 (apply display-build-manifest__1 _g129325_))
                ((let () (declare (not safe)) (##fx= _g129326_ 2))
                 (apply display-build-manifest__% _g129325_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  display-build-manifest
                  _g129325_))))))
    (define build-manifest/layer
      (lambda (_%layer129067%_)
        (let ((_%l129069%_ (assoc _%layer129067%_ __build-manifest)))
          (if _%l129069%_ (cons _%l129069%_ '()) '()))))
    (define build-manifest/head (lambda () (cons (car __build-manifest) '())))
    (define __build-manifest-string__%
      (lambda (_%manifest129011%_)
        (let ((_%manifest129014%_ _%manifest129011%_))
          (call-with-output-string
           '()
           (lambda (_%p129023%_)
             (let* ((_%manifest129025%_ _%manifest129014%_)
                    (_%port129028%_ _%p129023%_)
                    (_%manifest129033%_ _%manifest129025%_))
               (if (port? _%port129028%_)
                   (let ((_%port129048%_ _%port129028%_))
                     (__display-build-manifest__%
                      _%manifest129033%_
                      _%port129048%_))
                   (begin
                     (raise-contract-violation-error
                      '"contract violation"
                      'context:
                      'gerbil/runtime/system
                      'contract:
                      'port?
                      'value:
                      _%port129028%_)
                     '#!void))))))))
    (define __build-manifest-string__0
      (lambda ()
        (let ((_%manifest129062%_ __build-manifest))
          (__build-manifest-string__% _%manifest129062%_))))
    (define __build-manifest-string
      (lambda _g129327_
        (let ((_g129328_ (let () (declare (not safe)) (##length _g129327_))))
          (cond ((let () (declare (not safe)) (##fx= _g129328_ 0))
                 (apply __build-manifest-string__0 _g129327_))
                ((let () (declare (not safe)) (##fx= _g129328_ 1))
                 (apply __build-manifest-string__% _g129327_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __build-manifest-string
                  _g129327_))))))
    (define build-manifest-string__%
      (lambda (_%manifest128988%_)
        (if (list? _%manifest128988%_)
            (let ((_%manifest128992%_ _%manifest128988%_))
              (__build-manifest-string__% _%manifest128992%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/system.ss\"@40.30-40.38"
               'contract:
               'list?
               'value:
               _%manifest128988%_)
              '#!void))))
    (define build-manifest-string__0
      (lambda ()
        (let ((_%manifest129006%_ __build-manifest))
          (__build-manifest-string__% _%manifest129006%_))))
    (define build-manifest-string
      (lambda _g129329_
        (let ((_g129330_ (let () (declare (not safe)) (##length _g129329_))))
          (cond ((let () (declare (not safe)) (##fx= _g129330_ 0))
                 (apply build-manifest-string__0 _g129329_))
                ((let () (declare (not safe)) (##fx= _g129330_ 1))
                 (apply build-manifest-string__% _g129329_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  build-manifest-string
                  _g129329_))))))
    (define gerbil-system-version-string
      (lambda ()
        (let* ((_%manifest128970%_ gerbil-system-manifest)
               (_%manifest128975%_ _%manifest128970%_))
          (__build-manifest-string__% _%manifest128975%_))))
    (define __gerbil-greeting (gerbil-system-version-string))
    (define gerbil-greeting (lambda () __gerbil-greeting))
    (define __gerbil-greeting-set!
      (lambda (_%new-value128955%_)
        (let ((_%new-value128958%_ _%new-value128955%_))
          (set! __gerbil-greeting _%new-value128958%_))))
    (define gerbil-greeting-set!
      (lambda (_%new-value128940%_)
        (if (string? _%new-value128940%_)
            (let ((_%new-value128945%_ _%new-value128940%_))
              (__gerbil-greeting-set! _%new-value128945%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/runtime/system
               'contract:
               'string?
               'value:
               _%new-value128940%_)
              '#!void))))
    (define gerbil-system (lambda () 'gerbil-gambit))
    (define gerbil-home
      (lambda ()
        (let ((_%$e128936%_
               (let () (declare (not safe)) (##getenv '"GERBIL_HOME" '#f))))
          (if _%$e128936%_ _%$e128936%_ (path-expand '"~~")))))
    (define gerbil-path
      (lambda ()
        (let ((_%$e128932%_
               (let () (declare (not safe)) (##getenv '"GERBIL_PATH" '#f))))
          (if _%$e128932%_ _%$e128932%_ (path-expand '"~/.gerbil")))))
    (define __smp?
      (let ((__tmp129331
             (lambda ()
               (if (let ((__tmp129332
                          (let* ((_%str128901%_ (configure-command-string))
                                 (_%char128904%_ '#\')
                                 (_%str128909%_ _%str128901%_)
                                 (_%char128921%_ _%char128904%_))
                            (declare (not safe))
                            (__string-split _%str128909%_ _%char128921%_))))
                     (declare (not safe))
                     (##member '"--enable-smp" __tmp129332))
                   '#t
                   '#f))))
        (declare (not safe))
        (__make-atomic-promise __tmp129331)))
    (define gerbil-runtime-smp? (lambda () (force __smp?)))
    (define __DEBUG
      (let () (declare (not safe)) (##getenv '"GERBIL_DEBUG" '#f)))))
