(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/util::timestamp 1795039811)
  (begin
    (define raise-contract-violation-error error)
    (set! raise-contract-violation-error raise-contract-violation-error)
    (define displayln
      (lambda _%args120070%_
        (let ()
          (let () (declare (not safe)) (##for-each display _%args120070%_))
          (newline))))
    (define display*
      (lambda _%args120067%_
        (let () (declare (not safe)) (##for-each display _%args120067%_))))
    (define __file-newer?
      (lambda (_%file1119858%_ _%file2119859%_)
        (let* ((_%file1119862%_ _%file1119858%_)
               (_%file2119870%_ _%file2119859%_))
          (letrec ((_%__modification-time120014%_
                    (lambda (_%file120055%_)
                      (let* ((_%file120058%_ _%file120055%_)
                             (__tmp122950
                              (let ((__tmp122951
                                     (let ()
                                       (declare (not safe))
                                       (##file-info _%file120058%_ '#t))))
                                (declare (not safe))
                                (##file-info-last-modification-time
                                 __tmp122951))))
                        (declare (not safe))
                        (##time->seconds __tmp122950))))
                   (_%modification-time120015%_
                    (lambda (_%file120043%_)
                      (let ((_%file120046%_ _%file120043%_))
                        (_%__modification-time120014%_ _%file120046%_)))))
            (let ((__tmp122953
                   (let* ((_%file120017%_ _%file1119862%_)
                          (_%file120021%_ _%file120017%_))
                     (_%__modification-time120014%_ _%file120021%_)))
                  (__tmp122952
                   (let* ((_%file120030%_ _%file2119870%_)
                          (_%file120034%_ _%file120030%_))
                     (_%__modification-time120014%_ _%file120034%_))))
              (declare (not safe))
              (##fl> __tmp122953 __tmp122952))))))
    (define file-newer?
      (lambda (_%file1119833%_ _%file2119834%_)
        (if (string? _%file1119833%_)
            (let ((_%file1119838%_ _%file1119833%_))
              (if (string? _%file2119834%_)
                  (let ((_%file2119848%_ _%file2119834%_))
                    (__file-newer? _%file1119838%_ _%file2119848%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@75.20-75.25"
                     'contract:
                     'string?
                     'value:
                     _%file2119834%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@74.20-74.25"
               'contract:
               'string?
               'value:
               _%file1119833%_)
              '#!void))))
    (define __create-directory*__%
      (lambda (_%dir119543%_ _%perms119544%_)
        (let* ((_%dir119547%_ _%dir119543%_) (_%perms119555%_ _%perms119544%_))
          (letrec ((_%__create1119699%_
                    (lambda (_%path119808%_)
                      (let ((_%path119811%_ _%path119808%_))
                        (if (let ()
                              (declare (not safe))
                              (##file-exists? _%path119811%_))
                            (if (eq? (file-type _%path119811%_) 'directory)
                                '#!void
                                (begin
                                  (raise-contract-violation-error
                                   '"Path component is not a directory"
                                   'value:
                                   _%path119811%_)
                                  '#!void))
                            (if _%perms119555%_
                                (create-directory
                                 (cons 'path:
                                       (cons _%path119811%_
                                             (cons 'permissions:
                                                   (cons _%perms119555%_
                                                         '())))))
                                (create-directory _%path119811%_))))))
                   (_%create1119700%_
                    (lambda (_%path119796%_)
                      (let ((_%path119799%_ _%path119796%_))
                        (_%__create1119699%_ _%path119799%_)))))
            (if (let () (declare (not safe)) (##file-exists? _%dir119547%_))
                '#!void
                (let _%lp119702%_ ((_%start119704%_ '0))
                  (let ((_%$e119761%_
                         (let* ((_%str119706%_ _%dir119547%_)
                                (_%criterion119709%_ '#\/)
                                (_%start119712%_ _%start119704%_)
                                (_%end119715%_ '#f)
                                (_%str119720%_ _%str119706%_))
                           (if (nonnegative-fixnum? _%start119712%_)
                               (let ((_%start119735%_ _%start119712%_))
                                 (if (let ((_%$e119747%_ '#t))
                                       (and _%$e119747%_ _%$e119747%_))
                                     (let ((_%end119751%_ _%end119715%_))
                                       (__string-index__%
                                        _%str119720%_
                                        _%criterion119709%_
                                        _%start119735%_
                                        _%end119751%_))
                                     (begin
                                       (raise-contract-violation-error
                                        '"contract violation"
                                        'context:
                                        'gerbil/runtime/util
                                        'contract:
                                        '(? (or not fixnum?))
                                        'value:
                                        _%end119715%_)
                                       '#!void)))
                               (begin
                                 (raise-contract-violation-error
                                  '"contract violation"
                                  'context:
                                  'gerbil/runtime/util
                                  'contract:
                                  'nonnegative-fixnum?
                                  'value:
                                  _%start119712%_)
                                 '#!void)))))
                    (if _%$e119761%_
                        (let ()
                          (if (let ()
                                (declare (not safe))
                                (##fx> _%$e119761%_ '0))
                              (let* ((_%path119766%_
                                      (substring
                                       _%dir119547%_
                                       '0
                                       _%$e119761%_))
                                     (_%path119770%_ _%path119766%_))
                                (_%__create1119699%_ _%path119770%_))
                              '#!void)
                          (_%lp119702%_
                           (let ()
                             (declare (not safe))
                             (##fx+ _%$e119761%_ '1))))
                        (let* ((_%path119782%_ _%dir119547%_)
                               (_%path119786%_ _%path119782%_))
                          (_%__create1119699%_ _%path119786%_))))))
            '#!void))))
    (define __create-directory*__0
      (lambda (_%dir119826%_)
        (let ((_%perms119828%_ '493))
          (__create-directory*__% _%dir119826%_ _%perms119828%_))))
    (define __create-directory*
      (lambda _g122954_
        (let ((_g122955_ (let () (declare (not safe)) (##length _g122954_))))
          (cond ((let () (declare (not safe)) (##fx= _g122955_ 1))
                 (apply __create-directory*__0 _g122954_))
                ((let () (declare (not safe)) (##fx= _g122955_ 2))
                 (apply __create-directory*__% _g122954_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __create-directory*
                  _g122954_))))))
    (define create-directory*__%
      (lambda (_%dir119507%_ _%perms119508%_)
        (if (string? _%dir119507%_)
            (let ((_%dir119512%_ _%dir119507%_))
              (if (fixnum? _%perms119508%_)
                  (let ((_%perms119522%_ _%perms119508%_))
                    (__create-directory*__% _%dir119512%_ _%perms119522%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@86.26-86.31"
                     'contract:
                     'fixnum?
                     'value:
                     _%perms119508%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@85.26-85.29"
               'contract:
               'string?
               'value:
               _%dir119507%_)
              '#!void))))
    (define create-directory*__0
      (lambda (_%dir119535%_)
        (let ((_%perms119537%_ '493))
          (create-directory*__% _%dir119535%_ _%perms119537%_))))
    (define create-directory*
      (lambda _g122956_
        (let ((_g122957_ (let () (declare (not safe)) (##length _g122956_))))
          (cond ((let () (declare (not safe)) (##fx= _g122957_ 1))
                 (apply create-directory*__0 _g122956_))
                ((let () (declare (not safe)) (##fx= _g122957_ 2))
                 (apply create-directory*__% _g122956_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  create-directory*
                  _g122956_))))))
    (define __move-file__%
      (lambda (_%src119450%_ _%dest119451%_ _%replace?119452%_)
        (let* ((_%src119455%_ _%src119450%_)
               (_%dest119463%_ _%dest119451%_)
               (_%replace?119471%_ _%replace?119452%_))
          (letrec ((_%force-move-it119480%_
                    (lambda ()
                      (let ((_%tmp119486%_
                             (if _%replace?119471%_
                                 (if (let ()
                                       (declare (not safe))
                                       (##file-exists? _%dest119463%_))
                                     (let ((__tmp122958
                                            (number->string
                                             (let ()
                                               (declare (not safe))
                                               (##current-time-point)))))
                                       (declare (not safe))
                                       (##string-append
                                        _%dest119463%_
                                        '"."
                                        __tmp122958))
                                     '#f)
                                 '#f)))
                        (if _%tmp119486%_
                            (let ()
                              (declare (not safe))
                              (##rename-file _%dest119463%_ _%tmp119486%_))
                            '#!void)
                        (with-exception-catcher
                         (lambda (_%e119488%_)
                           (if _%tmp119486%_
                               (let ()
                                 (declare (not safe))
                                 (##rename-file
                                  _%tmp119486%_
                                  _%dest119463%_
                                  '#t))
                               '#!void)
                           (raise _%e119488%_))
                         (lambda ()
                           (let ((_%fi119491%_
                                  (let ()
                                    (declare (not safe))
                                    (##file-info _%src119455%_ '#f))))
                             (if (eq? (let ()
                                        (declare (not safe))
                                        (##file-info-type _%fi119491%_))
                                      'symbolic-link)
                                 (let ((__tmp122959
                                        (path-normalize _%src119455%_)))
                                   (declare (not safe))
                                   (##create-symbolic-link
                                    __tmp122959
                                    _%dest119463%_))
                                 (let ()
                                   (declare (not safe))
                                   (##copy-file
                                    _%src119455%_
                                    _%dest119463%_))))
                           (let ()
                             (declare (not safe))
                             (##delete-file _%src119455%_))
                           (if _%tmp119486%_
                               (with-exception-catcher
                                void
                                (lambda ()
                                  (let ()
                                    (declare (not safe))
                                    (##delete-file _%tmp119486%_))))
                               '#!void)))))))
            (with-exception-catcher
             (lambda (_%e119482%_)
               (if (let () (declare (not safe)) (##file-exists? _%src119455%_))
                   (_%force-move-it119480%_)
                   (raise _%e119482%_)))
             (lambda ()
               (let ()
                 (declare (not safe))
                 (##rename-file
                  _%src119455%_
                  _%dest119463%_
                  _%replace?119471%_))))
            '#!void))))
    (define __move-file__0
      (lambda (_%src119497%_ _%dest119498%_)
        (let ((_%replace?119500%_ '#t))
          (__move-file__% _%src119497%_ _%dest119498%_ _%replace?119500%_))))
    (define __move-file
      (lambda _g122960_
        (let ((_g122961_ (let () (declare (not safe)) (##length _g122960_))))
          (cond ((let () (declare (not safe)) (##fx= _g122961_ 2))
                 (apply __move-file__0 _g122960_))
                ((let () (declare (not safe)) (##fx= _g122961_ 3))
                 (apply __move-file__% _g122960_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __move-file
                  _g122960_))))))
    (define move-file__%
      (lambda (_%src119401%_ _%dest119402%_ _%replace?119403%_)
        (if (string? _%src119401%_)
            (let ((_%src119407%_ _%src119401%_))
              (if (string? _%dest119402%_)
                  (let ((_%dest119417%_ _%dest119402%_))
                    (if (boolean? _%replace?119403%_)
                        (let ((_%replace?119427%_ _%replace?119403%_))
                          (__move-file__%
                           _%src119407%_
                           _%dest119417%_
                           _%replace?119427%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/util.ss\"@111.51-111.59"
                           'contract:
                           'boolean?
                           'value:
                           _%replace?119403%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@111.34-111.38"
                     'contract:
                     'string?
                     'value:
                     _%dest119402%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@111.18-111.21"
               'contract:
               'string?
               'value:
               _%src119401%_)
              '#!void))))
    (define move-file__0
      (lambda (_%src119440%_ _%dest119441%_)
        (let ((_%replace?119443%_ '#t))
          (move-file__% _%src119440%_ _%dest119441%_ _%replace?119443%_))))
    (define move-file
      (lambda _g122962_
        (let ((_g122963_ (let () (declare (not safe)) (##length _g122962_))))
          (cond ((let () (declare (not safe)) (##fx= _g122963_ 2))
                 (apply move-file__0 _g122962_))
                ((let () (declare (not safe)) (##fx= _g122963_ 3))
                 (apply move-file__% _g122962_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  move-file
                  _g122962_))))))
    (define force-current-outputs
      (lambda ()
        (let ()
          (with-exception-catcher
           void
           (lambda () (force-output (current-output-port))))
          (with-exception-catcher
           void
           (lambda () (force-output (current-error-port))))
          '#!void)))
    (define absent-obj (let () (declare (not safe)) (##absent-object)))
    (define absent-value '#(#!void))
    (define true (lambda _%ignore119393%_ '#t))
    (define true? (lambda (_%obj119390%_) (eq? _%obj119390%_ '#t)))
    (define false (lambda _%ignore119387%_ '#f))
    (define void (lambda _%ignore119384%_ '#!void))
    (define void? (lambda (_%obj119381%_) (eq? _%obj119381%_ '#!void)))
    (define dssl-object?
      (lambda (_%obj119378%_)
        (if (let ()
              (declare (not safe))
              (##memq _%obj119378%_ '(#!key #!rest #!optional)))
            '#t
            '#f)))
    (define dssl-key-object?
      (lambda (_%obj119375%_) (eq? _%obj119375%_ '#!key)))
    (define dssl-rest-object?
      (lambda (_%obj119372%_) (eq? _%obj119372%_ '#!rest)))
    (define dssl-optional-object?
      (lambda (_%obj119369%_) (eq? _%obj119369%_ '#!optional)))
    (define immediate?
      (lambda (_%obj119366%_)
        (not (let () (declare (not safe)) (##mem-allocated? _%obj119366%_)))))
    (define nonnegative-fixnum?
      (lambda (_%obj119363%_)
        (if (fixnum? _%obj119363%_)
            (let () (declare (not safe)) (##fx>= _%obj119363%_ '0))
            '#f)))
    (define pair-or-null?
      (lambda (_%obj119357%_)
        (let ((_%$e119360%_ (pair? _%obj119357%_)))
          (if _%$e119360%_ _%$e119360%_ (null? _%obj119357%_)))))
    (define values-count
      (lambda (_%obj119354%_)
        (if (let () (declare (not safe)) (##values? _%obj119354%_))
            (let () (declare (not safe)) (##values-length _%obj119354%_))
            '1)))
    (define __values-ref
      (lambda (_%obj119341%_ _%k119342%_)
        (let ((_%k119345%_ _%k119342%_))
          (if (let () (declare (not safe)) (##values? _%obj119341%_))
              (let ()
                (declare (not safe))
                (##values-ref _%obj119341%_ _%k119345%_))
              _%obj119341%_))))
    (define values-ref
      (lambda (_%obj119326%_ _%k119327%_)
        (if (fixnum? _%k119327%_)
            (let ((_%k119331%_ _%k119327%_))
              (__values-ref _%obj119326%_ _%k119331%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@255.23-255.24"
               'contract:
               'fixnum?
               'value:
               _%k119327%_)
              '#!void))))
    (define values->list
      (lambda (_%obj119323%_)
        (if (let () (declare (not safe)) (##values? _%obj119323%_))
            (let () (declare (not safe)) (##values->list _%obj119323%_))
            (list _%obj119323%_))))
    (define __foldl1
      (lambda (_%f119271%_ _%iv119272%_ _%lst119273%_)
        (let ((_%f119276%_ _%f119271%_))
          (let _%lp119285%_ ((_%rest119287%_ _%lst119273%_)
                             (_%r119288%_ _%iv119272%_))
            (let* ((_%$%rest119289119297%_ _%rest119287%_)
                   (_%$%else119291119305%_ (lambda () _%r119288%_))
                   (_%$%K119293119311%_
                    (lambda (_%rest119308%_ _%x119309%_)
                      (_%lp119285%_
                       _%rest119308%_
                       (let ()
                         (declare (not safe))
                         (_%f119276%_ _%x119309%_ _%r119288%_))))))
              (if (pair? _%$%rest119289119297%_)
                  (let ((_%$%hd119294119314%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest119289119297%_)))
                        (_%$%tl119295119316%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest119289119297%_))))
                    (let* ((_%x119319%_ _%$%hd119294119314%_)
                           (_%rest119321%_ _%$%tl119295119316%_))
                      (_%$%K119293119311%_ _%rest119321%_ _%x119319%_)))
                  (_%$%else119291119305%_)))))))
    (define foldl1
      (lambda (_%f119255%_ _%iv119256%_ _%lst119257%_)
        (if (procedure? _%f119255%_)
            (let ((_%f119261%_ _%f119255%_))
              (__foldl1 _%f119261%_ _%iv119256%_ _%lst119257%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@278.15-278.16"
               'contract:
               'procedure?
               'value:
               _%f119255%_)
              '#!void))))
    (define __foldl2
      (lambda (_%f119168%_ _%iv119169%_ _%lst1119170%_ _%lst2119171%_)
        (let ((_%f119174%_ _%f119168%_))
          (let _%lp119183%_ ((_%rest1119185%_ _%lst1119170%_)
                             (_%rest2119186%_ _%lst2119171%_)
                             (_%r119187%_ _%iv119169%_))
            (let* ((_%$%rest1119188119196%_ _%rest1119185%_)
                   (_%$%else119190119204%_ (lambda () _%r119187%_))
                   (_%$%K119192119243%_
                    (lambda (_%rest1119207%_ _%x1119208%_)
                      (let* ((_%$%rest2119209119217%_ _%rest2119186%_)
                             (_%$%else119211119225%_ (lambda () _%r119187%_))
                             (_%$%K119213119231%_
                              (lambda (_%rest2119228%_ _%x2119229%_)
                                (_%lp119183%_
                                 _%rest1119207%_
                                 _%rest2119228%_
                                 (let ()
                                   (declare (not safe))
                                   (_%f119174%_
                                    _%x1119208%_
                                    _%x2119229%_
                                    _%r119187%_))))))
                        (if (pair? _%$%rest2119209119217%_)
                            (let ((_%$%hd119214119234%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest2119209119217%_)))
                                  (_%$%tl119215119236%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest2119209119217%_))))
                              (let* ((_%x2119239%_ _%$%hd119214119234%_)
                                     (_%rest2119241%_ _%$%tl119215119236%_))
                                (_%$%K119213119231%_
                                 _%rest2119241%_
                                 _%x2119239%_)))
                            (_%$%else119211119225%_))))))
              (if (pair? _%$%rest1119188119196%_)
                  (let ((_%$%hd119193119246%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest1119188119196%_)))
                        (_%$%tl119194119248%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest1119188119196%_))))
                    (let* ((_%x1119251%_ _%$%hd119193119246%_)
                           (_%rest1119253%_ _%$%tl119194119248%_))
                      (_%$%K119192119243%_ _%rest1119253%_ _%x1119251%_)))
                  (_%$%else119190119204%_)))))))
    (define foldl2
      (lambda (_%f119151%_ _%iv119152%_ _%lst1119153%_ _%lst2119154%_)
        (if (procedure? _%f119151%_)
            (let ((_%f119158%_ _%f119151%_))
              (__foldl2
               _%f119158%_
               _%iv119152%_
               _%lst1119153%_
               _%lst2119154%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@285.15-285.16"
               'contract:
               'procedure?
               'value:
               _%f119151%_)
              '#!void))))
    (define foldl__0
      (lambda (_%f119084%_ _%iv119085%_ _%lst119086%_)
        (let* ((_%f119088%_ _%f119084%_)
               (_%iv119091%_ _%iv119085%_)
               (_%lst119094%_ _%lst119086%_))
          (if (procedure? _%f119088%_)
              (let ((_%f119099%_ _%f119088%_))
                (__foldl1 _%f119099%_ _%iv119091%_ _%lst119094%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f119088%_)
                '#!void)))))
    (define foldl__1
      (lambda (_%f119112%_ _%iv119113%_ _%lst1119114%_ _%lst2119115%_)
        (let* ((_%f119117%_ _%f119112%_)
               (_%iv119120%_ _%iv119113%_)
               (_%lst1119123%_ _%lst1119114%_)
               (_%lst2119126%_ _%lst2119115%_))
          (if (procedure? _%f119117%_)
              (let ((_%f119131%_ _%f119117%_))
                (__foldl2
                 _%f119131%_
                 _%iv119120%_
                 _%lst1119123%_
                 _%lst2119126%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f119117%_)
                '#!void)))))
    (define foldl
      (lambda _g122964_
        (let ((_g122965_ (let () (declare (not safe)) (##length _g122964_))))
          (cond ((let () (declare (not safe)) (##fx= _g122965_ 3))
                 (apply foldl__0 _g122964_))
                ((let () (declare (not safe)) (##fx= _g122965_ 4))
                 (apply foldl__1 _g122964_))
                ((let () (declare (not safe)) (##fx>= _g122965_ 4))
                 (apply foldl* _g122964_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  foldl
                  _g122964_))))))
    (define __foldl*
      (lambda (_%f119015%_ _%iv119016%_ . _%rest119017%_)
        (let ((_%f119020%_ _%f119015%_))
          (let _%recur119029%_ ((_%iv119031%_ _%iv119016%_)
                                (_%rest119032%_ _%rest119017%_))
            (if (let* ((_%f119034%_ pair?)
                       (_%lst119037%_ _%rest119032%_)
                       (_%f119042%_ _%f119034%_))
                  (__andmap1 _%f119042%_ _%lst119037%_))
                (_%recur119029%_
                 (let ((__tmp122966
                        (let* ((_%f119061%_
                                (lambda (_%xs119058%_ _%r119059%_)
                                  (cons (car _%xs119058%_) _%r119059%_)))
                               (_%iv119064%_ (list _%iv119031%_))
                               (_%lst119067%_ _%rest119032%_)
                               (_%f119072%_ _%f119061%_))
                          (__foldr1 _%f119072%_ _%iv119064%_ _%lst119067%_))))
                   (declare (not safe))
                   (##apply _%f119020%_ __tmp122966))
                 (map cdr _%rest119032%_))
                _%iv119031%_)))))
    (define foldl*
      (lambda (_%f118999%_ _%iv119000%_ . _%rest119001%_)
        (if (procedure? _%f118999%_)
            (let ((_%f119005%_ _%f118999%_))
              (declare (not safe))
              (##apply __foldl* _%f119005%_ _%iv119000%_ _%rest119001%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@303.15-303.16"
               'contract:
               'procedure?
               'value:
               _%f118999%_)
              '#!void))))
    (define __foldr1
      (lambda (_%f118948%_ _%iv118949%_ _%lst118950%_)
        (let ((_%f118953%_ _%f118948%_))
          (let _%recur118962%_ ((_%rest118964%_ _%lst118950%_))
            (let* ((_%$%rest118965118973%_ _%rest118964%_)
                   (_%$%else118967118981%_ (lambda () _%iv118949%_))
                   (_%$%K118969118987%_
                    (lambda (_%rest118984%_ _%x118985%_)
                      (let ((__tmp122967 (_%recur118962%_ _%rest118984%_)))
                        (declare (not safe))
                        (_%f118953%_ _%x118985%_ __tmp122967)))))
              (if (pair? _%$%rest118965118973%_)
                  (let ((_%$%hd118970118990%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest118965118973%_)))
                        (_%$%tl118971118992%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest118965118973%_))))
                    (let* ((_%x118995%_ _%$%hd118970118990%_)
                           (_%rest118997%_ _%$%tl118971118992%_))
                      (_%$%K118969118987%_ _%rest118997%_ _%x118995%_)))
                  (_%$%else118967118981%_)))))))
    (define foldr1
      (lambda (_%f118932%_ _%iv118933%_ _%lst118934%_)
        (if (procedure? _%f118932%_)
            (let ((_%f118938%_ _%f118932%_))
              (__foldr1 _%f118938%_ _%iv118933%_ _%lst118934%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@313.15-313.16"
               'contract:
               'procedure?
               'value:
               _%f118932%_)
              '#!void))))
    (define __foldr2
      (lambda (_%f118846%_ _%iv118847%_ _%lst1118848%_ _%lst2118849%_)
        (let ((_%f118852%_ _%f118846%_))
          (let _%recur118861%_ ((_%rest1118863%_ _%lst1118848%_)
                                (_%rest2118864%_ _%lst2118849%_))
            (let* ((_%$%rest1118865118873%_ _%rest1118863%_)
                   (_%$%else118867118881%_ (lambda () _%iv118847%_))
                   (_%$%K118869118920%_
                    (lambda (_%rest1118884%_ _%x1118885%_)
                      (let* ((_%$%rest2118886118894%_ _%rest2118864%_)
                             (_%$%else118888118902%_ (lambda () _%iv118847%_))
                             (_%$%K118890118908%_
                              (lambda (_%rest2118905%_ _%x2118906%_)
                                (let ((__tmp122968
                                       (_%recur118861%_
                                        _%rest1118884%_
                                        _%rest2118905%_)))
                                  (declare (not safe))
                                  (_%f118852%_
                                   _%x1118885%_
                                   _%x2118906%_
                                   __tmp122968)))))
                        (if (pair? _%$%rest2118886118894%_)
                            (let ((_%$%hd118891118911%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest2118886118894%_)))
                                  (_%$%tl118892118913%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest2118886118894%_))))
                              (let* ((_%x2118916%_ _%$%hd118891118911%_)
                                     (_%rest2118918%_ _%$%tl118892118913%_))
                                (_%$%K118890118908%_
                                 _%rest2118918%_
                                 _%x2118916%_)))
                            (_%$%else118888118902%_))))))
              (if (pair? _%$%rest1118865118873%_)
                  (let ((_%$%hd118870118923%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest1118865118873%_)))
                        (_%$%tl118871118925%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest1118865118873%_))))
                    (let* ((_%x1118928%_ _%$%hd118870118923%_)
                           (_%rest1118930%_ _%$%tl118871118925%_))
                      (_%$%K118869118920%_ _%rest1118930%_ _%x1118928%_)))
                  (_%$%else118867118881%_)))))))
    (define foldr2
      (lambda (_%f118829%_ _%iv118830%_ _%lst1118831%_ _%lst2118832%_)
        (if (procedure? _%f118829%_)
            (let ((_%f118836%_ _%f118829%_))
              (__foldr2
               _%f118836%_
               _%iv118830%_
               _%lst1118831%_
               _%lst2118832%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@320.15-320.16"
               'contract:
               'procedure?
               'value:
               _%f118829%_)
              '#!void))))
    (define foldr__0
      (lambda (_%f118762%_ _%iv118763%_ _%lst118764%_)
        (let* ((_%f118766%_ _%f118762%_)
               (_%iv118769%_ _%iv118763%_)
               (_%lst118772%_ _%lst118764%_))
          (if (procedure? _%f118766%_)
              (let ((_%f118777%_ _%f118766%_))
                (__foldr1 _%f118777%_ _%iv118769%_ _%lst118772%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f118766%_)
                '#!void)))))
    (define foldr__1
      (lambda (_%f118790%_ _%iv118791%_ _%lst1118792%_ _%lst2118793%_)
        (let* ((_%f118795%_ _%f118790%_)
               (_%iv118798%_ _%iv118791%_)
               (_%lst1118801%_ _%lst1118792%_)
               (_%lst2118804%_ _%lst2118793%_))
          (if (procedure? _%f118795%_)
              (let ((_%f118809%_ _%f118795%_))
                (__foldr2
                 _%f118809%_
                 _%iv118798%_
                 _%lst1118801%_
                 _%lst2118804%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f118795%_)
                '#!void)))))
    (define foldr
      (lambda _g122969_
        (let ((_g122970_ (let () (declare (not safe)) (##length _g122969_))))
          (cond ((let () (declare (not safe)) (##fx= _g122970_ 3))
                 (apply foldr__0 _g122969_))
                ((let () (declare (not safe)) (##fx= _g122970_ 4))
                 (apply foldr__1 _g122969_))
                ((let () (declare (not safe)) (##fx>= _g122970_ 4))
                 (apply foldr* _g122969_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  foldr
                  _g122969_))))))
    (define __foldr*
      (lambda (_%f118694%_ _%iv118695%_ . _%rest118696%_)
        (let ((_%f118699%_ _%f118694%_))
          (let _%recur118708%_ ((_%rest118710%_ _%rest118696%_))
            (if (let* ((_%f118712%_ pair?)
                       (_%lst118715%_ _%rest118710%_)
                       (_%f118720%_ _%f118712%_))
                  (__andmap1 _%f118720%_ _%lst118715%_))
                (let ((__tmp122971
                       (let* ((_%f118739%_
                               (lambda (_%xs118736%_ _%r118737%_)
                                 (cons (car _%xs118736%_) _%r118737%_)))
                              (_%iv118742%_
                               (list (_%recur118708%_
                                      (map cdr _%rest118710%_))))
                              (_%lst118745%_ _%rest118710%_)
                              (_%f118750%_ _%f118739%_))
                         (__foldr1 _%f118750%_ _%iv118742%_ _%lst118745%_))))
                  (declare (not safe))
                  (##apply _%f118699%_ __tmp122971))
                _%iv118695%_)))))
    (define foldr*
      (lambda (_%f118678%_ _%iv118679%_ . _%rest118680%_)
        (if (procedure? _%f118678%_)
            (let ((_%f118684%_ _%f118678%_))
              (declare (not safe))
              (##apply __foldr* _%f118684%_ _%iv118679%_ _%rest118680%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@338.15-338.16"
               'contract:
               'procedure?
               'value:
               _%f118678%_)
              '#!void))))
    (define remove-nulls!
      (lambda (_%lists118565%_)
        (letrec ((_%process-tails!118567%_
                  (lambda (_%previous-cell118622%_ _%rest118623%_)
                    (let* ((_%$%rest118624118637%_ _%rest118623%_)
                           (_%$%E118628118641%_
                            (lambda ()
                              (error '"No clause matching"
                                     _%$%rest118624118637%_
                                     '([[] . r])
                                     '([_ . r])
                                     '(_))
                              '#!void)))
                      (let ((_%$%K118633118668%_
                             (lambda (_%r118666%_)
                               (let ((__tmp122973 _%previous-cell118622%_)
                                     (__tmp122972 (remove-nulls! _%r118666%_)))
                                 (declare (not safe))
                                 (##set-cdr! __tmp122973 __tmp122972))))
                            (_%$%K118630118655%_
                             (lambda (_%r118653%_)
                               (_%process-tails!118567%_
                                _%rest118623%_
                                _%r118653%_)))
                            (_%$%K118629118646%_ (lambda () '#!void)))
                        (if (pair? _%$%rest118624118637%_)
                            (let ((_%$%tl118635118673%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest118624118637%_)))
                                  (_%$%hd118634118671%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest118624118637%_))))
                              (if (null? _%$%hd118634118671%_)
                                  (let ((_%r118676%_ _%$%tl118635118673%_))
                                    (_%$%K118633118668%_ _%r118676%_))
                                  (let ((_%r118661%_ _%$%tl118635118673%_))
                                    (_%$%K118630118655%_ _%r118661%_))))
                            '#!void))))))
          (let* ((_%$%lists118568118581%_ _%lists118565%_)
                 (_%$%E118572118585%_
                  (lambda ()
                    (error '"No clause matching"
                           _%$%lists118568118581%_
                           '([[] . r])
                           '([_ . r])
                           '(_))
                    '#!void)))
            (let ((_%$%K118577118612%_
                   (lambda (_%r118610%_) (remove-nulls! _%r118610%_)))
                  (_%$%K118574118599%_
                   (lambda (_%r118597%_)
                     (_%process-tails!118567%_ _%lists118565%_ _%r118597%_)
                     _%lists118565%_))
                  (_%$%K118573118590%_ (lambda () _%lists118565%_)))
              (if (pair? _%$%lists118568118581%_)
                  (let ((_%$%tl118579118617%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%lists118568118581%_)))
                        (_%$%hd118578118615%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%lists118568118581%_))))
                    (if (null? _%$%hd118578118615%_)
                        (let ((_%r118620%_ _%$%tl118579118617%_))
                          (remove-nulls! _%r118620%_))
                        (let ((_%r118605%_ _%$%tl118579118617%_))
                          (_%$%K118574118599%_ _%r118605%_))))
                  (_%$%K118573118590%_)))))))
    (define append1!
      (lambda (_%l118550%_ _%x118551%_)
        (let ((_%l2118554%_ (cons _%x118551%_ '())))
          (if (pair? _%l118550%_)
              (let ((_%l118556%_ _%l118550%_))
                (let ((__tmp122974
                       (let ()
                         (declare (not safe))
                         (##last-pair _%l118556%_))))
                  (declare (not safe))
                  (##set-cdr! __tmp122974 _%l2118554%_))
                _%l118556%_)
              _%l2118554%_))))
    (define __append-reverse-until
      (lambda (_%pred118492%_ _%rhead118493%_ _%tail118494%_)
        (let ((_%pred118497%_ _%pred118492%_))
          (let _%loop118506%_ ((_%rhead118508%_ _%rhead118493%_)
                               (_%tail118509%_ _%tail118494%_))
            (let* ((_%$%rhead118511118520%_ _%rhead118508%_)
                   (_%$%E118514118524%_
                    (lambda ()
                      (error '"No clause matching"
                             _%$%rhead118511118520%_
                             '([])
                             '([a :: r]))
                      '#!void)))
              (let ((_%$%K118518118547%_
                     (lambda () (values '() _%tail118509%_)))
                    (_%$%K118515118531%_
                     (lambda (_%r118528%_ _%a118529%_)
                       (if (let ()
                             (declare (not safe))
                             (_%pred118497%_ _%a118529%_))
                           (values _%rhead118508%_ _%tail118509%_)
                           (_%loop118506%_
                            _%r118528%_
                            (cons _%a118529%_ _%tail118509%_))))))
                (let ((_%$%try-match118513118543%_
                       (lambda ()
                         (if (pair? _%$%rhead118511118520%_)
                             (let ((_%$%tl118517118536%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%rhead118511118520%_)))
                                   (_%$%hd118516118534%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%rhead118511118520%_))))
                               (let ((_%a118539%_ _%$%hd118516118534%_)
                                     (_%r118541%_ _%$%tl118517118536%_))
                                 (_%$%K118515118531%_
                                  _%r118541%_
                                  _%a118539%_)))
                             (_%$%E118514118524%_)))))
                  (if (null? _%$%rhead118511118520%_)
                      (_%$%K118518118547%_)
                      (_%$%try-match118513118543%_)))))))))
    (define append-reverse-until
      (lambda (_%pred118476%_ _%rhead118477%_ _%tail118478%_)
        (if (procedure? _%pred118476%_)
            (let ((_%pred118482%_ _%pred118476%_))
              (__append-reverse-until
               _%pred118482%_
               _%rhead118477%_
               _%tail118478%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@376.29-376.33"
               'contract:
               'procedure?
               'value:
               _%pred118476%_)
              '#!void))))
    (define __andmap1
      (lambda (_%f118425%_ _%lst118426%_)
        (let ((_%f118429%_ _%f118425%_))
          (let _%lp118438%_ ((_%rest118440%_ _%lst118426%_))
            (let* ((_%$%rest118442118450%_ _%rest118440%_)
                   (_%$%else118444118458%_ (lambda () '#t))
                   (_%$%K118446118464%_
                    (lambda (_%rest118461%_ _%x118462%_)
                      (if (let ()
                            (declare (not safe))
                            (_%f118429%_ _%x118462%_))
                          (_%lp118438%_ _%rest118461%_)
                          '#f))))
              (if (pair? _%$%rest118442118450%_)
                  (let ((_%$%hd118447118467%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest118442118450%_)))
                        (_%$%tl118448118469%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest118442118450%_))))
                    (let* ((_%x118472%_ _%$%hd118447118467%_)
                           (_%rest118474%_ _%$%tl118448118469%_))
                      (_%$%K118446118464%_ _%rest118474%_ _%x118472%_)))
                  (_%$%else118444118458%_)))))))
    (define andmap1
      (lambda (_%f118410%_ _%lst118411%_)
        (if (procedure? _%f118410%_)
            (let ((_%f118415%_ _%f118410%_))
              (__andmap1 _%f118415%_ _%lst118411%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@387.16-387.17"
               'contract:
               'procedure?
               'value:
               _%f118410%_)
              '#!void))))
    (define __andmap2
      (lambda (_%f118324%_ _%lst1118325%_ _%lst2118326%_)
        (let ((_%f118329%_ _%f118324%_))
          (let _%lp118338%_ ((_%rest1118340%_ _%lst1118325%_)
                             (_%rest2118341%_ _%lst2118326%_))
            (let* ((_%$%rest1118343118351%_ _%rest1118340%_)
                   (_%$%else118345118359%_ (lambda () '#t))
                   (_%$%K118347118398%_
                    (lambda (_%rest1118362%_ _%x1118363%_)
                      (let* ((_%$%rest2118364118372%_ _%rest2118341%_)
                             (_%$%else118366118380%_ (lambda () '#t))
                             (_%$%K118368118386%_
                              (lambda (_%rest2118383%_ _%x2118384%_)
                                (if (let ()
                                      (declare (not safe))
                                      (_%f118329%_ _%x1118363%_ _%x2118384%_))
                                    (_%lp118338%_
                                     _%rest1118362%_
                                     _%rest2118383%_)
                                    '#f))))
                        (if (pair? _%$%rest2118364118372%_)
                            (let ((_%$%hd118369118389%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest2118364118372%_)))
                                  (_%$%tl118370118391%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest2118364118372%_))))
                              (let* ((_%x2118394%_ _%$%hd118369118389%_)
                                     (_%rest2118396%_ _%$%tl118370118391%_))
                                (_%$%K118368118386%_
                                 _%rest2118396%_
                                 _%x2118394%_)))
                            (_%$%else118366118380%_))))))
              (if (pair? _%$%rest1118343118351%_)
                  (let ((_%$%hd118348118401%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest1118343118351%_)))
                        (_%$%tl118349118403%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest1118343118351%_))))
                    (let* ((_%x1118406%_ _%$%hd118348118401%_)
                           (_%rest1118408%_ _%$%tl118349118403%_))
                      (_%$%K118347118398%_ _%rest1118408%_ _%x1118406%_)))
                  (_%$%else118345118359%_)))))))
    (define andmap2
      (lambda (_%f118308%_ _%lst1118309%_ _%lst2118310%_)
        (if (procedure? _%f118308%_)
            (let ((_%f118314%_ _%f118308%_))
              (__andmap2 _%f118314%_ _%lst1118309%_ _%lst2118310%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@396.16-396.17"
               'contract:
               'procedure?
               'value:
               _%f118308%_)
              '#!void))))
    (define andmap__0
      (lambda (_%f118252%_ _%lst118253%_)
        (let* ((_%f118255%_ _%f118252%_) (_%lst118258%_ _%lst118253%_))
          (if (procedure? _%f118255%_)
              (let ((_%f118263%_ _%f118255%_))
                (__andmap1 _%f118263%_ _%lst118258%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f118255%_)
                '#!void)))))
    (define andmap__1
      (lambda (_%f118275%_ _%lst1118276%_ _%lst2118277%_)
        (let* ((_%f118279%_ _%f118275%_)
               (_%lst1118282%_ _%lst1118276%_)
               (_%lst2118285%_ _%lst2118277%_))
          (if (procedure? _%f118279%_)
              (let ((_%f118290%_ _%f118279%_))
                (__andmap2 _%f118290%_ _%lst1118282%_ _%lst2118285%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f118279%_)
                '#!void)))))
    (define andmap
      (lambda _g122975_
        (let ((_g122976_ (let () (declare (not safe)) (##length _g122975_))))
          (cond ((let () (declare (not safe)) (##fx= _g122976_ 2))
                 (apply andmap__0 _g122975_))
                ((let () (declare (not safe)) (##fx= _g122976_ 3))
                 (apply andmap__1 _g122975_))
                ((let () (declare (not safe)) (##fx>= _g122976_ 3))
                 (apply andmap* _g122975_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  andmap
                  _g122975_))))))
    (define __andmap*
      (lambda (_%f118209%_ . _%rest118210%_)
        (let ((_%f118213%_ _%f118209%_))
          (let _%recur118222%_ ((_%rest118224%_ _%rest118210%_))
            (if (let* ((_%f118227%_ pair?)
                       (_%lst118230%_ _%rest118224%_)
                       (_%f118235%_ _%f118227%_))
                  (__andmap1 _%f118235%_ _%lst118230%_))
                (if (let ((__tmp122977 (map car _%rest118224%_)))
                      (declare (not safe))
                      (##apply _%f118213%_ __tmp122977))
                    (_%recur118222%_ (map cdr _%rest118224%_))
                    '#f)
                '#t)))))
    (define andmap*
      (lambda (_%f118194%_ . _%rest118195%_)
        (if (procedure? _%f118194%_)
            (let ((_%f118199%_ _%f118194%_))
              (declare (not safe))
              (##apply __andmap* _%f118199%_ _%rest118195%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@416.16-416.17"
               'contract:
               'procedure?
               'value:
               _%f118194%_)
              '#!void))))
    (define __ormap1
      (lambda (_%f118141%_ _%lst118142%_)
        (let ((_%f118145%_ _%f118141%_))
          (let _%lp118154%_ ((_%rest118156%_ _%lst118142%_))
            (let* ((_%$%rest118157118165%_ _%rest118156%_)
                   (_%$%else118159118173%_ (lambda () '#f))
                   (_%$%K118161118182%_
                    (lambda (_%rest118176%_ _%x118177%_)
                      (let ((_%$e118179%_
                             (let ()
                               (declare (not safe))
                               (_%f118145%_ _%x118177%_))))
                        (if _%$e118179%_
                            _%$e118179%_
                            (_%lp118154%_ _%rest118176%_))))))
              (if (pair? _%$%rest118157118165%_)
                  (let ((_%$%hd118162118185%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest118157118165%_)))
                        (_%$%tl118163118187%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest118157118165%_))))
                    (let* ((_%x118190%_ _%$%hd118162118185%_)
                           (_%rest118192%_ _%$%tl118163118187%_))
                      (_%$%K118161118182%_ _%rest118192%_ _%x118190%_)))
                  (_%$%else118159118173%_)))))))
    (define ormap1
      (lambda (_%f118126%_ _%lst118127%_)
        (if (procedure? _%f118126%_)
            (let ((_%f118131%_ _%f118126%_))
              (__ormap1 _%f118131%_ _%lst118127%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@425.15-425.16"
               'contract:
               'procedure?
               'value:
               _%f118126%_)
              '#!void))))
    (define __ormap2
      (lambda (_%f118038%_ _%lst1118039%_ _%lst2118040%_)
        (let ((_%f118043%_ _%f118038%_))
          (let _%lp118052%_ ((_%rest1118054%_ _%lst1118039%_)
                             (_%rest2118055%_ _%lst2118040%_))
            (let* ((_%$%rest1118056118064%_ _%rest1118054%_)
                   (_%$%else118058118072%_ (lambda () '#f))
                   (_%$%K118060118114%_
                    (lambda (_%rest1118075%_ _%x1118076%_)
                      (let* ((_%$%rest2118077118085%_ _%rest2118055%_)
                             (_%$%else118079118093%_ (lambda () '#f))
                             (_%$%K118081118102%_
                              (lambda (_%rest2118096%_ _%x2118097%_)
                                (let ((_%$e118099%_
                                       (let ()
                                         (declare (not safe))
                                         (_%f118043%_
                                          _%x1118076%_
                                          _%x2118097%_))))
                                  (if _%$e118099%_
                                      _%$e118099%_
                                      (_%lp118052%_
                                       _%rest1118075%_
                                       _%rest2118096%_))))))
                        (if (pair? _%$%rest2118077118085%_)
                            (let ((_%$%hd118082118105%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest2118077118085%_)))
                                  (_%$%tl118083118107%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest2118077118085%_))))
                              (let* ((_%x2118110%_ _%$%hd118082118105%_)
                                     (_%rest2118112%_ _%$%tl118083118107%_))
                                (_%$%K118081118102%_
                                 _%rest2118112%_
                                 _%x2118110%_)))
                            (_%$%else118079118093%_))))))
              (if (pair? _%$%rest1118056118064%_)
                  (let ((_%$%hd118061118117%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest1118056118064%_)))
                        (_%$%tl118062118119%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest1118056118064%_))))
                    (let* ((_%x1118122%_ _%$%hd118061118117%_)
                           (_%rest1118124%_ _%$%tl118062118119%_))
                      (_%$%K118060118114%_ _%rest1118124%_ _%x1118122%_)))
                  (_%$%else118058118072%_)))))))
    (define ormap2
      (lambda (_%f118022%_ _%lst1118023%_ _%lst2118024%_)
        (if (procedure? _%f118022%_)
            (let ((_%f118028%_ _%f118022%_))
              (__ormap2 _%f118028%_ _%lst1118023%_ _%lst2118024%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@432.15-432.16"
               'contract:
               'procedure?
               'value:
               _%f118022%_)
              '#!void))))
    (define ormap__0
      (lambda (_%f117966%_ _%lst117967%_)
        (let* ((_%f117969%_ _%f117966%_) (_%lst117972%_ _%lst117967%_))
          (if (procedure? _%f117969%_)
              (let ((_%f117977%_ _%f117969%_))
                (__ormap1 _%f117977%_ _%lst117972%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f117969%_)
                '#!void)))))
    (define ormap__1
      (lambda (_%f117989%_ _%lst1117990%_ _%lst2117991%_)
        (let* ((_%f117993%_ _%f117989%_)
               (_%lst1117996%_ _%lst1117990%_)
               (_%lst2117999%_ _%lst2117991%_))
          (if (procedure? _%f117993%_)
              (let ((_%f118004%_ _%f117993%_))
                (__ormap2 _%f118004%_ _%lst1117996%_ _%lst2117999%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f117993%_)
                '#!void)))))
    (define ormap
      (lambda _g122978_
        (let ((_g122979_ (let () (declare (not safe)) (##length _g122978_))))
          (cond ((let () (declare (not safe)) (##fx= _g122979_ 2))
                 (apply ormap__0 _g122978_))
                ((let () (declare (not safe)) (##fx= _g122979_ 3))
                 (apply ormap__1 _g122978_))
                ((let () (declare (not safe)) (##fx>= _g122979_ 3))
                 (apply ormap* _g122978_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  ormap
                  _g122978_))))))
    (define __ormap*
      (lambda (_%f117922%_ . _%rest117923%_)
        (let ((_%f117926%_ _%f117922%_))
          (let _%recur117935%_ ((_%rest117937%_ _%rest117923%_))
            (if (let* ((_%f117939%_ pair?)
                       (_%lst117942%_ _%rest117937%_)
                       (_%f117947%_ _%f117939%_))
                  (__andmap1 _%f117947%_ _%lst117942%_))
                (let ((_%$e117963%_
                       (let ((__tmp122980 (map car _%rest117937%_)))
                         (declare (not safe))
                         (##apply _%f117926%_ __tmp122980))))
                  (if _%$e117963%_
                      _%$e117963%_
                      (_%recur117935%_ (map cdr _%rest117937%_))))
                '#f)))))
    (define ormap*
      (lambda (_%f117907%_ . _%rest117908%_)
        (if (procedure? _%f117907%_)
            (let ((_%f117912%_ _%f117907%_))
              (declare (not safe))
              (##apply __ormap* _%f117912%_ _%rest117908%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@450.15-450.16"
               'contract:
               'procedure?
               'value:
               _%f117907%_)
              '#!void))))
    (define __filter-map1
      (lambda (_%f117850%_ _%lst117851%_)
        (let ((_%f117854%_ _%f117850%_))
          (let _%recur117863%_ ((_%rest117865%_ _%lst117851%_))
            (let* ((_%$%rest117867117875%_ _%rest117865%_)
                   (_%$%else117869117883%_ (lambda () '()))
                   (_%$%K117871117895%_
                    (lambda (_%rest117886%_ _%x117887%_)
                      (let ((_%$e117889%_
                             (let ()
                               (declare (not safe))
                               (_%f117854%_ _%x117887%_))))
                        (if _%$e117889%_
                            (cons _%$e117889%_
                                  (_%recur117863%_ _%rest117886%_))
                            (_%recur117863%_ _%rest117886%_))))))
              (if (pair? _%$%rest117867117875%_)
                  (let ((_%$%hd117872117898%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest117867117875%_)))
                        (_%$%tl117873117900%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest117867117875%_))))
                    (let* ((_%x117903%_ _%$%hd117872117898%_)
                           (_%rest117905%_ _%$%tl117873117900%_))
                      (_%$%K117871117895%_ _%rest117905%_ _%x117903%_)))
                  (_%$%else117869117883%_)))))))
    (define filter-map1
      (lambda (_%f117835%_ _%lst117836%_)
        (if (procedure? _%f117835%_)
            (let ((_%f117840%_ _%f117835%_))
              (__filter-map1 _%f117840%_ _%lst117836%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@457.20-457.21"
               'contract:
               'procedure?
               'value:
               _%f117835%_)
              '#!void))))
    (define __filter-map2
      (lambda (_%f117743%_ _%lst1117744%_ _%lst2117745%_)
        (let ((_%f117748%_ _%f117743%_))
          (let _%recur117757%_ ((_%rest1117759%_ _%lst1117744%_)
                                (_%rest2117760%_ _%lst2117745%_))
            (let* ((_%$%rest1117762117770%_ _%rest1117759%_)
                   (_%$%else117764117778%_ (lambda () '()))
                   (_%$%K117766117823%_
                    (lambda (_%rest1117781%_ _%x1117782%_)
                      (let* ((_%$%rest2117783117791%_ _%rest2117760%_)
                             (_%$%else117785117799%_ (lambda () '()))
                             (_%$%K117787117811%_
                              (lambda (_%rest2117802%_ _%x2117803%_)
                                (let ((_%$e117805%_
                                       (let ()
                                         (declare (not safe))
                                         (_%f117748%_
                                          _%x1117782%_
                                          _%x2117803%_))))
                                  (if _%$e117805%_
                                      (cons _%$e117805%_
                                            (_%recur117757%_
                                             _%rest1117781%_
                                             _%rest2117802%_))
                                      (_%recur117757%_
                                       _%rest1117781%_
                                       _%rest2117802%_))))))
                        (if (pair? _%$%rest2117783117791%_)
                            (let ((_%$%hd117788117814%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest2117783117791%_)))
                                  (_%$%tl117789117816%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest2117783117791%_))))
                              (let* ((_%x2117819%_ _%$%hd117788117814%_)
                                     (_%rest2117821%_ _%$%tl117789117816%_))
                                (_%$%K117787117811%_
                                 _%rest2117821%_
                                 _%x2117819%_)))
                            (_%$%else117785117799%_))))))
              (if (pair? _%$%rest1117762117770%_)
                  (let ((_%$%hd117767117826%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest1117762117770%_)))
                        (_%$%tl117768117828%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest1117762117770%_))))
                    (let* ((_%x1117831%_ _%$%hd117767117826%_)
                           (_%rest1117833%_ _%$%tl117768117828%_))
                      (_%$%K117766117823%_ _%rest1117833%_ _%x1117831%_)))
                  (_%$%else117764117778%_)))))))
    (define filter-map2
      (lambda (_%f117727%_ _%lst1117728%_ _%lst2117729%_)
        (if (procedure? _%f117727%_)
            (let ((_%f117733%_ _%f117727%_))
              (__filter-map2 _%f117733%_ _%lst1117728%_ _%lst2117729%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@468.20-468.21"
               'contract:
               'procedure?
               'value:
               _%f117727%_)
              '#!void))))
    (define filter-map__0
      (lambda (_%f117671%_ _%lst117672%_)
        (let* ((_%f117674%_ _%f117671%_) (_%lst117677%_ _%lst117672%_))
          (if (procedure? _%f117674%_)
              (let ((_%f117682%_ _%f117674%_))
                (__filter-map1 _%f117682%_ _%lst117677%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f117674%_)
                '#!void)))))
    (define filter-map__1
      (lambda (_%f117694%_ _%lst1117695%_ _%lst2117696%_)
        (let* ((_%f117698%_ _%f117694%_)
               (_%lst1117701%_ _%lst1117695%_)
               (_%lst2117704%_ _%lst2117696%_))
          (if (procedure? _%f117698%_)
              (let ((_%f117709%_ _%f117698%_))
                (__filter-map2 _%f117709%_ _%lst1117701%_ _%lst2117704%_))
              (begin
                (raise-contract-violation-error
                 '"contract violation"
                 'context:
                 'gerbil/runtime/util
                 'contract:
                 'procedure?
                 'value:
                 _%f117698%_)
                '#!void)))))
    (define filter-map
      (lambda _g122981_
        (let ((_g122982_ (let () (declare (not safe)) (##length _g122981_))))
          (cond ((let () (declare (not safe)) (##fx= _g122982_ 2))
                 (apply filter-map__0 _g122981_))
                ((let () (declare (not safe)) (##fx= _g122982_ 3))
                 (apply filter-map__1 _g122981_))
                ((let () (declare (not safe)) (##fx>= _g122982_ 3))
                 (apply filter-map* _g122981_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  filter-map
                  _g122981_))))))
    (define __filter-map*
      (lambda (_%f117622%_ . _%rest117623%_)
        (let ((_%f117626%_ _%f117622%_))
          (let _%recur117635%_ ((_%rest117637%_ _%rest117623%_))
            (if (let* ((_%f117640%_ pair?)
                       (_%lst117643%_ _%rest117637%_)
                       (_%f117648%_ _%f117640%_))
                  (__andmap1 _%f117648%_ _%lst117643%_))
                (let ((_%$e117665%_
                       (let ((__tmp122983 (map car _%rest117637%_)))
                         (declare (not safe))
                         (##apply _%f117626%_ __tmp122983))))
                  (if _%$e117665%_
                      (cons _%$e117665%_
                            (_%recur117635%_ (map cdr _%rest117637%_)))
                      (_%recur117635%_ (map cdr _%rest117637%_))))
                '())))))
    (define filter-map*
      (lambda (_%f117607%_ . _%rest117608%_)
        (if (procedure? _%f117607%_)
            (let ((_%f117612%_ _%f117607%_))
              (declare (not safe))
              (##apply __filter-map* _%f117612%_ _%rest117608%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@490.20-490.21"
               'contract:
               'procedure?
               'value:
               _%f117607%_)
              '#!void))))
    (define agetq__%
      (lambda (_%key117583%_ _%lst117585%_ _%default117587%_)
        (let ((_%$e117590%_
               (if (pair? _%lst117585%_)
                   (assq _%key117583%_ _%lst117585%_)
                   '#f)))
          (if _%$e117590%_
              (cdr _%$e117590%_)
              (if (procedure? _%default117587%_)
                  (_%default117587%_ _%key117583%_)
                  _%default117587%_)))))
    (define agetq__0
      (lambda (_%key117598%_ _%lst117599%_)
        (let ((_%default117601%_ '#f))
          (agetq__% _%key117598%_ _%lst117599%_ _%default117601%_))))
    (define agetq
      (lambda _g122984_
        (let ((_g122985_ (let () (declare (not safe)) (##length _g122984_))))
          (cond ((let () (declare (not safe)) (##fx= _g122985_ 2))
                 (apply agetq__0 _g122984_))
                ((let () (declare (not safe)) (##fx= _g122985_ 3))
                 (apply agetq__% _g122984_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  agetq
                  _g122984_))))))
    (define agetv__%
      (lambda (_%key117558%_ _%lst117560%_ _%default117562%_)
        (let ((_%$e117565%_
               (if (pair? _%lst117560%_)
                   (assv _%key117558%_ _%lst117560%_)
                   '#f)))
          (if _%$e117565%_
              (cdr _%$e117565%_)
              (if (procedure? _%default117562%_)
                  (_%default117562%_ _%key117558%_)
                  _%default117562%_)))))
    (define agetv__0
      (lambda (_%key117573%_ _%lst117574%_)
        (let ((_%default117576%_ '#f))
          (agetv__% _%key117573%_ _%lst117574%_ _%default117576%_))))
    (define agetv
      (lambda _g122986_
        (let ((_g122987_ (let () (declare (not safe)) (##length _g122986_))))
          (cond ((let () (declare (not safe)) (##fx= _g122987_ 2))
                 (apply agetv__0 _g122986_))
                ((let () (declare (not safe)) (##fx= _g122987_ 3))
                 (apply agetv__% _g122986_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  agetv
                  _g122986_))))))
    (define aget__%
      (lambda (_%key117533%_ _%lst117535%_ _%default117537%_)
        (let ((_%$e117540%_
               (if (pair? _%lst117535%_)
                   (assoc _%key117533%_ _%lst117535%_)
                   '#f)))
          (if _%$e117540%_
              (cdr _%$e117540%_)
              (if (procedure? _%default117537%_)
                  (_%default117537%_ _%key117533%_)
                  _%default117537%_)))))
    (define aget__0
      (lambda (_%key117548%_ _%lst117549%_)
        (let ((_%default117551%_ '#f))
          (aget__% _%key117548%_ _%lst117549%_ _%default117551%_))))
    (define aget
      (lambda _g122988_
        (let ((_g122989_ (let () (declare (not safe)) (##length _g122988_))))
          (cond ((let () (declare (not safe)) (##fx= _g122989_ 2))
                 (apply aget__0 _g122988_))
                ((let () (declare (not safe)) (##fx= _g122989_ 3))
                 (apply aget__% _g122988_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  aget
                  _g122988_))))))
    (define assgetq agetq)
    (define assgetv agetv)
    (define assget aget)
    (define pgetq__%
      (lambda (_%key117462%_ _%lst117464%_ _%default117466%_)
        (let _%lp117469%_ ((_%rest117472%_ _%lst117464%_))
          (let* ((_%$%rest117474117484%_ _%rest117472%_)
                 (_%$%else117476117492%_
                  (lambda ()
                    (if (procedure? _%default117466%_)
                        (_%default117466%_ _%key117462%_)
                        _%default117466%_)))
                 (_%$%K117478117501%_
                  (lambda (_%rest117495%_ _%v117496%_ _%k117498%_)
                    (if (eq? _%k117498%_ _%key117462%_)
                        _%v117496%_
                        (_%lp117469%_ _%rest117495%_)))))
            (if (pair? _%$%rest117474117484%_)
                (let ((_%$%hd117479117504%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest117474117484%_)))
                      (_%$%tl117480117506%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest117474117484%_))))
                  (let ((_%k117509%_ _%$%hd117479117504%_))
                    (if (pair? _%$%tl117480117506%_)
                        (let ((_%$%hd117481117511%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%tl117480117506%_)))
                              (_%$%tl117482117513%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%tl117480117506%_))))
                          (let* ((_%v117516%_ _%$%hd117481117511%_)
                                 (_%rest117518%_ _%$%tl117482117513%_))
                            (_%$%K117478117501%_
                             _%rest117518%_
                             _%v117516%_
                             _%k117509%_)))
                        (_%$%else117476117492%_))))
                (_%$%else117476117492%_))))))
    (define pgetq__0
      (lambda (_%key117523%_ _%lst117524%_)
        (let ((_%default117526%_ '#f))
          (pgetq__% _%key117523%_ _%lst117524%_ _%default117526%_))))
    (define pgetq
      (lambda _g122990_
        (let ((_g122991_ (let () (declare (not safe)) (##length _g122990_))))
          (cond ((let () (declare (not safe)) (##fx= _g122991_ 2))
                 (apply pgetq__0 _g122990_))
                ((let () (declare (not safe)) (##fx= _g122991_ 3))
                 (apply pgetq__% _g122990_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  pgetq
                  _g122990_))))))
    (define pgetv__%
      (lambda (_%key117391%_ _%lst117393%_ _%default117395%_)
        (let _%lp117398%_ ((_%rest117401%_ _%lst117393%_))
          (let* ((_%$%rest117403117413%_ _%rest117401%_)
                 (_%$%else117405117421%_
                  (lambda ()
                    (if (procedure? _%default117395%_)
                        (_%default117395%_ _%key117391%_)
                        _%default117395%_)))
                 (_%$%K117407117430%_
                  (lambda (_%rest117424%_ _%v117425%_ _%k117427%_)
                    (if (eqv? _%k117427%_ _%key117391%_)
                        _%v117425%_
                        (_%lp117398%_ _%rest117424%_)))))
            (if (pair? _%$%rest117403117413%_)
                (let ((_%$%hd117408117433%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest117403117413%_)))
                      (_%$%tl117409117435%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest117403117413%_))))
                  (let ((_%k117438%_ _%$%hd117408117433%_))
                    (if (pair? _%$%tl117409117435%_)
                        (let ((_%$%hd117410117440%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%tl117409117435%_)))
                              (_%$%tl117411117442%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%tl117409117435%_))))
                          (let* ((_%v117445%_ _%$%hd117410117440%_)
                                 (_%rest117447%_ _%$%tl117411117442%_))
                            (_%$%K117407117430%_
                             _%rest117447%_
                             _%v117445%_
                             _%k117438%_)))
                        (_%$%else117405117421%_))))
                (_%$%else117405117421%_))))))
    (define pgetv__0
      (lambda (_%key117452%_ _%lst117453%_)
        (let ((_%default117455%_ '#f))
          (pgetv__% _%key117452%_ _%lst117453%_ _%default117455%_))))
    (define pgetv
      (lambda _g122992_
        (let ((_g122993_ (let () (declare (not safe)) (##length _g122992_))))
          (cond ((let () (declare (not safe)) (##fx= _g122993_ 2))
                 (apply pgetv__0 _g122992_))
                ((let () (declare (not safe)) (##fx= _g122993_ 3))
                 (apply pgetv__% _g122992_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  pgetv
                  _g122992_))))))
    (define pget__%
      (lambda (_%key117320%_ _%lst117322%_ _%default117324%_)
        (let _%lp117327%_ ((_%rest117330%_ _%lst117322%_))
          (let* ((_%$%rest117332117342%_ _%rest117330%_)
                 (_%$%else117334117350%_
                  (lambda ()
                    (if (procedure? _%default117324%_)
                        (_%default117324%_ _%key117320%_)
                        _%default117324%_)))
                 (_%$%K117336117359%_
                  (lambda (_%rest117353%_ _%v117354%_ _%k117356%_)
                    (if (equal? _%k117356%_ _%key117320%_)
                        _%v117354%_
                        (_%lp117327%_ _%rest117353%_)))))
            (if (pair? _%$%rest117332117342%_)
                (let ((_%$%hd117337117362%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest117332117342%_)))
                      (_%$%tl117338117364%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest117332117342%_))))
                  (let ((_%k117367%_ _%$%hd117337117362%_))
                    (if (pair? _%$%tl117338117364%_)
                        (let ((_%$%hd117339117369%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%tl117338117364%_)))
                              (_%$%tl117340117371%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%tl117338117364%_))))
                          (let* ((_%v117374%_ _%$%hd117339117369%_)
                                 (_%rest117376%_ _%$%tl117340117371%_))
                            (_%$%K117336117359%_
                             _%rest117376%_
                             _%v117374%_
                             _%k117367%_)))
                        (_%$%else117334117350%_))))
                (_%$%else117334117350%_))))))
    (define pget__0
      (lambda (_%key117381%_ _%lst117382%_)
        (let ((_%default117384%_ '#f))
          (pget__% _%key117381%_ _%lst117382%_ _%default117384%_))))
    (define pget
      (lambda _g122994_
        (let ((_g122995_ (let () (declare (not safe)) (##length _g122994_))))
          (cond ((let () (declare (not safe)) (##fx= _g122995_ 2))
                 (apply pget__0 _g122994_))
                ((let () (declare (not safe)) (##fx= _g122995_ 3))
                 (apply pget__% _g122994_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  pget
                  _g122994_))))))
    (define __find
      (lambda (_%pred117280%_ _%lst117281%_)
        (let* ((_%pred117284%_ _%pred117280%_)
               (_%$e117315%_
                (let* ((_%proc117293%_ _%pred117284%_)
                       (_%lst117296%_ _%lst117281%_)
                       (_%proc117301%_ _%proc117293%_))
                  (__memf _%proc117301%_ _%lst117296%_))))
          (if _%$e117315%_
              (let () (declare (not safe)) (##car _%$e117315%_))
              '#f))))
    (define find
      (lambda (_%pred117265%_ _%lst117266%_)
        (if (procedure? _%pred117265%_)
            (let ((_%pred117270%_ _%pred117265%_))
              (__find _%pred117270%_ _%lst117266%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@536.13-536.17"
               'contract:
               'procedure?
               'value:
               _%pred117265%_)
              '#!void))))
    (define __memf
      (lambda (_%proc117215%_ _%lst117216%_)
        (let ((_%proc117219%_ _%proc117215%_))
          (let _%lp117228%_ ((_%rest117230%_ _%lst117216%_))
            (let* ((_%$%rest117231117239%_ _%rest117230%_)
                   (_%$%else117233117247%_ (lambda () '#f))
                   (_%$%K117235117253%_
                    (lambda (_%tl117250%_ _%hd117251%_)
                      (if (let ()
                            (declare (not safe))
                            (_%proc117219%_ _%hd117251%_))
                          _%rest117230%_
                          (_%lp117228%_ _%tl117250%_)))))
              (if (pair? _%$%rest117231117239%_)
                  (let ((_%$%hd117236117256%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest117231117239%_)))
                        (_%$%tl117237117258%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest117231117239%_))))
                    (let* ((_%hd117261%_ _%$%hd117236117256%_)
                           (_%tl117263%_ _%$%tl117237117258%_))
                      (_%$%K117235117253%_ _%tl117263%_ _%hd117261%_)))
                  (_%$%else117233117247%_)))))))
    (define memf
      (lambda (_%proc117200%_ _%lst117201%_)
        (if (procedure? _%proc117200%_)
            (let ((_%proc117205%_ _%proc117200%_))
              (__memf _%proc117205%_ _%lst117201%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@541.13-541.17"
               'contract:
               'procedure?
               'value:
               _%proc117200%_)
              '#!void))))
    (define remove1
      (lambda (_%el117123%_ _%lst117125%_)
        (let _%lp117128%_ ((_%rest117131%_ _%lst117125%_) (_%r117133%_ '()))
          (let* ((_%$%rest117135117143%_ _%rest117131%_)
                 (_%$%else117137117151%_ (lambda () _%lst117125%_))
                 (_%$%K117139117188%_
                  (lambda (_%rest117154%_ _%hd117155%_)
                    (if (equal? _%el117123%_ _%hd117155%_)
                        (let* ((_%f117158%_ cons)
                               (_%iv117161%_ _%rest117154%_)
                               (_%lst117164%_ _%r117133%_)
                               (_%f117169%_ _%f117158%_))
                          (__foldl1 _%f117169%_ _%iv117161%_ _%lst117164%_))
                        (_%lp117128%_
                         _%rest117154%_
                         (cons _%hd117155%_ _%r117133%_))))))
            (if (pair? _%$%rest117135117143%_)
                (let ((_%$%hd117140117191%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest117135117143%_)))
                      (_%$%tl117141117193%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest117135117143%_))))
                  (let* ((_%hd117196%_ _%$%hd117140117191%_)
                         (_%rest117198%_ _%$%tl117141117193%_))
                    (_%$%K117139117188%_ _%rest117198%_ _%hd117196%_)))
                (_%$%else117137117151%_))))))
    (define remv1
      (lambda (_%el117046%_ _%lst117048%_)
        (let _%lp117051%_ ((_%rest117054%_ _%lst117048%_) (_%r117056%_ '()))
          (let* ((_%$%rest117058117066%_ _%rest117054%_)
                 (_%$%else117060117074%_ (lambda () _%lst117048%_))
                 (_%$%K117062117111%_
                  (lambda (_%rest117077%_ _%hd117078%_)
                    (if (eqv? _%el117046%_ _%hd117078%_)
                        (let* ((_%f117081%_ cons)
                               (_%iv117084%_ _%rest117077%_)
                               (_%lst117087%_ _%r117056%_)
                               (_%f117092%_ _%f117081%_))
                          (__foldl1 _%f117092%_ _%iv117084%_ _%lst117087%_))
                        (_%lp117051%_
                         _%rest117077%_
                         (cons _%hd117078%_ _%r117056%_))))))
            (if (pair? _%$%rest117058117066%_)
                (let ((_%$%hd117063117114%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest117058117066%_)))
                      (_%$%tl117064117116%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest117058117066%_))))
                  (let* ((_%hd117119%_ _%$%hd117063117114%_)
                         (_%rest117121%_ _%$%tl117064117116%_))
                    (_%$%K117062117111%_ _%rest117121%_ _%hd117119%_)))
                (_%$%else117060117074%_))))))
    (define remq1
      (lambda (_%el116969%_ _%lst116971%_)
        (let _%lp116974%_ ((_%rest116977%_ _%lst116971%_) (_%r116979%_ '()))
          (let* ((_%$%rest116981116989%_ _%rest116977%_)
                 (_%$%else116983116997%_ (lambda () _%lst116971%_))
                 (_%$%K116985117034%_
                  (lambda (_%rest117000%_ _%hd117001%_)
                    (if (eq? _%el116969%_ _%hd117001%_)
                        (let* ((_%f117004%_ cons)
                               (_%iv117007%_ _%rest117000%_)
                               (_%lst117010%_ _%r116979%_)
                               (_%f117015%_ _%f117004%_))
                          (__foldl1 _%f117015%_ _%iv117007%_ _%lst117010%_))
                        (_%lp116974%_
                         _%rest117000%_
                         (cons _%hd117001%_ _%r116979%_))))))
            (if (pair? _%$%rest116981116989%_)
                (let ((_%$%hd116986117037%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest116981116989%_)))
                      (_%$%tl116987117039%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest116981116989%_))))
                  (let* ((_%hd117042%_ _%$%hd116986117037%_)
                         (_%rest117044%_ _%$%tl116987117039%_))
                    (_%$%K116985117034%_ _%rest117044%_ _%hd117042%_)))
                (_%$%else116983116997%_))))))
    (define __remf
      (lambda (_%proc116886%_ _%lst116887%_)
        (let ((_%proc116890%_ _%proc116886%_))
          (let _%lp116899%_ ((_%rest116901%_ _%lst116887%_) (_%r116902%_ '()))
            (let* ((_%$%rest116903116911%_ _%rest116901%_)
                   (_%$%else116905116919%_ (lambda () _%lst116887%_))
                   (_%$%K116907116957%_
                    (lambda (_%rest116922%_ _%hd116923%_)
                      (if (let ()
                            (declare (not safe))
                            (_%proc116890%_ _%hd116923%_))
                          (let* ((_%f116925%_ cons)
                                 (_%iv116928%_ _%rest116922%_)
                                 (_%lst116931%_ _%r116902%_)
                                 (_%f116936%_ _%f116925%_))
                            (__foldl1 _%f116936%_ _%iv116928%_ _%lst116931%_))
                          (_%lp116899%_
                           _%rest116922%_
                           (cons _%hd116923%_ _%r116902%_))))))
              (if (pair? _%$%rest116903116911%_)
                  (let ((_%$%hd116908116960%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest116903116911%_)))
                        (_%$%tl116909116962%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest116903116911%_))))
                    (let* ((_%hd116965%_ _%$%hd116908116960%_)
                           (_%rest116967%_ _%$%tl116909116962%_))
                      (_%$%K116907116957%_ _%rest116967%_ _%hd116965%_)))
                  (_%$%else116905116919%_)))))))
    (define remf
      (lambda (_%proc116871%_ _%lst116872%_)
        (if (procedure? _%proc116871%_)
            (let ((_%proc116876%_ _%proc116871%_))
              (__remf _%proc116876%_ _%lst116872%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@563.13-563.17"
               'contract:
               'procedure?
               'value:
               _%proc116871%_)
              '#!void))))
    (define __1+
      (lambda (_%x116859%_)
        (let ((_%x116862%_ _%x116859%_)) (+ _%x116862%_ '1))))
    (define 1+
      (lambda (_%x116845%_)
        (if (number? _%x116845%_)
            (let ((_%x116849%_ _%x116845%_)) (__1+ _%x116849%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@572.11-572.12"
               'contract:
               'number?
               'value:
               _%x116845%_)
              '#!void))))
    (define __1-
      (lambda (_%x116833%_)
        (let ((_%x116836%_ _%x116833%_)) (- _%x116836%_ '1))))
    (define 1-
      (lambda (_%x116819%_)
        (if (number? _%x116819%_)
            (let ((_%x116823%_ _%x116819%_)) (__1- _%x116823%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@580.11-580.12"
               'contract:
               'number?
               'value:
               _%x116819%_)
              '#!void))))
    (define __fx1+
      (lambda (_%x116807%_)
        (let ((_%x116810%_ _%x116807%_))
          (declare (not safe))
          (##fx+ _%x116810%_ '1))))
    (define fx1+
      (lambda (_%x116793%_)
        (if (fixnum? _%x116793%_)
            (let ((_%x116797%_ _%x116793%_)) (__fx1+ _%x116797%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@588.13-588.14"
               'contract:
               'fixnum?
               'value:
               _%x116793%_)
              '#!void))))
    (define __fx1-
      (lambda (_%x116781%_)
        (let ((_%x116784%_ _%x116781%_))
          (declare (not safe))
          (##fx- _%x116784%_ '1))))
    (define fx1-
      (lambda (_%x116767%_)
        (if (fixnum? _%x116767%_)
            (let ((_%x116771%_ _%x116767%_)) (__fx1- _%x116771%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@596.13-596.14"
               'contract:
               'fixnum?
               'value:
               _%x116767%_)
              '#!void))))
    (define fxshift fxarithmetic-shift)
    (define fx/ fxquotient)
    (define fx% fxremainder)
    (define fx>=0?
      (lambda (_%x116764%_)
        (if (fixnum? _%x116764%_)
            (let () (declare (not safe)) (##fx>= _%x116764%_ '0))
            '#f)))
    (define fx>0?
      (lambda (_%x116761%_)
        (if (fixnum? _%x116761%_)
            (let () (declare (not safe)) (##fx> _%x116761%_ '0))
            '#f)))
    (define fx=0?
      (lambda (_%x116758%_)
        (let () (declare (not safe)) (##fx= _%x116758%_ '0))))
    (define fx<0?
      (lambda (_%x116755%_)
        (if (fixnum? _%x116755%_)
            (let () (declare (not safe)) (##fx< _%x116755%_ '0))
            '#f)))
    (define fx<=0?
      (lambda (_%x116752%_)
        (if (fixnum? _%x116752%_)
            (let () (declare (not safe)) (##fx<= _%x116752%_ '0))
            '#f)))
    (define interned-symbol?
      (lambda (_%x116749%_)
        (if (symbol? _%x116749%_) (not (uninterned-symbol? _%x116749%_)) '#f)))
    (define __display-as-string
      (lambda (_%x116643%_ _%port116644%_)
        (let ((_%port116647%_ _%port116644%_))
          (if (or (string? _%x116643%_)
                  (symbol? _%x116643%_)
                  (keyword? _%x116643%_)
                  (number? _%x116643%_)
                  (char? _%x116643%_))
              (display _%x116643%_ _%port116647%_)
              (if (pair? _%x116643%_)
                  (let ()
                    (let* ((_%x116670%_
                            (let () (declare (not safe)) (##car _%x116643%_)))
                           (_%port116673%_ _%port116647%_))
                      (if (output-port? _%port116673%_)
                          (let ((_%port116678%_ _%port116673%_))
                            (__display-as-string _%x116670%_ _%port116678%_))
                          (begin
                            (raise-contract-violation-error
                             '"contract violation"
                             'context:
                             'gerbil/runtime/util
                             'contract:
                             'output-port?
                             'value:
                             _%port116673%_)
                            '#!void)))
                    (let* ((_%x116693%_
                            (let () (declare (not safe)) (##cdr _%x116643%_)))
                           (_%port116696%_ _%port116647%_))
                      (if (output-port? _%port116696%_)
                          (let ((_%port116701%_ _%port116696%_))
                            (__display-as-string _%x116693%_ _%port116701%_))
                          (begin
                            (raise-contract-violation-error
                             '"contract violation"
                             'context:
                             'gerbil/runtime/util
                             'contract:
                             'output-port?
                             'value:
                             _%port116696%_)
                            '#!void))))
                  (if (vector? _%x116643%_)
                      (vector-for-each
                       (lambda (_%$%g116712116714%_)
                         (let* ((_%x116717%_ _%$%g116712116714%_)
                                (_%port116720%_ _%port116647%_))
                           (if (output-port? _%port116720%_)
                               (let ((_%port116725%_ _%port116720%_))
                                 (__display-as-string
                                  _%x116717%_
                                  _%port116725%_))
                               (begin
                                 (raise-contract-violation-error
                                  '"contract violation"
                                  'context:
                                  'gerbil/runtime/util
                                  'contract:
                                  'output-port?
                                  'value:
                                  _%port116720%_)
                                 '#!void))))
                       _%x116643%_)
                      (if (or (null? _%x116643%_)
                              (eq? _%x116643%_ '#!void)
                              (eof-object? _%x116643%_)
                              (boolean? _%x116643%_))
                          '#!void
                          (let ()
                            (raise-contract-violation-error
                             '"cannot convert as string"
                             'value:
                             _%x116643%_)
                            '#!void))))))))
    (define display-as-string
      (lambda (_%x116628%_ _%port116629%_)
        (if (output-port? _%port116629%_)
            (let ((_%port116633%_ _%port116629%_))
              (__display-as-string _%x116628%_ _%port116633%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@626.28-626.32"
               'contract:
               'output-port?
               'value:
               _%port116629%_)
              '#!void))))
    (define as-string__0
      (lambda (_%x116568%_)
        (if (string? _%x116568%_)
            _%x116568%_
            (if (symbol? _%x116568%_)
                (let () (declare (not safe)) (##symbol->string _%x116568%_))
                (if (keyword? _%x116568%_)
                    (let ()
                      (declare (not safe))
                      (##keyword->string _%x116568%_))
                    (if (number? _%x116568%_)
                        (let ()
                          (declare (not safe))
                          (##number->string _%x116568%_))
                        (call-with-output-string
                         '()
                         (lambda (_%$%g116574116576%_)
                           (let* ((_%x116579%_ _%x116568%_)
                                  (_%port116582%_ _%$%g116574116576%_))
                             (if (output-port? _%port116582%_)
                                 (let ((_%port116587%_ _%port116582%_))
                                   (__display-as-string
                                    _%x116579%_
                                    _%port116587%_))
                                 (begin
                                   (raise-contract-violation-error
                                    '"contract violation"
                                    'context:
                                    'gerbil/runtime/util
                                    'contract:
                                    'output-port?
                                    'value:
                                    _%port116582%_)
                                   '#!void)))))))))))
    (define as-string__1
      (lambda _%args116601%_
        (call-with-output-string
         '()
         (lambda (_%$%g116602116604%_)
           (let* ((_%x116607%_ _%args116601%_)
                  (_%port116610%_ _%$%g116602116604%_))
             (if (output-port? _%port116610%_)
                 (let ((_%port116615%_ _%port116610%_))
                   (__display-as-string _%x116607%_ _%port116615%_))
                 (begin
                   (raise-contract-violation-error
                    '"contract violation"
                    'context:
                    'gerbil/runtime/util
                    'contract:
                    'output-port?
                    'value:
                    _%port116610%_)
                   '#!void)))))))
    (define as-string
      (lambda _g122996_
        (let ((_g122997_ (let () (declare (not safe)) (##length _g122996_))))
          (cond ((let () (declare (not safe)) (##fx= _g122997_ 1))
                 (apply as-string__0 _g122996_))
                (#t
                 (apply (lambda _%args116601%_
                          (let ()
                            (declare (not safe))
                            (##apply as-string__1 _%args116601%_)))
                        _g122996_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  as-string
                  _g122996_))))))
    (define make-symbol__0
      (lambda (_%x116564%_)
        (if (interned-symbol? _%x116564%_)
            _%x116564%_
            (let ((__tmp122998 (as-string__0 _%x116564%_)))
              (declare (not safe))
              (##string->symbol __tmp122998)))))
    (define make-symbol__1
      (lambda _%args116566%_
        (let ((__tmp122999
               (let ()
                 (declare (not safe))
                 (##apply as-string _%args116566%_))))
          (declare (not safe))
          (##string->symbol __tmp122999))))
    (define make-symbol
      (lambda _g123000_
        (let ((_g123001_ (let () (declare (not safe)) (##length _g123000_))))
          (cond ((let () (declare (not safe)) (##fx= _g123001_ 1))
                 (apply make-symbol__0 _g123000_))
                (#t
                 (apply (lambda _%args116566%_
                          (let ()
                            (declare (not safe))
                            (##apply make-symbol__1 _%args116566%_)))
                        _g123000_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-symbol
                  _g123000_))))))
    (define make-keyword__0
      (lambda (_%x116560%_)
        (if (interned-keyword? _%x116560%_)
            _%x116560%_
            (let ((__tmp123002 (as-string__0 _%x116560%_)))
              (declare (not safe))
              (##string->keyword __tmp123002)))))
    (define make-keyword__1
      (lambda _%args116562%_
        (let ((__tmp123003
               (let ()
                 (declare (not safe))
                 (##apply as-string _%args116562%_))))
          (declare (not safe))
          (##string->keyword __tmp123003))))
    (define make-keyword
      (lambda _g123004_
        (let ((_g123005_ (let () (declare (not safe)) (##length _g123004_))))
          (cond ((let () (declare (not safe)) (##fx= _g123005_ 1))
                 (apply make-keyword__0 _g123004_))
                (#t
                 (apply (lambda _%args116562%_
                          (let ()
                            (declare (not safe))
                            (##apply make-keyword__1 _%args116562%_)))
                        _g123004_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-keyword
                  _g123004_))))))
    (define interned-keyword?
      (lambda (_%x116557%_)
        (if (keyword? _%x116557%_)
            (not (uninterned-keyword? _%x116557%_))
            '#f)))
    (define __symbol->keyword
      (lambda (_%sym116545%_)
        (let ((_%sym116548%_ _%sym116545%_))
          (if (uninterned-symbol? _%sym116548%_)
              (let ((__tmp123006
                     (let ()
                       (declare (not safe))
                       (##symbol->string _%sym116548%_))))
                (declare (not safe))
                (##string->uninterned-keyword __tmp123006))
              (let ((__tmp123007
                     (let ()
                       (declare (not safe))
                       (##symbol->string _%sym116548%_))))
                (declare (not safe))
                (##string->keyword __tmp123007))))))
    (define symbol->keyword
      (lambda (_%sym116531%_)
        (if (symbol? _%sym116531%_)
            (let ((_%sym116535%_ _%sym116531%_))
              (__symbol->keyword _%sym116535%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@670.24-670.27"
               'contract:
               'symbol?
               'value:
               _%sym116531%_)
              '#!void))))
    (define __keyword->symbol
      (lambda (_%sym116519%_)
        (let ((_%sym116522%_ _%sym116519%_))
          (if (uninterned-keyword? _%sym116522%_)
              (let ((__tmp123008
                     (let ()
                       (declare (not safe))
                       (##keyword->string _%sym116522%_))))
                (declare (not safe))
                (##string->uninterned-symbol __tmp123008))
              (let ((__tmp123009
                     (let ()
                       (declare (not safe))
                       (##keyword->string _%sym116522%_))))
                (declare (not safe))
                (##string->symbol __tmp123009))))))
    (define keyword->symbol
      (lambda (_%sym116505%_)
        (if (keyword? _%sym116505%_)
            (let ((_%sym116509%_ _%sym116505%_))
              (__keyword->symbol _%sym116509%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@676.24-676.27"
               'contract:
               'keyword?
               'value:
               _%sym116505%_)
              '#!void))))
    (define __bytes->string__%
      (lambda (_%bstr116465%_ _%enc116466%_)
        (let* ((_%bstr116469%_ _%bstr116465%_) (_%enc116477%_ _%enc116466%_))
          (if (eq? _%enc116477%_ 'UTF-8)
              (let () (declare (not safe)) (##utf8->string _%bstr116469%_))
              (let* ((_%in116486%_
                      (open-input-u8vector
                       (list 'char-encoding:
                             _%enc116477%_
                             'init:
                             _%bstr116469%_)))
                     (_%len116488%_
                      (let ()
                        (declare (not safe))
                        (##u8vector-length _%bstr116469%_)))
                     (_%out116490%_
                      (let ()
                        (declare (not safe))
                        (##make-string _%len116488%_)))
                     (_%n116492%_
                      (read-substring
                       _%out116490%_
                       '0
                       _%len116488%_
                       _%in116486%_)))
                (string-shrink! _%out116490%_ _%n116492%_)
                _%out116490%_)))))
    (define __bytes->string__0
      (lambda (_%bstr116498%_)
        (let ((_%enc116500%_ 'UTF-8))
          (__bytes->string__% _%bstr116498%_ _%enc116500%_))))
    (define __bytes->string
      (lambda _g123010_
        (let ((_g123011_ (let () (declare (not safe)) (##length _g123010_))))
          (cond ((let () (declare (not safe)) (##fx= _g123011_ 1))
                 (apply __bytes->string__0 _g123010_))
                ((let () (declare (not safe)) (##fx= _g123011_ 2))
                 (apply __bytes->string__% _g123010_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __bytes->string
                  _g123010_))))))
    (define bytes->string__%
      (lambda (_%bstr116429%_ _%enc116430%_)
        (if (u8vector? _%bstr116429%_)
            (let ((_%bstr116434%_ _%bstr116429%_))
              (if (symbol? _%enc116430%_)
                  (let ((_%enc116444%_ _%enc116430%_))
                    (__bytes->string__% _%bstr116434%_ _%enc116444%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@683.25-683.28"
                     'contract:
                     'symbol?
                     'value:
                     _%enc116430%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@682.22-682.26"
               'contract:
               'u8vector?
               'value:
               _%bstr116429%_)
              '#!void))))
    (define bytes->string__0
      (lambda (_%bstr116457%_)
        (let ((_%enc116459%_ 'UTF-8))
          (bytes->string__% _%bstr116457%_ _%enc116459%_))))
    (define bytes->string
      (lambda _g123012_
        (let ((_g123013_ (let () (declare (not safe)) (##length _g123012_))))
          (cond ((let () (declare (not safe)) (##fx= _g123013_ 1))
                 (apply bytes->string__0 _g123012_))
                ((let () (declare (not safe)) (##fx= _g123013_ 2))
                 (apply bytes->string__% _g123012_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  bytes->string
                  _g123012_))))))
    (define __string->bytes__%
      (lambda (_%str116347%_ _%enc116348%_)
        (let* ((_%str116351%_ _%str116347%_) (_%enc116359%_ _%enc116348%_))
          (if (eq? _%enc116359%_ 'UTF-8)
              (let () (declare (not safe)) (##string->utf8 _%str116351%_))
              (let* ((_%str116368%_ _%str116351%_)
                     (_%start116371%_ '0)
                     (_%end116374%_
                      (let ()
                        (declare (not safe))
                        (##string-length _%str116351%_)))
                     (_%enc116377%_ _%enc116359%_)
                     (_%str116382%_ _%str116368%_))
                (if (nonnegative-fixnum? _%start116371%_)
                    (let ((_%start116398%_ _%start116371%_))
                      (if (nonnegative-fixnum? _%end116374%_)
                          (let ((_%end116408%_ _%end116374%_))
                            (__substring->bytes__%
                             _%str116382%_
                             _%start116398%_
                             _%end116408%_
                             _%enc116377%_))
                          (begin
                            (raise-contract-violation-error
                             '"contract violation"
                             'context:
                             'gerbil/runtime/util
                             'contract:
                             'nonnegative-fixnum?
                             'value:
                             _%end116374%_)
                            '#!void)))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/util
                       'contract:
                       'nonnegative-fixnum?
                       'value:
                       _%start116371%_)
                      '#!void)))))))
    (define __string->bytes__0
      (lambda (_%str116421%_)
        (let ((_%enc116423%_ 'UTF-8))
          (__string->bytes__% _%str116421%_ _%enc116423%_))))
    (define __string->bytes
      (lambda _g123014_
        (let ((_g123015_ (let () (declare (not safe)) (##length _g123014_))))
          (cond ((let () (declare (not safe)) (##fx= _g123015_ 1))
                 (apply __string->bytes__0 _g123014_))
                ((let () (declare (not safe)) (##fx= _g123015_ 2))
                 (apply __string->bytes__% _g123014_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __string->bytes
                  _g123014_))))))
    (define string->bytes__%
      (lambda (_%str116311%_ _%enc116312%_)
        (if (string? _%str116311%_)
            (let ((_%str116316%_ _%str116311%_))
              (if (symbol? _%enc116312%_)
                  (let ((_%enc116326%_ _%enc116312%_))
                    (__string->bytes__% _%str116316%_ _%enc116326%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@695.25-695.28"
                     'contract:
                     'symbol?
                     'value:
                     _%enc116312%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@694.22-694.25"
               'contract:
               'string?
               'value:
               _%str116311%_)
              '#!void))))
    (define string->bytes__0
      (lambda (_%str116339%_)
        (let ((_%enc116341%_ 'UTF-8))
          (string->bytes__% _%str116339%_ _%enc116341%_))))
    (define string->bytes
      (lambda _g123016_
        (let ((_g123017_ (let () (declare (not safe)) (##length _g123016_))))
          (cond ((let () (declare (not safe)) (##fx= _g123017_ 1))
                 (apply string->bytes__0 _g123016_))
                ((let () (declare (not safe)) (##fx= _g123017_ 2))
                 (apply string->bytes__% _g123016_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  string->bytes
                  _g123016_))))))
    (define __substring->bytes__%
      (lambda (_%str116263%_ _%start116264%_ _%end116265%_ _%enc116266%_)
        (let* ((_%str116269%_ _%str116263%_)
               (_%start116277%_ _%start116264%_)
               (_%end116285%_ _%end116265%_))
          (if (eq? _%enc116266%_ 'UTF-8)
              (string->utf8 _%str116269%_ _%start116277%_ _%end116285%_)
              (let ((_%out116294%_
                     (open-output-u8vector
                      (list 'char-encoding: _%enc116266%_))))
                (write-substring
                 _%str116269%_
                 _%start116277%_
                 _%end116285%_
                 _%out116294%_)
                (get-output-u8vector _%out116294%_))))))
    (define __substring->bytes__0
      (lambda (_%str116299%_ _%start116300%_ _%end116301%_)
        (let ((_%enc116303%_ 'UTF-8))
          (__substring->bytes__%
           _%str116299%_
           _%start116300%_
           _%end116301%_
           _%enc116303%_))))
    (define __substring->bytes
      (lambda _g123018_
        (let ((_g123019_ (let () (declare (not safe)) (##length _g123018_))))
          (cond ((let () (declare (not safe)) (##fx= _g123019_ 3))
                 (apply __substring->bytes__0 _g123018_))
                ((let () (declare (not safe)) (##fx= _g123019_ 4))
                 (apply __substring->bytes__% _g123018_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __substring->bytes
                  _g123018_))))))
    (define substring->bytes__%
      (lambda (_%str116211%_ _%start116212%_ _%end116213%_ _%enc116214%_)
        (if (string? _%str116211%_)
            (let ((_%str116218%_ _%str116211%_))
              (if (nonnegative-fixnum? _%start116212%_)
                  (let ((_%start116228%_ _%start116212%_))
                    (if (nonnegative-fixnum? _%end116213%_)
                        (let ((_%end116238%_ _%end116213%_))
                          (__substring->bytes__%
                           _%str116218%_
                           _%start116228%_
                           _%end116238%_
                           _%enc116214%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/util.ss\"@703.25-703.28"
                           'contract:
                           'nonnegative-fixnum?
                           'value:
                           _%end116213%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@702.25-702.30"
                     'contract:
                     'nonnegative-fixnum?
                     'value:
                     _%start116212%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@701.25-701.28"
               'contract:
               'string?
               'value:
               _%str116211%_)
              '#!void))))
    (define substring->bytes__0
      (lambda (_%str116251%_ _%start116252%_ _%end116253%_)
        (let ((_%enc116255%_ 'UTF-8))
          (substring->bytes__%
           _%str116251%_
           _%start116252%_
           _%end116253%_
           _%enc116255%_))))
    (define substring->bytes
      (lambda _g123020_
        (let ((_g123021_ (let () (declare (not safe)) (##length _g123020_))))
          (cond ((let () (declare (not safe)) (##fx= _g123021_ 3))
                 (apply substring->bytes__0 _g123020_))
                ((let () (declare (not safe)) (##fx= _g123021_ 4))
                 (apply substring->bytes__% _g123020_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  substring->bytes
                  _g123020_))))))
    (define __string-empty?
      (lambda (_%str116198%_)
        (let* ((_%str116201%_ _%str116198%_)
               (__tmp123022
                (let () (declare (not safe)) (##string-length _%str116201%_))))
          (declare (not safe))
          (##fxzero? __tmp123022))))
    (define string-empty?
      (lambda (_%str116184%_)
        (if (string? _%str116184%_)
            (let ((_%str116188%_ _%str116184%_))
              (__string-empty? _%str116188%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@712.22-712.25"
               'contract:
               'string?
               'value:
               _%str116184%_)
              '#!void))))
    (define __string-index__%
      (lambda (_%str116018%_ _%criterion116019%_ _%start116020%_ _%end116021%_)
        (let* ((_%str116024%_ _%str116018%_)
               (_%start116032%_ _%start116020%_)
               (_%end116040%_ _%end116021%_)
               (_%end116052%_
                (let ((_%$e116049%_ _%end116040%_))
                  (if _%$e116049%_
                      _%$e116049%_
                      (let ()
                        (declare (not safe))
                        (##string-length _%str116024%_))))))
          (if (< _%start116032%_ '0)
              (let ()
                (raise-contract-violation-error
                 '"invalid start for string-index"
                 'value:
                 (cons _%str116024%_ (cons _%start116032%_ '())))
                '#!void)
              (if (> _%end116052%_
                     (let ()
                       (declare (not safe))
                       (##string-length _%str116024%_)))
                  (let ()
                    (raise-contract-violation-error
                     '"invalid end for string-index"
                     'value:
                     (cons _%str116024%_ (cons _%end116052%_ '())))
                    '#!void)
                  (if (char? _%criterion116019%_)
                      (let* ((_%str116057%_ _%str116024%_)
                             (_%char116060%_ _%criterion116019%_)
                             (_%start116063%_ _%start116032%_)
                             (_%end116066%_ _%end116052%_)
                             (_%str116070%_ _%str116057%_)
                             (_%char116086%_ _%char116060%_)
                             (_%start116094%_ _%start116063%_)
                             (_%end116102%_ _%end116066%_))
                        (____string-index/char
                         _%str116070%_
                         _%char116086%_
                         _%start116094%_
                         _%end116102%_))
                      (if (procedure? _%criterion116019%_)
                          (let* ((_%str116112%_ _%str116024%_)
                                 (_%pred?116115%_ _%criterion116019%_)
                                 (_%start116118%_ _%start116032%_)
                                 (_%end116121%_ _%end116052%_)
                                 (_%str116125%_ _%str116112%_)
                                 (_%pred?116137%_ _%pred?116115%_)
                                 (_%start116145%_ _%start116118%_)
                                 (_%end116153%_ _%end116121%_))
                            (____string-index/pred
                             _%str116125%_
                             _%pred?116137%_
                             _%start116145%_
                             _%end116153%_))
                          (let ()
                            (raise-contract-violation-error
                             '"string-index criterion must be char or procedure"
                             'value:
                             _%criterion116019%_)
                            '#!void))))))))
    (define __string-index__0
      (lambda (_%str116166%_ _%criterion116167%_)
        (let* ((_%start116169%_ '0) (_%end116171%_ '#f))
          (__string-index__%
           _%str116166%_
           _%criterion116167%_
           _%start116169%_
           _%end116171%_))))
    (define __string-index__1
      (lambda (_%str116173%_ _%criterion116174%_ _%start116175%_)
        (let ((_%end116177%_ '#f))
          (__string-index__%
           _%str116173%_
           _%criterion116174%_
           _%start116175%_
           _%end116177%_))))
    (define __string-index
      (lambda _g123023_
        (let ((_g123024_ (let () (declare (not safe)) (##length _g123023_))))
          (cond ((let () (declare (not safe)) (##fx= _g123024_ 2))
                 (apply __string-index__0 _g123023_))
                ((let () (declare (not safe)) (##fx= _g123024_ 3))
                 (apply __string-index__1 _g123023_))
                ((let () (declare (not safe)) (##fx= _g123024_ 4))
                 (apply __string-index__% _g123023_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __string-index
                  _g123023_))))))
    (define string-index__%
      (lambda (_%str115953%_ _%criterion115954%_ _%start115955%_ _%end115956%_)
        (if (string? _%str115953%_)
            (let ((_%str115960%_ _%str115953%_))
              (if (nonnegative-fixnum? _%start115955%_)
                  (let ((_%start115970%_ _%start115955%_))
                    (if (or (not _%end115956%_) (fixnum? _%end115956%_))
                        (let ((_%end115986%_ _%end115956%_))
                          (__string-index__%
                           _%str115960%_
                           _%criterion115954%_
                           _%start115970%_
                           _%end115986%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/util.ss\"@722.21-722.24"
                           'contract:
                           '(? (or not fixnum?))
                           'value:
                           _%end115956%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@721.21-721.26"
                     'contract:
                     'nonnegative-fixnum?
                     'value:
                     _%start115955%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@719.21-719.24"
               'contract:
               'string?
               'value:
               _%str115953%_)
              '#!void))))
    (define string-index__0
      (lambda (_%str115999%_ _%criterion116000%_)
        (let* ((_%start116002%_ '0) (_%end116004%_ '#f))
          (string-index__%
           _%str115999%_
           _%criterion116000%_
           _%start116002%_
           _%end116004%_))))
    (define string-index__1
      (lambda (_%str116006%_ _%criterion116007%_ _%start116008%_)
        (let ((_%end116010%_ '#f))
          (string-index__%
           _%str116006%_
           _%criterion116007%_
           _%start116008%_
           _%end116010%_))))
    (define string-index
      (lambda _g123025_
        (let ((_g123026_ (let () (declare (not safe)) (##length _g123025_))))
          (cond ((let () (declare (not safe)) (##fx= _g123026_ 2))
                 (apply string-index__0 _g123025_))
                ((let () (declare (not safe)) (##fx= _g123026_ 3))
                 (apply string-index__1 _g123025_))
                ((let () (declare (not safe)) (##fx= _g123026_ 4))
                 (apply string-index__% _g123025_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  string-index
                  _g123025_))))))
    (define ____string-index/char
      (lambda (_%str115898%_ _%char115899%_ _%start115900%_ _%end115901%_)
        (let* ((_%str115904%_ _%str115898%_)
               (_%char115912%_ _%char115899%_)
               (_%start115920%_ _%start115900%_)
               (_%end115928%_ _%end115901%_))
          (let _%lp115937%_ ((_%k115939%_ _%start115920%_))
            (let ((_%k115941%_ _%k115939%_))
              (if (let ()
                    (declare (not safe))
                    (##fx< _%k115941%_ _%end115928%_))
                  (if (eq? _%char115912%_
                           (let ()
                             (declare (not safe))
                             (##string-ref _%str115904%_ _%k115941%_)))
                      _%k115941%_
                      (_%lp115937%_
                       (let () (declare (not safe)) (##fx+ _%k115941%_ '1))))
                  '#f))))))
    (define __string-index/char
      (lambda (_%str115859%_ _%char115860%_ _%start115861%_ _%end115862%_)
        (let* ((_%str115865%_ _%str115859%_)
               (_%char115873%_ _%char115860%_)
               (_%start115881%_ _%start115861%_)
               (_%end115889%_ _%end115862%_))
          (____string-index/char
           _%str115865%_
           _%char115873%_
           _%start115881%_
           _%end115889%_))))
    (define ____string-index/pred
      (lambda (_%str115805%_ _%pred?115806%_ _%start115807%_ _%end115808%_)
        (let* ((_%str115811%_ _%str115805%_)
               (_%pred?115819%_ _%pred?115806%_)
               (_%start115827%_ _%start115807%_)
               (_%end115835%_ _%end115808%_))
          (let _%lp115844%_ ((_%k115846%_ _%start115827%_))
            (let ((_%k115848%_ _%k115846%_))
              (if (let ()
                    (declare (not safe))
                    (##fx< _%k115848%_ _%end115835%_))
                  (if (let ((__tmp123027
                             (let ()
                               (declare (not safe))
                               (##string-ref _%str115811%_ _%k115848%_))))
                        (declare (not safe))
                        (_%pred?115819%_ __tmp123027))
                      _%k115848%_
                      (_%lp115844%_
                       (let () (declare (not safe)) (##fx+ _%k115848%_ '1))))
                  '#f))))))
    (define __string-index/pred
      (lambda (_%str115766%_ _%pred?115767%_ _%start115768%_ _%end115769%_)
        (let* ((_%str115772%_ _%str115766%_)
               (_%pred?115780%_ _%pred?115767%_)
               (_%start115788%_ _%start115768%_)
               (_%end115796%_ _%end115769%_))
          (____string-index/pred
           _%str115772%_
           _%pred?115780%_
           _%start115788%_
           _%end115796%_))))
    (define __string-rindex__%
      (lambda (_%str115606%_ _%criterion115607%_ _%start115608%_ _%end115609%_)
        (let* ((_%str115612%_ _%str115606%_)
               (_%start115620%_ _%start115608%_)
               (_%end115628%_ _%end115609%_))
          (if (>= _%start115620%_
                  (let ()
                    (declare (not safe))
                    (##string-length _%str115612%_)))
              (let ()
                (raise-contract-violation-error
                 '"invalid start for string-rindex"
                 'value:
                 (cons _%str115612%_ (cons _%start115620%_ '())))
                '#!void)
              (if (< _%end115628%_ '0)
                  (let ()
                    (raise-contract-violation-error
                     '"invalid end for string-rindex"
                     'value:
                     (cons _%str115612%_ (cons _%end115628%_ '())))
                    '#!void)
                  (if (char? _%criterion115607%_)
                      (let* ((_%str115640%_ _%str115612%_)
                             (_%char115643%_ _%criterion115607%_)
                             (_%start115646%_ _%start115620%_)
                             (_%end115649%_ _%end115628%_)
                             (_%str115653%_ _%str115640%_)
                             (_%char115668%_ _%char115643%_)
                             (_%start115676%_ _%start115646%_)
                             (_%end115684%_ _%end115649%_))
                        (____string-rindex/char
                         _%str115653%_
                         _%char115668%_
                         _%start115676%_
                         _%end115684%_))
                      (if (procedure? _%criterion115607%_)
                          (let* ((_%str115694%_ _%str115612%_)
                                 (_%pred?115697%_ _%criterion115607%_)
                                 (_%start115700%_ _%start115620%_)
                                 (_%end115703%_ _%end115628%_)
                                 (_%str115707%_ _%str115694%_)
                                 (_%pred?115719%_ _%pred?115697%_)
                                 (_%start115727%_ _%start115700%_)
                                 (_%end115735%_ _%end115703%_))
                            (____string-rindex/pred
                             _%str115707%_
                             _%pred?115719%_
                             _%start115727%_
                             _%end115735%_))
                          (let ()
                            (raise-contract-violation-error
                             '"string-rindex criterion must be char or procedure"
                             'value:
                             _%criterion115607%_)
                            '#!void))))))))
    (define __string-rindex__0
      (lambda (_%str115748%_ _%criterion115749%_)
        (let* ((_%start115751%_
                (let ((__tmp123028 (string-length _%str115748%_)))
                  (declare (not safe))
                  (##fx- __tmp123028 '1)))
               (_%end115753%_ '0))
          (__string-rindex__%
           _%str115748%_
           _%criterion115749%_
           _%start115751%_
           _%end115753%_))))
    (define __string-rindex__1
      (lambda (_%str115755%_ _%criterion115756%_ _%start115757%_)
        (let ((_%end115759%_ '0))
          (__string-rindex__%
           _%str115755%_
           _%criterion115756%_
           _%start115757%_
           _%end115759%_))))
    (define __string-rindex
      (lambda _g123029_
        (let ((_g123030_ (let () (declare (not safe)) (##length _g123029_))))
          (cond ((let () (declare (not safe)) (##fx= _g123030_ 2))
                 (apply __string-rindex__0 _g123029_))
                ((let () (declare (not safe)) (##fx= _g123030_ 3))
                 (apply __string-rindex__1 _g123029_))
                ((let () (declare (not safe)) (##fx= _g123030_ 4))
                 (apply __string-rindex__% _g123029_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __string-rindex
                  _g123029_))))))
    (define string-rindex__%
      (lambda (_%str115547%_ _%criterion115548%_ _%start115549%_ _%end115550%_)
        (if (string? _%str115547%_)
            (let ((_%str115554%_ _%str115547%_))
              (if (fixnum? _%start115549%_)
                  (let ((_%start115564%_ _%start115549%_))
                    (if (fixnum? _%end115550%_)
                        (let ((_%end115574%_ _%end115550%_))
                          (__string-rindex__%
                           _%str115554%_
                           _%criterion115548%_
                           _%start115564%_
                           _%end115574%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/util.ss\"@766.22-766.25"
                           'contract:
                           'fixnum?
                           'value:
                           _%end115550%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@765.22-765.27"
                     'contract:
                     'fixnum?
                     'value:
                     _%start115549%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@763.22-763.25"
               'contract:
               'string?
               'value:
               _%str115547%_)
              '#!void))))
    (define string-rindex__0
      (lambda (_%str115587%_ _%criterion115588%_)
        (let* ((_%start115590%_
                (let ((__tmp123031 (string-length _%str115587%_)))
                  (declare (not safe))
                  (##fx- __tmp123031 '1)))
               (_%end115592%_ '0))
          (string-rindex__%
           _%str115587%_
           _%criterion115588%_
           _%start115590%_
           _%end115592%_))))
    (define string-rindex__1
      (lambda (_%str115594%_ _%criterion115595%_ _%start115596%_)
        (let ((_%end115598%_ '0))
          (string-rindex__%
           _%str115594%_
           _%criterion115595%_
           _%start115596%_
           _%end115598%_))))
    (define string-rindex
      (lambda _g123032_
        (let ((_g123033_ (let () (declare (not safe)) (##length _g123032_))))
          (cond ((let () (declare (not safe)) (##fx= _g123033_ 2))
                 (apply string-rindex__0 _g123032_))
                ((let () (declare (not safe)) (##fx= _g123033_ 3))
                 (apply string-rindex__1 _g123032_))
                ((let () (declare (not safe)) (##fx= _g123033_ 4))
                 (apply string-rindex__% _g123032_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  string-rindex
                  _g123032_))))))
    (define ____string-rindex/char
      (lambda (_%str115492%_ _%char115493%_ _%start115494%_ _%end115495%_)
        (let* ((_%str115498%_ _%str115492%_)
               (_%char115506%_ _%char115493%_)
               (_%start115514%_ _%start115494%_)
               (_%end115522%_ _%end115495%_))
          (let _%lp115531%_ ((_%k115533%_ _%start115514%_))
            (let ((_%k115535%_ _%k115533%_))
              (if (let ()
                    (declare (not safe))
                    (##fx>= _%k115535%_ _%end115522%_))
                  (if (eq? _%char115506%_
                           (let ()
                             (declare (not safe))
                             (##string-ref _%str115498%_ _%k115535%_)))
                      _%k115535%_
                      (_%lp115531%_
                       (let () (declare (not safe)) (##fx- _%k115535%_ '1))))
                  '#f))))))
    (define __string-rindex/char
      (lambda (_%str115453%_ _%char115454%_ _%start115455%_ _%end115456%_)
        (let* ((_%str115459%_ _%str115453%_)
               (_%char115467%_ _%char115454%_)
               (_%start115475%_ _%start115455%_)
               (_%end115483%_ _%end115456%_))
          (____string-rindex/char
           _%str115459%_
           _%char115467%_
           _%start115475%_
           _%end115483%_))))
    (define ____string-rindex/pred
      (lambda (_%str115399%_ _%pred?115400%_ _%start115401%_ _%end115402%_)
        (let* ((_%str115405%_ _%str115399%_)
               (_%pred?115413%_ _%pred?115400%_)
               (_%start115421%_ _%start115401%_)
               (_%end115429%_ _%end115402%_))
          (let _%lp115438%_ ((_%k115440%_ _%start115421%_))
            (let ((_%k115442%_ _%k115440%_))
              (if (let ()
                    (declare (not safe))
                    (##fx>= _%k115442%_ _%end115429%_))
                  (if (let ((__tmp123034
                             (let ()
                               (declare (not safe))
                               (##string-ref _%str115405%_ _%k115442%_))))
                        (declare (not safe))
                        (_%pred?115413%_ __tmp123034))
                      _%k115442%_
                      (_%lp115438%_
                       (let () (declare (not safe)) (##fx- _%k115442%_ '1))))
                  '#f))))))
    (define __string-rindex/pred
      (lambda (_%str115360%_ _%pred?115361%_ _%start115362%_ _%end115363%_)
        (let* ((_%str115366%_ _%str115360%_)
               (_%pred?115374%_ _%pred?115361%_)
               (_%start115382%_ _%start115362%_)
               (_%end115390%_ _%end115363%_))
          (____string-rindex/pred
           _%str115366%_
           _%pred?115374%_
           _%start115382%_
           _%end115390%_))))
    (define __string-split
      (lambda (_%str115248%_ _%char115249%_)
        (let* ((_%str115252%_ _%str115248%_)
               (_%char115260%_ _%char115249%_)
               (_%len115269%_
                (let () (declare (not safe)) (##string-length _%str115252%_))))
          (let _%lp115271%_ ((_%start115273%_ '0) (_%r115274%_ '()))
            (let* ((_%start115277%_ _%start115273%_)
                   (_%$e115345%_
                    (let* ((_%str115290%_ _%str115252%_)
                           (_%criterion115293%_ _%char115260%_)
                           (_%start115296%_ _%start115277%_)
                           (_%end115299%_ '#f)
                           (_%str115304%_ _%str115290%_))
                      (if (nonnegative-fixnum? _%start115296%_)
                          (let ((_%start115319%_ _%start115296%_))
                            (if (let ((_%$e115331%_ '#t))
                                  (and _%$e115331%_ _%$e115331%_))
                                (let ((_%end115335%_ _%end115299%_))
                                  (__string-index__%
                                   _%str115304%_
                                   _%criterion115293%_
                                   _%start115319%_
                                   _%end115335%_))
                                (begin
                                  (raise-contract-violation-error
                                   '"contract violation"
                                   'context:
                                   'gerbil/runtime/util
                                   'contract:
                                   '(? (or not fixnum?))
                                   'value:
                                   _%end115299%_)
                                  '#!void)))
                          (begin
                            (raise-contract-violation-error
                             '"contract violation"
                             'context:
                             'gerbil/runtime/util
                             'contract:
                             'nonnegative-fixnum?
                             'value:
                             _%start115296%_)
                            '#!void)))))
              (if _%$e115345%_
                  (let ((_%end115350%_ _%$e115345%_))
                    (_%lp115271%_
                     (let () (declare (not safe)) (##fx+ _%end115350%_ '1))
                     (cons (let ()
                             (declare (not safe))
                             (##substring
                              _%str115252%_
                              _%start115277%_
                              _%end115350%_))
                           _%r115274%_)))
                  (if (let ()
                        (declare (not safe))
                        (##fx< _%start115277%_ _%len115269%_))
                      (foldl__0
                       cons
                       (list (let ()
                               (declare (not safe))
                               (##substring
                                _%str115252%_
                                _%start115277%_
                                _%len115269%_)))
                       _%r115274%_)
                      (reverse! _%r115274%_))))))))
    (define string-split
      (lambda (_%str115223%_ _%char115224%_)
        (if (string? _%str115223%_)
            (let ((_%str115228%_ _%str115223%_))
              (if (char? _%char115224%_)
                  (let ((_%char115238%_ _%char115224%_))
                    (__string-split _%str115228%_ _%char115238%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@804.37-804.41"
                     'contract:
                     'char?
                     'value:
                     _%char115224%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@804.21-804.24"
               'contract:
               'string?
               'value:
               _%str115223%_)
              '#!void))))
    (define string-join
      (lambda (_%strs115073%_ _%join115074%_)
        (letrec ((_%join-length115077%_
                  (lambda (_%strs115161%_ _%jlen115162%_)
                    (let _%lp115164%_ ((_%rest115166%_ _%strs115161%_)
                                       (_%len115167%_ '0))
                      (let* ((_%len115169%_ _%len115167%_)
                             (_%$%rest115177115185%_ _%rest115166%_)
                             (_%$%else115179115193%_ (lambda () '0))
                             (_%$%K115181115211%_
                              (lambda (_%rest115196%_ _%hd115197%_)
                                (if (string? _%hd115197%_)
                                    (let ((_%hd115199%_ _%hd115197%_))
                                      (if (pair? _%rest115196%_)
                                          (_%lp115164%_
                                           _%rest115196%_
                                           (fx+ (let ()
                                                  (declare (not safe))
                                                  (##string-length
                                                   _%hd115199%_))
                                                _%jlen115162%_
                                                _%len115169%_))
                                          (let ((__tmp123035
                                                 (let ()
                                                   (declare (not safe))
                                                   (##string-length
                                                    _%hd115199%_))))
                                            (declare (not safe))
                                            (##fx+ __tmp123035
                                                   _%len115169%_))))
                                    (begin
                                      (raise-contract-violation-error
                                       '"expected string"
                                       'value:
                                       _%hd115197%_)
                                      '#!void)))))
                        (if (pair? _%$%rest115177115185%_)
                            (let ((_%$%hd115182115214%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest115177115185%_)))
                                  (_%$%tl115183115216%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest115177115185%_))))
                              (let* ((_%hd115219%_ _%$%hd115182115214%_)
                                     (_%rest115221%_ _%$%tl115183115216%_))
                                (_%$%K115181115211%_
                                 _%rest115221%_
                                 _%hd115219%_)))
                            (_%$%else115179115193%_)))))))
          (let* ((_%join115082%_
                  (if (char? _%join115074%_)
                      (let () (declare (not safe)) (##string _%join115074%_))
                      (if (string? _%join115074%_)
                          _%join115074%_
                          (let ()
                            (raise-contract-violation-error
                             '"expected string or char"
                             'value:
                             _%join115074%_)
                            '#!void))))
                 (_%jlen115084%_
                  (let ()
                    (declare (not safe))
                    (##string-length _%join115082%_)))
                 (_%olen115086%_
                  (_%join-length115077%_ _%strs115073%_ _%jlen115084%_))
                 (_%ostr115088%_
                  (let ()
                    (declare (not safe))
                    (##make-string _%olen115086%_))))
            (let _%lp115091%_ ((_%rest115093%_ _%strs115073%_)
                               (_%k115094%_ '0))
              (let* ((_%k115097%_ _%k115094%_)
                     (_%$%rest115113115121%_ _%rest115093%_)
                     (_%$%else115115115129%_ (lambda () '""))
                     (_%$%K115117115149%_
                      (lambda (_%rest115132%_ _%hd115133%_)
                        (let* ((_%hd115135%_ _%hd115133%_)
                               (_%hdlen115147%_
                                (let ()
                                  (declare (not safe))
                                  (##string-length _%hd115135%_))))
                          (if (pair? _%rest115132%_)
                              (begin
                                (let ()
                                  (declare (not safe))
                                  (##substring-move!
                                   _%hd115135%_
                                   '0
                                   _%hdlen115147%_
                                   _%ostr115088%_
                                   _%k115097%_))
                                (let ((__tmp123036
                                       (let ()
                                         (declare (not safe))
                                         (##fx+ _%k115097%_ _%hdlen115147%_))))
                                  (declare (not safe))
                                  (##substring-move!
                                   _%join115082%_
                                   '0
                                   _%jlen115084%_
                                   _%ostr115088%_
                                   __tmp123036))
                                (_%lp115091%_
                                 _%rest115132%_
                                 (let ()
                                   (declare (not safe))
                                   (##fx+ _%k115097%_
                                          _%hdlen115147%_
                                          _%jlen115084%_))))
                              (begin
                                (let ()
                                  (declare (not safe))
                                  (##substring-move!
                                   _%hd115135%_
                                   '0
                                   _%hdlen115147%_
                                   _%ostr115088%_
                                   _%k115097%_))
                                _%ostr115088%_))))))
                (if (pair? _%$%rest115113115121%_)
                    (let ((_%$%hd115118115152%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest115113115121%_)))
                          (_%$%tl115119115154%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest115113115121%_))))
                      (let* ((_%hd115157%_ _%$%hd115118115152%_)
                             (_%rest115159%_ _%$%tl115119115154%_))
                        (_%$%K115117115149%_ _%rest115159%_ _%hd115157%_)))
                    (_%$%else115115115129%_))))))))
    (define __read-u8vector__%
      (lambda (_%bytes115013%_ _%port115014%_ _%start115015%_ _%end115016%_)
        (let* ((_%bytes115019%_ _%bytes115013%_)
               (_%port115027%_ _%port115014%_)
               (_%start115035%_ _%start115015%_)
               (_%end115043%_ _%end115016%_))
          (declare (not safe))
          (##read-subu8vector
           _%bytes115019%_
           _%start115035%_
           _%end115043%_
           _%port115027%_))))
    (define __read-u8vector__0
      (lambda (_%bytes115055%_ _%port115056%_)
        (let* ((_%start115058%_ '0)
               (_%end115060%_ (u8vector-length _%bytes115055%_)))
          (__read-u8vector__%
           _%bytes115055%_
           _%port115056%_
           _%start115058%_
           _%end115060%_))))
    (define __read-u8vector__1
      (lambda (_%bytes115062%_ _%port115063%_ _%start115064%_)
        (let ((_%end115066%_ (u8vector-length _%bytes115062%_)))
          (__read-u8vector__%
           _%bytes115062%_
           _%port115063%_
           _%start115064%_
           _%end115066%_))))
    (define __read-u8vector
      (lambda _g123037_
        (let ((_g123038_ (let () (declare (not safe)) (##length _g123037_))))
          (cond ((let () (declare (not safe)) (##fx= _g123038_ 2))
                 (apply __read-u8vector__0 _g123037_))
                ((let () (declare (not safe)) (##fx= _g123038_ 3))
                 (apply __read-u8vector__1 _g123037_))
                ((let () (declare (not safe)) (##fx= _g123038_ 4))
                 (apply __read-u8vector__% _g123037_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __read-u8vector
                  _g123037_))))))
    (define read-u8vector__%
      (lambda (_%bytes114938%_ _%port114939%_ _%start114940%_ _%end114941%_)
        (if (u8vector? _%bytes114938%_)
            (let ((_%bytes114945%_ _%bytes114938%_))
              (if (input-port? _%port114939%_)
                  (let ((_%port114955%_ _%port114939%_))
                    (if (and (fixnum? _%start114940%_)
                             (let ()
                               (declare (not safe))
                               (##fx>= _%start114940%_ '0))
                             (let ((__tmp123039
                                    (let ()
                                      (declare (not safe))
                                      (##u8vector-length _%bytes114945%_))))
                               (declare (not safe))
                               (##fx< _%start114940%_ __tmp123039)))
                        (let ((_%start114968%_ _%start114940%_))
                          (if (and (fixnum? _%end114941%_)
                                   (let ((__tmp123040
                                          (let ()
                                            (declare (not safe))
                                            (##u8vector-length
                                             _%bytes114945%_))))
                                     (declare (not safe))
                                     (##fx<= _%start114968%_
                                             _%end114941%_
                                             __tmp123040)))
                              (let ((_%end114981%_ _%end114941%_))
                                (__read-u8vector__%
                                 _%bytes114945%_
                                 _%port114955%_
                                 _%start114968%_
                                 _%end114981%_))
                              (begin
                                (raise-contract-violation-error
                                 '"contract violation"
                                 'context:
                                 '"\"gerbil/runtime/util.ss\"@873.22-873.25"
                                 'contract:
                                 '(in-range-inclusive?
                                   start
                                   (u8vector-length bytes))
                                 'value:
                                 _%end114941%_)
                                '#!void)))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/util.ss\"@871.22-871.27"
                           'contract:
                           '(in-range? 0 (u8vector-length bytes))
                           'value:
                           _%start114940%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@870.22-870.26"
                     'contract:
                     'input-port?
                     'value:
                     _%port114939%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@869.22-869.27"
               'contract:
               'u8vector?
               'value:
               _%bytes114938%_)
              '#!void))))
    (define read-u8vector__0
      (lambda (_%bytes114994%_ _%port114995%_)
        (let* ((_%start114997%_ '0)
               (_%end114999%_ (u8vector-length _%bytes114994%_)))
          (read-u8vector__%
           _%bytes114994%_
           _%port114995%_
           _%start114997%_
           _%end114999%_))))
    (define read-u8vector__1
      (lambda (_%bytes115001%_ _%port115002%_ _%start115003%_)
        (let ((_%end115005%_ (u8vector-length _%bytes115001%_)))
          (read-u8vector__%
           _%bytes115001%_
           _%port115002%_
           _%start115003%_
           _%end115005%_))))
    (define read-u8vector
      (lambda _g123041_
        (let ((_g123042_ (let () (declare (not safe)) (##length _g123041_))))
          (cond ((let () (declare (not safe)) (##fx= _g123042_ 2))
                 (apply read-u8vector__0 _g123041_))
                ((let () (declare (not safe)) (##fx= _g123042_ 3))
                 (apply read-u8vector__1 _g123041_))
                ((let () (declare (not safe)) (##fx= _g123042_ 4))
                 (apply read-u8vector__% _g123041_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  read-u8vector
                  _g123041_))))))
    (define __write-u8vector__%
      (lambda (_%bytes114877%_ _%port114878%_ _%start114879%_ _%end114880%_)
        (let* ((_%bytes114883%_ _%bytes114877%_)
               (_%port114891%_ _%port114878%_)
               (_%start114899%_ _%start114879%_)
               (_%end114907%_ _%end114880%_))
          (declare (not safe))
          (##write-subu8vector
           _%bytes114883%_
           _%start114899%_
           _%end114907%_
           _%port114891%_))))
    (define __write-u8vector__0
      (lambda (_%bytes114919%_ _%port114920%_)
        (let* ((_%start114922%_ '0)
               (_%end114924%_ (u8vector-length _%bytes114919%_)))
          (__write-u8vector__%
           _%bytes114919%_
           _%port114920%_
           _%start114922%_
           _%end114924%_))))
    (define __write-u8vector__1
      (lambda (_%bytes114926%_ _%port114927%_ _%start114928%_)
        (let ((_%end114930%_ (u8vector-length _%bytes114926%_)))
          (__write-u8vector__%
           _%bytes114926%_
           _%port114927%_
           _%start114928%_
           _%end114930%_))))
    (define __write-u8vector
      (lambda _g123043_
        (let ((_g123044_ (let () (declare (not safe)) (##length _g123043_))))
          (cond ((let () (declare (not safe)) (##fx= _g123044_ 2))
                 (apply __write-u8vector__0 _g123043_))
                ((let () (declare (not safe)) (##fx= _g123044_ 3))
                 (apply __write-u8vector__1 _g123043_))
                ((let () (declare (not safe)) (##fx= _g123044_ 4))
                 (apply __write-u8vector__% _g123043_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __write-u8vector
                  _g123043_))))))
    (define write-u8vector__%
      (lambda (_%bytes114807%_ _%port114808%_ _%start114809%_ _%end114810%_)
        (if (u8vector? _%bytes114807%_)
            (let ((_%bytes114814%_ _%bytes114807%_))
              (if (output-port? _%port114808%_)
                  (let* ((_%port114824%_ _%port114808%_)
                         (_%start114833%_ _%start114809%_))
                    (if (and (fixnum? _%end114810%_)
                             (let ((__tmp123045
                                    (let ()
                                      (declare (not safe))
                                      (##u8vector-length _%bytes114814%_))))
                               (declare (not safe))
                               (##fx<= _%start114833%_
                                       _%end114810%_
                                       __tmp123045)))
                        (let ((_%end114845%_ _%end114810%_))
                          (__write-u8vector__%
                           _%bytes114814%_
                           _%port114824%_
                           _%start114833%_
                           _%end114845%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/util.ss\"@882.23-882.26"
                           'contract:
                           '(in-range-inclusive? start (u8vector-length bytes))
                           'value:
                           _%end114810%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/util.ss\"@880.23-880.27"
                     'contract:
                     'output-port?
                     'value:
                     _%port114808%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/util.ss\"@879.23-879.28"
               'contract:
               'u8vector?
               'value:
               _%bytes114807%_)
              '#!void))))
    (define write-u8vector__0
      (lambda (_%bytes114858%_ _%port114859%_)
        (let* ((_%start114861%_ '0)
               (_%end114863%_ (u8vector-length _%bytes114858%_)))
          (write-u8vector__%
           _%bytes114858%_
           _%port114859%_
           _%start114861%_
           _%end114863%_))))
    (define write-u8vector__1
      (lambda (_%bytes114865%_ _%port114866%_ _%start114867%_)
        (let ((_%end114869%_ (u8vector-length _%bytes114865%_)))
          (write-u8vector__%
           _%bytes114865%_
           _%port114866%_
           _%start114867%_
           _%end114869%_))))
    (define write-u8vector
      (lambda _g123046_
        (let ((_g123047_ (let () (declare (not safe)) (##length _g123046_))))
          (cond ((let () (declare (not safe)) (##fx= _g123047_ 2))
                 (apply write-u8vector__0 _g123046_))
                ((let () (declare (not safe)) (##fx= _g123047_ 3))
                 (apply write-u8vector__1 _g123046_))
                ((let () (declare (not safe)) (##fx= _g123047_ 4))
                 (apply write-u8vector__% _g123046_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  write-u8vector
                  _g123046_))))))
    (define DBG-printer (make-parameter write))
    (define DBG-helper
      (lambda (_%tag114775%_
               _%dbg-exprs114776%_
               _%dbg-thunks114777%_
               _%expr114778%_
               _%thunk114779%_)
        (letrec ((_%o114781%_ (current-output-port))
                 (_%e114782%_ (current-error-port))
                 (_%p114783%_ (let () (declare (not safe)) (DBG-printer)))
                 (_%f114784%_
                  (lambda ()
                    (force-output _%o114781%_)
                    (force-output _%e114782%_)))
                 (_%d114785%_
                  (lambda (_%x114792%_) (display _%x114792%_ _%e114782%_)))
                 (_%w114786%_
                  (lambda (_%x114794%_) (_%p114783%_ _%x114794%_ _%e114782%_)))
                 (_%n114787%_ (lambda () (newline _%e114782%_)))
                 (_%v114788%_
                  (lambda (_%l114797%_)
                    (for-each
                     (lambda (_%x114799%_)
                       (_%d114785%_ '" ")
                       (_%w114786%_ _%x114799%_))
                     _%l114797%_)
                    (_%n114787%_)))
                 (_%x114789%_
                  (lambda (_%expr114801%_ _%thunk114802%_)
                    (call-with-values
                     _%thunk114802%_
                     (lambda _%x114804%_
                       (_%f114784%_)
                       (_%d114785%_ '"  ")
                       (_%w114786%_ _%expr114801%_)
                       (_%d114785%_ '" =>")
                       (_%v114788%_ _%x114804%_)
                       (_%f114784%_)
                       (let ()
                         (declare (not safe))
                         (##apply values _%x114804%_)))))))
          (if _%tag114775%_
              (begin
                (if (eq? _%tag114775%_ '#!void)
                    '#!void
                    (begin
                      (_%f114784%_)
                      (_%d114785%_ _%tag114775%_)
                      (_%n114787%_)))
                (for-each _%x114789%_ _%dbg-exprs114776%_ _%dbg-thunks114777%_)
                (if _%thunk114779%_
                    (_%x114789%_ _%expr114778%_ _%thunk114779%_)
                    '#!void))
              (if _%thunk114779%_ (_%thunk114779%_) '#!void)))))))
