(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/loader::timestamp 1795039816)
  (begin
    (define __modules
      (let ()
        (declare (not safe))
        (make-hash-table__%
         '#f
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value)))
    (define __load-mx (make-mutex 'loader))
    (define __load-cv (make-condition-variable 'loader))
    (define __load-path '())
    (define __load-order
      (let ()
        (declare (not safe))
        (make-hash-table__%
         '#f
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value
         absent-value)))
    (define __load-order-next '1)
    (define load-path (lambda () __load-path))
    (define add-load-path!
      (lambda _%paths182124%_
        (if (let () (declare (not safe)) (andmap__0 string? _%paths182124%_))
            '#!void
            (let ()
              (declare (not safe))
              (error '"bad load path; expected list of paths"
                     _%paths182124%_)))
        (let ((__tmp182234
               (lambda (_%p182126%_)
                 (set! __load-path (cons _%p182126%_ __load-path))))
              (__tmp182233 (reverse! _%paths182124%_)))
          (declare (not safe))
          (##for-each __tmp182234 __tmp182233))))
    (define __set-load-path!
      (lambda (_%paths182112%_)
        (let ((_%paths182115%_ _%paths182112%_))
          (if (let () (declare (not safe)) (andmap__0 string? _%paths182115%_))
              '#!void
              (let ()
                (declare (not safe))
                (error '"bad load path; expected list of paths"
                       _%paths182115%_)))
          (set! __load-path _%paths182115%_))))
    (define set-load-path!
      (lambda (_%paths182098%_)
        (if (list? _%paths182098%_)
            (let ((_%paths182102%_ _%paths182098%_))
              (__set-load-path! _%paths182102%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/loader.ss\"@27.23-27.28"
               'contract:
               'list?
               'value:
               _%paths182098%_)
              '#!void))))
    (define __load-module
      (lambda (_%modpath181886%_)
        (let ((_%modpath181889%_ _%modpath181886%_))
          (mutex-lock! __load-mx)
          (let ((_%$e181921%_
                 (let* ((_%h181898%_ __modules)
                        (_%key181901%_ _%modpath181889%_)
                        (_%h181905%_ _%h181898%_)
                        (_%h181907%_ _%h181905%_))
                   (declare (not safe))
                   (__hash-get _%h181907%_ _%key181901%_))))
            (if _%$e181921%_
                (if (or (eq? 'builtin _%$e181921%_) (string? _%$e181921%_))
                    (let () (mutex-unlock! __load-mx) _%$e181921%_)
                    (if (eq? 'loading _%$e181921%_)
                        (let ()
                          (mutex-unlock! __load-mx __load-cv)
                          (let* ((_%modpath181931%_ _%modpath181889%_)
                                 (_%modpath181936%_ _%modpath181931%_))
                            (__load-module _%modpath181936%_)))
                        (if (and (pair? _%$e181921%_)
                                 (eq? (let ()
                                        (declare (not safe))
                                        (##car _%$e181921%_))
                                      'error))
                            (let ()
                              (mutex-unlock! __load-mx)
                              (let ((__tmp182235 (cadr _%$e181921%_)))
                                (declare (not safe))
                                (raise __tmp182235)))
                            (let ()
                              (mutex-unlock! __load-mx)
                              (let ()
                                (declare (not safe))
                                (error '"inernal error; unexpected loading state"
                                       _%$e181921%_))))))
                (let ((_%$e181951%_ (__find-library-module _%modpath181889%_)))
                  (if _%$e181951%_
                      (let ()
                        (let* ((_%h181956%_ __modules)
                               (_%key181959%_ _%modpath181889%_)
                               (_%value181962%_ 'loading)
                               (_%h181966%_ _%h181956%_)
                               (_%h181968%_ _%h181966%_))
                          (declare (not safe))
                          (__hash-put!
                           _%h181968%_
                           _%key181959%_
                           _%value181962%_))
                        (mutex-unlock! __load-mx)
                        (let ((__tmp182237
                               (lambda (_%exn181982%_)
                                 (mutex-lock! __load-mx)
                                 (let* ((_%h181984%_ __modules)
                                        (_%key181987%_ _%modpath181889%_)
                                        (_%value181990%_
                                         (list 'error _%exn181982%_))
                                        (_%h181994%_ _%h181984%_)
                                        (_%h181996%_ _%h181994%_))
                                   (declare (not safe))
                                   (__hash-put!
                                    _%h181996%_
                                    _%key181987%_
                                    _%value181990%_))
                                 (condition-variable-broadcast! __load-cv)
                                 (mutex-unlock! __load-mx)
                                 (let ()
                                   (declare (not safe))
                                   (raise _%exn181982%_))))
                              (__tmp182236
                               (lambda ()
                                 (let ((_%loaded-path182010%_
                                        (load _%$e181951%_)))
                                   (mutex-lock! __load-mx)
                                   (let* ((_%h182012%_ __modules)
                                          (_%key182015%_ _%modpath181889%_)
                                          (_%value182018%_
                                           _%loaded-path182010%_)
                                          (_%h182022%_ _%h182012%_)
                                          (_%h182024%_ _%h182022%_))
                                     (declare (not safe))
                                     (__hash-put!
                                      _%h182024%_
                                      _%key182015%_
                                      _%value182018%_))
                                   (if (let* ((_%h182038%_ __load-order)
                                              (_%key182041%_ _%modpath181889%_)
                                              (_%h182045%_ _%h182038%_)
                                              (_%h182047%_ _%h182045%_))
                                         (declare (not safe))
                                         (__hash-get
                                          _%h182047%_
                                          _%key182041%_))
                                       '#!void
                                       (begin
                                         (let* ((_%h182058%_ __load-order)
                                                (_%key182061%_
                                                 _%modpath181889%_)
                                                (_%value182064%_
                                                 __load-order-next)
                                                (_%h182068%_ _%h182058%_)
                                                (_%h182070%_ _%h182068%_))
                                           (declare (not safe))
                                           (__hash-put!
                                            _%h182070%_
                                            _%key182061%_
                                            _%value182064%_))
                                         (set! __load-order-next
                                               (let* ((_%x182082%_
                                                       __load-order-next)
                                                      (_%x182087%_
                                                       _%x182082%_))
                                                 (declare (not safe))
                                                 (__1+ _%x182087%_)))))
                                   (condition-variable-broadcast! __load-cv)
                                   (mutex-unlock! __load-mx)
                                   _%loaded-path182010%_))))
                          (declare (not safe))
                          (__with-catch __tmp182237 __tmp182236)))
                      (let ()
                        (mutex-unlock! __load-mx)
                        (let ()
                          (declare (not safe))
                          (error '"module not found"
                                 _%modpath181889%_))))))))))
    (define load-module
      (lambda (_%modpath181872%_)
        (if (string? _%modpath181872%_)
            (let ((_%modpath181876%_ _%modpath181872%_))
              (__load-module _%modpath181876%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/loader.ss\"@32.20-32.27"
               'contract:
               'string?
               'value:
               _%modpath181872%_)
              '#!void))))
    (define __reload-module!
      (lambda (_%modpath181730%_)
        (let ((_%modpath181733%_ _%modpath181730%_))
          (mutex-lock! __load-mx)
          (let ((_%$e181765%_
                 (let* ((_%h181742%_ __modules)
                        (_%key181745%_ _%modpath181733%_)
                        (_%h181749%_ _%h181742%_)
                        (_%h181751%_ _%h181749%_))
                   (declare (not safe))
                   (__hash-get _%h181751%_ _%key181745%_))))
            (if _%$e181765%_
                (if (eq? _%$e181765%_ 'builtin)
                    (let ()
                      (mutex-unlock! __load-mx)
                      (let ()
                        (declare (not safe))
                        (error '"cannot reload builtin module"
                               _%modpath181733%_)))
                    (if (eq? 'loading _%$e181765%_)
                        (let ()
                          (mutex-unlock! __load-mx __load-cv)
                          (let ()
                            (declare (not safe))
                            (error '"module is still loading")))
                        (if (string? _%$e181765%_)
                            (let ((_%latest-path181773%_
                                   (__find-library-module _%modpath181733%_)))
                              (if (or (equal? (path-extension _%$e181765%_)
                                              '".scm")
                                      (not (equal? _%$e181765%_
                                                   _%latest-path181773%_)))
                                  (begin
                                    (let* ((_%h181778%_ __modules)
                                           (_%key181781%_ _%modpath181733%_)
                                           (_%h181785%_ _%h181778%_)
                                           (_%h181787%_ _%h181785%_))
                                      (declare (not safe))
                                      (__hash-remove!
                                       _%h181787%_
                                       _%key181781%_))
                                    (mutex-unlock! __load-mx)
                                    (let* ((_%modpath181802%_
                                            _%modpath181733%_)
                                           (_%modpath181807%_
                                            _%modpath181802%_))
                                      (__load-module _%modpath181807%_)))
                                  (mutex-unlock! __load-mx)))
                            (if (and (pair? _%$e181765%_)
                                     (eq? (let ()
                                            (declare (not safe))
                                            (##car _%$e181765%_))
                                          'error))
                                (let ()
                                  (let* ((_%h181818%_ __modules)
                                         (_%key181821%_ _%modpath181733%_)
                                         (_%h181825%_ _%h181818%_)
                                         (_%h181827%_ _%h181825%_))
                                    (declare (not safe))
                                    (__hash-remove! _%h181827%_ _%key181821%_))
                                  (mutex-unlock! __load-mx)
                                  (let* ((_%modpath181839%_ _%modpath181733%_)
                                         (_%modpath181844%_ _%modpath181839%_))
                                    (__load-module _%modpath181844%_)))
                                (let ()
                                  (mutex-unlock! __load-mx)
                                  (let ()
                                    (declare (not safe))
                                    (error '"inernal error; unexpected loading state"
                                           _%$e181765%_)))))))
                (let ()
                  (mutex-unlock! __load-mx)
                  (let* ((_%modpath181856%_ _%modpath181733%_)
                         (_%modpath181861%_ _%modpath181856%_))
                    (__load-module _%modpath181861%_))))))))
    (define reload-module!
      (lambda (_%modpath181716%_)
        (if (string? _%modpath181716%_)
            (let ((_%modpath181720%_ _%modpath181716%_))
              (__reload-module! _%modpath181720%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/loader.ss\"@75.23-75.30"
               'contract:
               'string?
               'value:
               _%modpath181716%_)
              '#!void))))
    (define __find-library-module
      (lambda (_%modpath181650%_)
        (letrec ((_%find-compiled-file181652%_
                  (lambda (_%npath181705%_)
                    (let ((_%basepath181707%_
                           (let ()
                             (declare (not safe))
                             (##string-append _%npath181705%_ '".o"))))
                      (let _%lp181709%_ ((_%current181711%_ '#f)
                                         (_%n181712%_ '1))
                        (let ((_%next181714%_
                               (let ((__tmp182238
                                      (number->string _%n181712%_)))
                                 (declare (not safe))
                                 (##string-append
                                  _%basepath181707%_
                                  __tmp182238))))
                          (if (let ()
                                (declare (not safe))
                                (##file-exists? _%next181714%_))
                              (_%lp181709%_
                               _%next181714%_
                               (let ()
                                 (declare (not safe))
                                 (##fx+ _%n181712%_ '1)))
                              _%current181711%_))))))
                 (_%find-source-file181653%_
                  (lambda (_%npath181701%_)
                    (let ((_%spath181703%_
                           (let ()
                             (declare (not safe))
                             (##string-append _%npath181701%_ '".scm"))))
                      (if (let ()
                            (declare (not safe))
                            (##file-exists? _%spath181703%_))
                          _%spath181703%_
                          '#f)))))
          (let _%lp181655%_ ((_%rest181657%_ (load-path)))
            (let* ((_%$%rest181658181666%_ _%rest181657%_)
                   (_%$%else181660181674%_ (lambda () '#f))
                   (_%$%K181662181689%_
                    (lambda (_%rest181677%_ _%dir181678%_)
                      (let* ((_%npath181680%_
                              (path-expand
                               _%modpath181650%_
                               (path-expand _%dir181678%_)))
                             (_%$e181682%_
                              (_%find-compiled-file181652%_ _%npath181680%_)))
                        (if _%$e181682%_
                            (path-normalize _%$e181682%_)
                            (let ((_%$e181685%_
                                   (_%find-source-file181653%_
                                    _%npath181680%_)))
                              (if _%$e181685%_
                                  (path-normalize _%$e181685%_)
                                  (_%lp181655%_ _%rest181677%_))))))))
              (if (pair? _%$%rest181658181666%_)
                  (let ((_%$%hd181663181692%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest181658181666%_)))
                        (_%$%tl181664181694%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest181658181666%_))))
                    (let* ((_%dir181697%_ _%$%hd181663181692%_)
                           (_%rest181699%_ _%$%tl181664181694%_))
                      (_%$%K181662181689%_ _%rest181699%_ _%dir181697%_)))
                  (_%$%else181660181674%_)))))))
    (define list-modules
      (lambda ()
        (let ()
          (mutex-lock! __load-mx)
          (let ((_%result181648%_
                 (let* ((_%h181630%_ __modules)
                        (_%h181634%_ _%h181630%_)
                        (_%h181636%_ _%h181634%_))
                   (declare (not safe))
                   (__hash->list _%h181636%_))))
            (mutex-unlock! __load-mx)
            _%result181648%_))))
    (define __module-load-order
      (lambda (_%modpath181566%_)
        (let ((_%modpath181569%_ _%modpath181566%_))
          (mutex-lock! __load-mx)
          (let ((_%ord181626%_
                 (if (eq? (let* ((_%h181578%_ __modules)
                                 (_%key181581%_ _%modpath181569%_)
                                 (_%h181585%_ _%h181578%_)
                                 (_%h181587%_ _%h181585%_))
                            (declare (not safe))
                            (__hash-get _%h181587%_ _%key181581%_))
                          'builtin)
                     '0
                     (let ((_%$e181622%_
                            (let* ((_%h181602%_ __load-order)
                                   (_%key181605%_ _%modpath181569%_)
                                   (_%h181609%_ _%h181602%_)
                                   (_%h181611%_ _%h181609%_))
                              (declare (not safe))
                              (__hash-get _%h181611%_ _%key181605%_))))
                       (if _%$e181622%_ _%$e181622%_ '#f)))))
            (mutex-unlock! __load-mx)
            (if (exact-integer? _%ord181626%_)
                _%ord181626%_
                (begin
                  (let ()
                    (declare (not safe))
                    (error '"unknown module load order"
                           'module:
                           _%modpath181569%_))
                  '#!void))))))
    (define module-load-order
      (lambda (_%modpath181552%_)
        (if (string? _%modpath181552%_)
            (let ((_%modpath181556%_ _%modpath181552%_))
              (__module-load-order _%modpath181556%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/loader.ss\"@137.26-137.33"
               'contract:
               'string?
               'value:
               _%modpath181552%_)
              '#!void))))))
