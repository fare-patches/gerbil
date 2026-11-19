(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/optimize::timestamp 1795039825)
  (begin
    (define gxc#optimizer-info-init!
      (lambda ()
        (if (let () (declare (not safe)) (gxc#current-compile-optimizer-info))
            '#!void
            (let ((__tmp274274
                   (let ((__obj274268
                          (let ()
                            (declare (not safe))
                            (##structure
                             gxc#optimizer-info::t
                             '#f
                             '#f
                             '#f
                             '#f))))
                     (let ()
                       (declare (not safe))
                       (gxc#optimizer-info:::init! __obj274268))
                     __obj274268)))
              (declare (not safe))
              (gxc#current-compile-optimizer-info __tmp274274)))))
    (define gxc#optimize!
      (lambda (_%ctx273876%_)
        (let ((__tmp274276
               (lambda ()
                 (let ((__tmp274278
                        (lambda ()
                          (gxc#optimizer-load-builtin-ssxi _%ctx273876%_)
                          (gxc#optimizer-load-ssxi-deps _%ctx273876%_)
                          (let ((__tmp274280
                                 (##structure-ref
                                  (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-optimizer-info))
                                  '3
                                  gxc#optimizer-info::t
                                  '#f))
                                (__tmp274279
                                 (##structure-ref
                                  _%ctx273876%_
                                  '1
                                  gx#expander-context::t
                                  '#f)))
                            (declare (not safe))
                            (hash-put! __tmp274280 __tmp274279 '#t))
                          (let ((_%code273880%_
                                 (gxc#optimize-source
                                  (##structure-ref
                                   _%ctx273876%_
                                   '11
                                   gx#module-context::t
                                   '#f))))
                            (##structure-set!
                             _%ctx273876%_
                             _%code273880%_
                             '11
                             gx#module-context::t
                             '#f))))
                       (__tmp274277
                        (let () (declare (not safe)) (make-hash-table-eq))))
                   (declare (not safe))
                   (call-with-parameters__1
                    __tmp274278
                    gxc#current-compile-local-type
                    __tmp274277))))
              (__tmp274275 (let () (declare (not safe)) (make-hash-table-eq))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp274276
           gxc#current-compile-mutators
           __tmp274275))))
    (define gxc#optimizer-load-builtin-ssxi
      (lambda (_%ctx273862%_)
        (letrec ((_%load-it!273864%_
                  (lambda (_%id273874%_)
                    (if (let ((__tmp274281
                               (##structure-ref
                                (let ()
                                  (declare (not safe))
                                  (gxc#current-compile-optimizer-info))
                                '3
                                gxc#optimizer-info::t
                                '#f)))
                          (declare (not safe))
                          (hash-get __tmp274281 _%id273874%_))
                        '#!void
                        (begin
                          (gxc#optimizer-import-ssxi-by-id _%id273874%_)
                          (let ((__tmp274282
                                 (##structure-ref
                                  (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-optimizer-info))
                                  '3
                                  gxc#optimizer-info::t
                                  '#f)))
                            (declare (not safe))
                            (hash-put! __tmp274282 _%id273874%_ '#t)))))))
          (let* ((_%modid273866%_
                  (##structure-ref
                   _%ctx273862%_
                   '1
                   gx#expander-context::t
                   '#f))
                 (_%modid-str273868%_ (symbol->string _%modid273866%_)))
            (if (or (let ()
                      (declare (not safe))
                      (##string-prefix? '"gerbil/runtime" _%modid-str273868%_))
                    (let ()
                      (declare (not safe))
                      (##string-prefix? '"gerbil/core" _%modid-str273868%_)))
                (let ()
                  (declare (not safe))
                  (##for-each
                   _%load-it!273864%_
                   '(gerbil/builtin gerbil/builtin-inline-rules)))
                (let ()
                  (declare (not safe))
                  (##for-each
                   _%load-it!273864%_
                   '(gerbil/builtin
                     gerbil/builtin-inline-rules
                     gerbil/runtime/gambit
                     gerbil/runtime/util
                     gerbil/runtime/table
                     gerbil/runtime/control
                     gerbil/runtime/system
                     gerbil/runtime/c3
                     gerbil/runtime/mop
                     gerbil/runtime/mop-system-classes
                     gerbil/runtime/error
                     gerbil/runtime/interface
                     gerbil/runtime/hash
                     gerbil/runtime/thread
                     gerbil/runtime/syntax
                     gerbil/runtime/eval
                     gerbil/runtime/repl
                     gerbil/runtime/loader
                     gerbil/runtime/init
                     gerbil/runtime))))))))
    (define gxc#optimizer-load-ssxi-deps
      (lambda (_%ctx273799%_)
        (letrec* ((_%deps273801%_
                   (let* ((_%imports273852%_
                           (##structure-ref
                            _%ctx273799%_
                            '8
                            gx#module-context::t
                            '#f))
                          (_%$e273854%_
                           (let ()
                             (declare (not safe))
                             (gx#core-context-prelude__% _%ctx273799%_))))
                     (if _%$e273854%_
                         (cons _%$e273854%_ _%imports273852%_)
                         _%imports273852%_))))
          (let _%lp273803%_ ((_%rest273805%_ _%deps273801%_))
            (let* ((_%$%rest273806273814%_ _%rest273805%_)
                   (_%$%else273808273822%_ (lambda () '#!void))
                   (_%$%K273810273840%_
                    (lambda (_%rest273825%_ _%hd273826%_)
                      (if (let ()
                            (declare (not safe))
                            (##structure-instance-of?
                             _%hd273826%_
                             'gx#module-context::t))
                          (let ()
                            (if (let ((__tmp274284
                                       (##structure-ref
                                        (let ()
                                          (declare (not safe))
                                          (gxc#current-compile-optimizer-info))
                                        '3
                                        gxc#optimizer-info::t
                                        '#f))
                                      (__tmp274283
                                       (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%hd273826%_
                                          '1
                                          '#f
                                          '#f))))
                                  (declare (not safe))
                                  (hash-get __tmp274284 __tmp274283))
                                '#!void
                                (begin
                                  (let ((_%$e273829%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#core-context-prelude__%
                                            _%hd273826%_))))
                                    (if _%$e273829%_
                                        (_%lp273803%_
                                         (cons _%$e273829%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%hd273826%_
                                                  '8
                                                  '#f
                                                  '#f))))
                                        (_%lp273803%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%hd273826%_
                                            '8
                                            '#f
                                            '#f)))))
                                  (gxc#optimizer-load-ssxi _%hd273826%_)))
                            (_%lp273803%_ _%rest273825%_))
                          (if (let ()
                                (declare (not safe))
                                (##structure-instance-of?
                                 _%hd273826%_
                                 'gx#prelude-context::t))
                              (let ()
                                (if (let ((__tmp274286
                                           (##structure-ref
                                            (let ()
                                              (declare (not safe))
                                              (gxc#current-compile-optimizer-info))
                                            '3
                                            gxc#optimizer-info::t
                                            '#f))
                                          (__tmp274285
                                           (let ()
                                             (declare (not safe))
                                             (##unchecked-structure-ref
                                              _%hd273826%_
                                              '1
                                              '#f
                                              '#f))))
                                      (declare (not safe))
                                      (hash-get __tmp274286 __tmp274285))
                                    '#!void
                                    (begin
                                      (_%lp273803%_
                                       (let ()
                                         (declare (not safe))
                                         (##unchecked-structure-ref
                                          _%hd273826%_
                                          '7
                                          '#f
                                          '#f)))
                                      (gxc#optimizer-load-ssxi _%hd273826%_)))
                                (_%lp273803%_ _%rest273825%_))
                              (if (let ()
                                    (declare (not safe))
                                    (##structure-direct-instance-of?
                                     _%hd273826%_
                                     'gx#module-import::t))
                                  (_%lp273803%_
                                   (cons (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%hd273826%_
                                            '1
                                            '#f
                                            '#f))
                                         _%rest273825%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (##structure-direct-instance-of?
                                         _%hd273826%_
                                         'gx#module-export::t))
                                      (_%lp273803%_
                                       (cons (let ()
                                               (declare (not safe))
                                               (##unchecked-structure-ref
                                                _%hd273826%_
                                                '1
                                                '#f
                                                '#f))
                                             _%rest273825%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (##structure-direct-instance-of?
                                             _%hd273826%_
                                             'gx#import-set::t))
                                          (_%lp273803%_
                                           (cons (let ()
                                                   (declare (not safe))
                                                   (##unchecked-structure-ref
                                                    _%hd273826%_
                                                    '1
                                                    '#f
                                                    '#f))
                                                 _%rest273825%_))
                                          (let ()
                                            (declare (not safe))
                                            (error '"Unexpected module import"
                                                   _%hd273826%_))))))))))
              (if (pair? _%$%rest273806273814%_)
                  (let ((_%$%hd273811273843%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest273806273814%_)))
                        (_%$%tl273812273845%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest273806273814%_))))
                    (let* ((_%hd273848%_ _%$%hd273811273843%_)
                           (_%rest273850%_ _%$%tl273812273845%_))
                      (_%$%K273810273840%_ _%rest273850%_ _%hd273848%_)))
                  '#!void))))))
    (define gxc#optimizer-load-ssxi
      (lambda (_%ctx273779%_)
        (if (and (let ()
                   (declare (not safe))
                   (##structure-instance-of?
                    _%ctx273779%_
                    'gx#module-context::t))
                 (list? (let ()
                          (declare (not safe))
                          (##unchecked-structure-ref
                           _%ctx273779%_
                           '7
                           '#f
                           '#f))))
            '#!void
            (let* ((_%ht273781%_
                    (##structure-ref
                     (let ()
                       (declare (not safe))
                       (gxc#current-compile-optimizer-info))
                     '3
                     gxc#optimizer-info::t
                     '#f))
                   (_%id273783%_
                    (##structure-ref
                     _%ctx273779%_
                     '1
                     gx#expander-context::t
                     '#f))
                   (_%mod273785%_
                    (let ()
                      (declare (not safe))
                      (hash-get _%ht273781%_ _%id273783%_)))
                   (_%$e273788%_ _%mod273785%_))
              (if _%$e273788%_
                  _%$e273788%_
                  (let* ((_%mod273791%_
                          (gxc#optimizer-import-ssxi _%ctx273779%_))
                         (_%val273796%_
                          (let ((_%$e273793%_ _%mod273791%_))
                            (if _%$e273793%_ _%$e273793%_ '#!void))))
                    (let ()
                      (declare (not safe))
                      (hash-put! _%ht273781%_ _%id273783%_ _%val273796%_))
                    _%val273796%_))))))
    (define gxc#optimizer-import-ssxi
      (lambda (_%ctx273777%_)
        (if (##structure-ref _%ctx273777%_ '1 gx#expander-context::t '#f)
            (gxc#optimizer-import-ssxi-by-id
             (##structure-ref _%ctx273777%_ '1 gx#expander-context::t '#f))
            '#f)))
    (define gxc#optimizer-import-ssxi-by-id
      (lambda (_%id273755%_)
        (letrec ((_%catch-e273757%_
                  (lambda (_%exn273775%_)
                    (if (equal? (let ()
                                  (declare (not safe))
                                  (error-message _%exn273775%_))
                                '"cannot find library module")
                        '#!void
                        (begin
                          (let ()
                            (declare (not safe))
                            (display-exception__0 _%exn273775%_))
                          (let ()
                            (declare (not safe))
                            (displayln
                             '"*** WARNING Failed to load ssxi module for "
                             _%id273755%_))))
                    '#f))
                 (_%import-e273758%_
                  (lambda ()
                    (let* ((_%str-id273761%_
                            (let ((__tmp274287
                                   (let ()
                                     (declare (not safe))
                                     (gxc#module-id->path-string
                                      _%id273755%_))))
                              (declare (not safe))
                              (##string-append __tmp274287 '".ssxi")))
                           (_%artefact-path273768%_
                            (let ((_%$%odir273762273764%_
                                   (let ()
                                     (declare (not safe))
                                     (gxc#current-compile-output-dir))))
                              (if _%$%odir273762273764%_
                                  (let ((_%odir273766%_
                                         _%$%odir273762273764%_))
                                    (path-expand
                                     (let ()
                                       (declare (not safe))
                                       (##string-append
                                        _%str-id273761%_
                                        '".ss"))
                                     _%odir273766%_))
                                  '#f)))
                           (_%library-path273770%_
                            (let ((__tmp274288
                                   (let ()
                                     (declare (not safe))
                                     (##string-append
                                      '":"
                                      _%str-id273761%_
                                      '".ss"))))
                              (declare (not safe))
                              (##string->symbol __tmp274288)))
                           (_%ssxi-path273772%_
                            (if (and _%artefact-path273768%_
                                     (let ()
                                       (declare (not safe))
                                       (##file-exists?
                                        _%artefact-path273768%_)))
                                _%artefact-path273768%_
                                _%library-path273770%_)))
                      (let ()
                        (declare (not safe))
                        (gxc#verbose
                         '"Loading ssxi module "
                         _%ssxi-path273772%_))
                      (let ()
                        (declare (not safe))
                        (gx#import-module__% _%ssxi-path273772%_ '#t '#t))))))
          (let ()
            (declare (not safe))
            (__with-catch _%catch-e273757%_ _%import-e273758%_)))))
    (define gxc#optimize-source
      (lambda (_%stx273740%_)
        (let ()
          (declare (not safe))
          (gxc#apply-collect-mutators _%stx273740%_))
        (let ()
          (declare (not safe))
          (gxc#apply-collect-top-level-type-info _%stx273740%_))
        (let* ((_%stx273742%_
                (let ()
                  (declare (not safe))
                  (gxc#apply-generate-method-specializers _%stx273740%_)))
               (_%stx273744%_
                (let ()
                  (declare (not safe))
                  (gxc#apply-lift-top-lambdas _%stx273742%_))))
          (let ()
            (declare (not safe))
            (gxc#apply-collect-type-info _%stx273744%_))
          (let ()
            (declare (not safe))
            (gxc#apply-collect-mutable-type-info _%stx273744%_))
          (let _%fixpoint273747%_ ((_%current273749%_
                                    (let ()
                                      (declare (not safe))
                                      (gxc#optimizer-current-types))))
            (let ()
              (declare (not safe))
              (gxc#apply-refine-type-info _%stx273744%_))
            (let ((_%refined273751%_
                   (let ()
                     (declare (not safe))
                     (gxc#optimizer-current-types))))
              (if (equal? _%current273749%_ _%refined273751%_)
                  '#!void
                  (_%fixpoint273747%_ _%refined273751%_))))
          (let ()
            (declare (not safe))
            (gxc#apply-check-return-type _%stx273744%_))
          (let ()
            (declare (not safe))
            (gxc#apply-collect-top-level-declarations _%stx273744%_))
          (let ((_%stx273753%_
                 (let ()
                   (declare (not safe))
                   (gxc#apply-optimize-annotated _%stx273744%_))))
            (declare (not safe))
            (gxc#apply-optimize-call _%stx273753%_)))))
    (define gxc#::generate-ssxi::t
      (let ((__tmp274290 (list gxc#::generate-runtime-empty::t))
            (__tmp274289 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-ssxi::t
         '::generate-ssxi
         __tmp274290
         '()
         __tmp274289
         '#f)))
    (define gxc#::generate-ssxi?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-ssxi::t)))
    (define gxc#make-::generate-ssxi
      (lambda _%$args273737%_
        (apply make-instance gxc#::generate-ssxi::t _%$args273737%_)))
    (define gxc#::generate-ssxi-bind-methods!
      (let ((__tmp274291
             (lambda ()
               (force gxc#::generate-runtime-empty-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-ssxi::t
                  '%#begin
                  gxc#generate-runtime-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-ssxi::t
                  '%#begin-syntax
                  gxc#generate-ssxi-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-ssxi::t
                  '%#begin-annotation
                  gxc#generate-ssxi-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-ssxi::t
                  '%#module
                  gxc#generate-ssxi-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-ssxi::t
                  '%#define-values
                  gxc#generate-ssxi-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-ssxi::t
                  '%#call
                  gxc#generate-ssxi-call%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::generate-ssxi::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp274291)))
    (define gxc#apply-generate-ssxi
      (lambda (_%stx273729%_)
        (force gxc#::generate-ssxi-bind-methods!)
        (let* ((_%self273732%_
                (let ((__obj274270
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::generate-ssxi::t))))
                  __obj274270))
               (__tmp274292
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self273732%_ _%stx273729%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp274292
           gxc#current-compile-method
           _%self273732%_))))
    (define gxc#generate-ssxi-begin-syntax%
      (lambda (_%self273689%_ _%stx273690%_)
        (let* ((_%$%g273692273702%_
                (lambda (_%$%g273693273699%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g273693273699%_))))
               (_%$%g273691273726%_
                (lambda (_%$%g273693273705%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g273693273705%_))
                      (let ((_%$%e273695273707%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g273693273705%_))))
                        (let ((_%$%hd273696273710%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e273695273707%_)))
                              (_%$%tl273697273712%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e273695273707%_))))
                          (let ((__tmp274295
                                 (lambda ()
                                   (let ()
                                     (declare (not safe))
                                     (gxc#generate-runtime-begin%
                                      _%self273689%_
                                      _%stx273690%_))))
                                (__tmp274293
                                 (let ((__tmp274294
                                        (let ()
                                          (declare (not safe))
                                          (gx#current-expander-phi))))
                                   (declare (not safe))
                                   (##fx+ __tmp274294 '1))))
                            (declare (not safe))
                            (call-with-parameters__1
                             __tmp274295
                             gx#current-expander-phi
                             __tmp274293))))
                      (_%$%g273692273702%_ _%$%g273693273705%_)))))
          (_%$%g273691273726%_ _%stx273690%_))))
    (define gxc#generate-ssxi-module%
      (lambda (_%self273628%_ _%stx273629%_)
        (let* ((_%$%g273631273645%_
                (lambda (_%$%g273632273642%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g273632273642%_))))
               (_%$%g273630273686%_
                (lambda (_%$%g273632273648%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g273632273648%_))
                      (let ((_%$%e273635273650%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g273632273648%_))))
                        (let ((_%$%hd273636273653%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e273635273650%_)))
                              (_%$%tl273637273655%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e273635273650%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl273637273655%_))
                              (let ((_%$%e273638273658%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl273637273655%_))))
                                (let ((_%$%hd273639273661%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e273638273658%_)))
                                      (_%$%tl273640273663%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e273638273658%_))))
                                  (let* ((_%ctx273680%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#syntax-local-e__0
                                             _%$%hd273639273661%_)))
                                         (_%code273682%_
                                          (##structure-ref
                                           _%ctx273680%_
                                           '11
                                           gx#module-context::t
                                           '#f))
                                         (__tmp274296
                                          (lambda ()
                                            (let ()
                                              (declare (not safe))
                                              (gxc#compile-e__1
                                               _%self273628%_
                                               _%code273682%_)))))
                                    (declare (not safe))
                                    (call-with-parameters__1
                                     __tmp274296
                                     gx#current-expander-context
                                     _%ctx273680%_))))
                              (_%$%g273631273645%_ _%$%g273632273648%_))))
                      (_%$%g273631273645%_ _%$%g273632273648%_)))))
          (_%$%g273630273686%_ _%stx273629%_))))
    (define gxc#generate-ssxi-define-values%
      (lambda (_%self273435%_ _%stx273436%_)
        (letrec ((_%generate-e273438%_
                  (lambda (_%id273613%_)
                    (let* ((_%sym273615%_
                            (if (let ((__tmp274297
                                       (let ()
                                         (declare (not safe))
                                         (gx#datum->syntax__0 '#f 'id))))
                                  (declare (not safe))
                                  (gx#identifier? __tmp274297))
                                (let ()
                                  (declare (not safe))
                                  (gxc#identifier-symbol _%id273613%_))
                                '#f))
                           (_%$e273617%_
                            (let ()
                              (declare (not safe))
                              (gxc#optimizer-lookup-class _%sym273615%_))))
                      (if _%$e273617%_
                          (let ()
                            (let ()
                              (declare (not safe))
                              (gxc#verbose
                               '"generate class decl"
                               _%sym273615%_))
                            (cons 'begin
                                  (cons (cons 'declare-class
                                              (cons _%sym273615%_
                                                    (cons (let ((__method274272
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (__method-ref _%$e273617%_ 'typedecl))))
                    (if __method274272
                        (let ()
                          (declare (not safe))
                          (__method274272 _%$e273617%_))
                        (begin
                          (let ()
                            (declare (not safe))
                            (error '"Missing method" _%$e273617%_ 'typedecl))
                          '#!void)))
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (cons (cons 'declare-type
                                                    (cons _%sym273615%_
                                                          (cons (cons 'optimizer-resolve-class
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (list 'quote
                                          (list 'typedecl _%sym273615%_))
                                    '('class::t)))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              '()))))
                          (let ((_%$e273622%_
                                 (let ()
                                   (declare (not safe))
                                   (gxc#optimizer-lookup-type _%sym273615%_))))
                            (if _%$e273622%_
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (gxc#verbose
                                     '"generate typedecl "
                                     _%sym273615%_
                                     '" "
                                     _%$e273622%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (##structure-instance-of?
                                         _%$e273622%_
                                         'gxc#!class::t))
                                      (cons 'declare-type
                                            (cons _%sym273615%_
                                                  (cons (list 'optimizer-resolve-class
                                                              (list 'quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (list 'typedecl _%sym273615%_))
                      (list 'quote
                            (let ()
                              (declare (not safe))
                              (gxc#optimizer-lookup-class-name _%$e273622%_))))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (cons 'declare-type
                                            (cons _%sym273615%_
                                                  (cons (let ((__method274271
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (__method-ref _%$e273622%_ 'typedecl))))
                  (if __method274271
                      (let ()
                        (declare (not safe))
                        (__method274271 _%$e273622%_))
                      (begin
                        (let ()
                          (declare (not safe))
                          (error '"Missing method" _%$e273622%_ 'typedecl))
                        '#!void)))
                '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                '(begin))))))))
          (let* ((_%__stx273883273884%_ _%stx273436%_)
                 (_%$%g273441273479%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%__stx273883273884%_)))))
            (let ((_%__kont273885273886%_
                   (lambda (_%$%g273443273595%_)
                     (_%generate-e273438%_ _%$%g273443273595%_)))
                  (_%__kont273887273888%_
                   (lambda (_%$%g273456273530%_)
                     (let ((_%types273556%_
                            (map _%generate-e273438%_
                                 (let ((__tmp274298
                                        (lambda (_%$%g273548273551%_
                                                 _%$%g273549273553%_)
                                          (cons _%$%g273548273551%_
                                                _%$%g273549273553%_))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp274298
                                    '()
                                    _%$%g273456273530%_)))))
                       (cons 'begin _%types273556%_)))))
              (let ((_%__match273938273939%_
                     (lambda (_%$%e273457273484%_
                              _%$%hd273458273487%_
                              _%$%tl273459273489%_
                              _%$%e273460273492%_
                              _%$%hd273461273495%_
                              _%$%tl273462273497%_
                              _%__splice273889273890%_
                              _%$%target273463273500%_
                              _%$%tl273465273502%_)
                       (letrec ((_%$%loop273466273505%_
                                 (lambda (_%$%hd273464273508%_
                                          _%$%id273470273510%_)
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-pair? _%$%hd273464273508%_))
                                       (let ((_%$%e273467273512%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-e
                                                 _%$%hd273464273508%_))))
                                         (let ((_%$%lp-tl273469273517%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e273467273512%_)))
                                               (_%$%lp-hd273468273515%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e273467273512%_))))
                                           (_%$%loop273466273505%_
                                            _%$%lp-tl273469273517%_
                                            (cons _%$%lp-hd273468273515%_
                                                  _%$%id273470273510%_))))
                                       (let ((_%$%id273471273520%_
                                              (reverse _%$%id273470273510%_)))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%$%tl273462273497%_))
                                             (let ((_%$%e273472273522%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%tl273462273497%_))))
                                               (let ((_%$%tl273474273527%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e273472273522%_)))
                                                     (_%$%hd273473273525%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e273472273522%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-null?
                                                        _%$%tl273474273527%_))
                                                     (_%__kont273887273888%_
                                                      _%$%id273471273520%_)
                                                     (let ()
                                                       (declare (not safe))
                                                       (_%$%g273441273479%_)))))
                                             (let ()
                                               (declare (not safe))
                                               (_%$%g273441273479%_))))))))
                         (_%$%loop273466273505%_
                          _%$%target273463273500%_
                          '())))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%__stx273883273884%_))
                    (let ((_%$%e273444273563%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%__stx273883273884%_))))
                      (let ((_%$%tl273446273568%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e273444273563%_)))
                            (_%$%hd273445273566%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e273444273563%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl273446273568%_))
                            (let ((_%$%e273447273571%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl273446273568%_))))
                              (let ((_%$%tl273449273576%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e273447273571%_)))
                                    (_%$%hd273448273574%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e273447273571%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%hd273448273574%_))
                                    (let ((_%$%e273450273579%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%hd273448273574%_))))
                                      (let ((_%$%tl273452273584%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e273450273579%_)))
                                            (_%$%hd273451273582%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e273450273579%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl273452273584%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl273449273576%_))
                                                (let ((_%$%e273453273587%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl273449273576%_))))
                                                  (let ((_%$%tl273455273592%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e273453273587%_)))
                                                        (_%$%hd273454273590%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e273453273587%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl273455273592%_))
                                                        (_%__kont273885273886%_
                                                         _%$%hd273451273582%_)
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair/null?
                                                               _%$%hd273448273574%_))
                                                            (let ((_%__splice273889273890%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#syntax-split-splice->vector
                              _%$%hd273448273574%_
                              '0))))
                      (let ((_%$%tl273465273502%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%__splice273889273890%_ '1)))
                            (_%$%target273463273500%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%__splice273889273890%_ '0))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl273465273502%_))
                            (_%__match273938273939%_
                             _%$%e273444273563%_
                             _%$%hd273445273566%_
                             _%$%tl273446273568%_
                             _%$%e273447273571%_
                             _%$%hd273448273574%_
                             _%$%tl273449273576%_
                             _%__splice273889273890%_
                             _%$%target273463273500%_
                             _%$%tl273465273502%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g273441273479%_)))))
                    (let () (declare (not safe)) (_%$%g273441273479%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair/null?
                                                       _%$%hd273448273574%_))
                                                    (let ((_%__splice273889273890%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#syntax-split-splice->vector
                                                              _%$%hd273448273574%_
                                                              '0))))
                                                      (let ((_%$%tl273465273502%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##vector-ref _%__splice273889273890%_ '1)))
                    (_%$%target273463273500%_
                     (let ()
                       (declare (not safe))
                       (##vector-ref _%__splice273889273890%_ '0))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl273465273502%_))
                    (_%__match273938273939%_
                     _%$%e273444273563%_
                     _%$%hd273445273566%_
                     _%$%tl273446273568%_
                     _%$%e273447273571%_
                     _%$%hd273448273574%_
                     _%$%tl273449273576%_
                     _%__splice273889273890%_
                     _%$%target273463273500%_
                     _%$%tl273465273502%_)
                    (let () (declare (not safe)) (_%$%g273441273479%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g273441273479%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair/null?
                                                   _%$%hd273448273574%_))
                                                (let ((_%__splice273889273890%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#syntax-split-splice->vector
                                                          _%$%hd273448273574%_
                                                          '0))))
                                                  (let ((_%$%tl273465273502%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##vector-ref
                                                            _%__splice273889273890%_
                                                            '1)))
                                                        (_%$%target273463273500%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##vector-ref
                                                            _%__splice273889273890%_
                                                            '0))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl273465273502%_))
                                                        (_%__match273938273939%_
                                                         _%$%e273444273563%_
                                                         _%$%hd273445273566%_
                                                         _%$%tl273446273568%_
                                                         _%$%e273447273571%_
                                                         _%$%hd273448273574%_
                                                         _%$%tl273449273576%_
                                                         _%__splice273889273890%_
                                                         _%$%target273463273500%_
                                                         _%$%tl273465273502%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g273441273479%_)))))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g273441273479%_))))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair/null?
                                           _%$%hd273448273574%_))
                                        (let ((_%__splice273889273890%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-split-splice->vector
                                                  _%$%hd273448273574%_
                                                  '0))))
                                          (let ((_%$%tl273465273502%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice273889273890%_
                                                    '1)))
                                                (_%$%target273463273500%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice273889273890%_
                                                    '0))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl273465273502%_))
                                                (_%__match273938273939%_
                                                 _%$%e273444273563%_
                                                 _%$%hd273445273566%_
                                                 _%$%tl273446273568%_
                                                 _%$%e273447273571%_
                                                 _%$%hd273448273574%_
                                                 _%$%tl273449273576%_
                                                 _%__splice273889273890%_
                                                 _%$%target273463273500%_
                                                 _%$%tl273465273502%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g273441273479%_)))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g273441273479%_))))))
                            (let ()
                              (declare (not safe))
                              (_%$%g273441273479%_)))))
                    (let () (declare (not safe)) (_%$%g273441273479%_)))))))))
    (define gxc#generate-ssxi-call%
      (lambda (_%self272988%_ _%stx272989%_)
        (let* ((_%__stx273941273942%_ _%stx272989%_)
               (_%$%g272993273095%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx273941273942%_)))))
          (let ((_%__kont273943273944%_
                 (lambda (_%$%g272995273385%_
                          _%$%g272996273386%_
                          _%$%g272997273387%_
                          _%$%g272998273388%_
                          _%$%g272999273389%_)
                   (cons 'declare-method
                         (cons (let ()
                                 (declare (not safe))
                                 (gxc#identifier-symbol _%$%g272998273388%_))
                               (cons (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%g272997273387%_))
                                     (cons (let ()
                                             (declare (not safe))
                                             (gxc#identifier-symbol
                                              _%$%g272996273386%_))
                                           (cons (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%g272995273385%_))
                                                 '())))))))
                (_%__kont273945273946%_
                 (lambda (_%$%g273048273211%_
                          _%$%g273049273212%_
                          _%$%g273050273213%_
                          _%$%g273051273214%_)
                   (cons 'declare-method
                         (cons (let ()
                                 (declare (not safe))
                                 (gxc#identifier-symbol _%$%g273050273213%_))
                               (cons (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%g273049273212%_))
                                     (cons (let ()
                                             (declare (not safe))
                                             (gxc#identifier-symbol
                                              _%$%g273048273211%_))
                                           (cons '#f '())))))))
                (_%__kont273947273948%_ (lambda () '(begin))))
            (let ((_%__match274076274077%_
                   (lambda (_%$%e273000273257%_
                            _%$%hd273001273260%_
                            _%$%tl273002273262%_
                            _%$%e273003273265%_
                            _%$%hd273004273268%_
                            _%$%tl273005273270%_
                            _%$%e273006273273%_
                            _%$%hd273007273276%_
                            _%$%tl273008273278%_
                            _%$%e273009273281%_
                            _%$%hd273010273284%_
                            _%$%tl273011273286%_
                            _%$%e273012273289%_
                            _%$%hd273013273292%_
                            _%$%tl273014273294%_
                            _%$%e273015273297%_
                            _%$%hd273016273300%_
                            _%$%tl273017273302%_
                            _%$%e273018273305%_
                            _%$%hd273019273308%_
                            _%$%tl273020273310%_
                            _%$%e273021273313%_
                            _%$%hd273022273316%_
                            _%$%tl273023273318%_
                            _%$%e273024273321%_
                            _%$%hd273025273324%_
                            _%$%tl273026273326%_
                            _%$%e273027273329%_
                            _%$%hd273028273332%_
                            _%$%tl273029273334%_
                            _%$%e273030273337%_
                            _%$%hd273031273340%_
                            _%$%tl273032273342%_
                            _%$%e273033273345%_
                            _%$%hd273034273348%_
                            _%$%tl273035273350%_
                            _%$%e273036273353%_
                            _%$%hd273037273356%_
                            _%$%tl273038273358%_
                            _%$%e273039273361%_
                            _%$%hd273040273364%_
                            _%$%tl273041273366%_
                            _%$%e273042273369%_
                            _%$%hd273043273372%_
                            _%$%tl273044273374%_
                            _%$%e273045273377%_
                            _%$%hd273046273380%_
                            _%$%tl273047273382%_)
                     (let ((_%$%g272995273385%_ _%$%hd273046273380%_)
                           (_%$%g272996273386%_ _%$%hd273037273356%_)
                           (_%$%g272997273387%_ _%$%hd273028273332%_)
                           (_%$%g272998273388%_ _%$%hd273019273308%_)
                           (_%$%g272999273389%_ _%$%hd273010273284%_))
                       (if (let ()
                             (declare (not safe))
                             (gxc#runtime-identifier=?
                              _%$%g272999273389%_
                              'bind-method!))
                           (_%__kont273943273944%_
                            _%$%g272995273385%_
                            _%$%g272996273386%_
                            _%$%g272997273387%_
                            _%$%g272998273388%_
                            _%$%g272999273389%_)
                           (_%__kont273947273948%_))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx273941273942%_))
                  (let ((_%$%e273000273257%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx273941273942%_))))
                    (let ((_%$%tl273002273262%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e273000273257%_)))
                          (_%$%hd273001273260%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e273000273257%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl273002273262%_))
                          (let ((_%$%e273003273265%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl273002273262%_))))
                            (let ((_%$%tl273005273270%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e273003273265%_)))
                                  (_%$%hd273004273268%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e273003273265%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd273004273268%_))
                                  (let ((_%$%e273006273273%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd273004273268%_))))
                                    (let ((_%$%tl273008273278%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e273006273273%_)))
                                          (_%$%hd273007273276%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e273006273273%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd273007273276%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd273007273276%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl273008273278%_))
                                                  (let ((_%$%e273009273281%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl273008273278%_))))
                                                    (let ((_%$%tl273011273286%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e273009273281%_)))
                                                          (_%$%hd273010273284%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e273009273281%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl273011273286%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl273005273270%_))
                      (let ((_%$%e273012273289%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl273005273270%_))))
                        (let ((_%$%tl273014273294%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e273012273289%_)))
                              (_%$%hd273013273292%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e273012273289%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd273013273292%_))
                              (let ((_%$%e273015273297%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%hd273013273292%_))))
                                (let ((_%$%tl273017273302%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e273015273297%_)))
                                      (_%$%hd273016273300%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e273015273297%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd273016273300%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd273016273300%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl273017273302%_))
                                              (let ((_%$%e273018273305%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl273017273302%_))))
                                                (let ((_%$%tl273020273310%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e273018273305%_)))
                                                      (_%$%hd273019273308%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e273018273305%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl273020273310%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl273014273294%_))
                                                          (let ((_%$%e273021273313%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%tl273014273294%_))))
                    (let ((_%$%tl273023273318%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e273021273313%_)))
                          (_%$%hd273022273316%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e273021273313%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%hd273022273316%_))
                          (let ((_%$%e273024273321%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%hd273022273316%_))))
                            (let ((_%$%tl273026273326%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e273024273321%_)))
                                  (_%$%hd273025273324%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e273024273321%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#identifier? _%$%hd273025273324%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-eq?
                                         '%#quote
                                         _%$%hd273025273324%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl273026273326%_))
                                          (let ((_%$%e273027273329%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl273026273326%_))))
                                            (let ((_%$%tl273029273334%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e273027273329%_)))
                                                  (_%$%hd273028273332%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e273027273329%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-null?
                                                     _%$%tl273029273334%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl273023273318%_))
                                                      (let ((_%$%e273030273337%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl273023273318%_))))
                (let ((_%$%tl273032273342%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e273030273337%_)))
                      (_%$%hd273031273340%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e273030273337%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%hd273031273340%_))
                      (let ((_%$%e273033273345%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%hd273031273340%_))))
                        (let ((_%$%tl273035273350%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e273033273345%_)))
                              (_%$%hd273034273348%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e273033273345%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#identifier? _%$%hd273034273348%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-eq? '%#ref _%$%hd273034273348%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl273035273350%_))
                                      (let ((_%$%e273036273353%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl273035273350%_))))
                                        (let ((_%$%tl273038273358%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e273036273353%_)))
                                              (_%$%hd273037273356%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e273036273353%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl273038273358%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl273032273342%_))
                                                  (let ((_%$%e273039273361%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl273032273342%_))))
                                                    (let ((_%$%tl273041273366%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e273039273361%_)))
                                                          (_%$%hd273040273364%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e273039273361%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%hd273040273364%_))
                                                          (let ((_%$%e273042273369%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%hd273040273364%_))))
                    (let ((_%$%tl273044273374%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e273042273369%_)))
                          (_%$%hd273043273372%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e273042273369%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#identifier? _%$%hd273043273372%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-eq? '%#quote _%$%hd273043273372%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl273044273374%_))
                                  (let ((_%$%e273045273377%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl273044273374%_))))
                                    (let ((_%$%tl273047273382%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e273045273377%_)))
                                          (_%$%hd273046273380%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e273045273377%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl273047273382%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl273041273366%_))
                                              (_%__match274076274077%_
                                               _%$%e273000273257%_
                                               _%$%hd273001273260%_
                                               _%$%tl273002273262%_
                                               _%$%e273003273265%_
                                               _%$%hd273004273268%_
                                               _%$%tl273005273270%_
                                               _%$%e273006273273%_
                                               _%$%hd273007273276%_
                                               _%$%tl273008273278%_
                                               _%$%e273009273281%_
                                               _%$%hd273010273284%_
                                               _%$%tl273011273286%_
                                               _%$%e273012273289%_
                                               _%$%hd273013273292%_
                                               _%$%tl273014273294%_
                                               _%$%e273015273297%_
                                               _%$%hd273016273300%_
                                               _%$%tl273017273302%_
                                               _%$%e273018273305%_
                                               _%$%hd273019273308%_
                                               _%$%tl273020273310%_
                                               _%$%e273021273313%_
                                               _%$%hd273022273316%_
                                               _%$%tl273023273318%_
                                               _%$%e273024273321%_
                                               _%$%hd273025273324%_
                                               _%$%tl273026273326%_
                                               _%$%e273027273329%_
                                               _%$%hd273028273332%_
                                               _%$%tl273029273334%_
                                               _%$%e273030273337%_
                                               _%$%hd273031273340%_
                                               _%$%tl273032273342%_
                                               _%$%e273033273345%_
                                               _%$%hd273034273348%_
                                               _%$%tl273035273350%_
                                               _%$%e273036273353%_
                                               _%$%hd273037273356%_
                                               _%$%tl273038273358%_
                                               _%$%e273039273361%_
                                               _%$%hd273040273364%_
                                               _%$%tl273041273366%_
                                               _%$%e273042273369%_
                                               _%$%hd273043273372%_
                                               _%$%tl273044273374%_
                                               _%$%e273045273377%_
                                               _%$%hd273046273380%_
                                               _%$%tl273047273382%_)
                                              (_%__kont273947273948%_))
                                          (_%__kont273947273948%_))))
                                  (_%__kont273947273948%_))
                              (_%__kont273947273948%_))
                          (_%__kont273947273948%_))))
                  (_%__kont273947273948%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl273032273342%_))
                                                      (if (let ((__tmp274299
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f '-bind-method))))
                    (declare (not safe))
                    (gxc#runtime-identifier=? __tmp274299 'bind-method!))
                  (let ((_%$%g273048273211%_ _%$%hd273037273356%_)
                        (_%$%g273049273212%_ _%$%hd273028273332%_)
                        (_%$%g273050273213%_ _%$%hd273019273308%_)
                        (_%$%g273051273214%_ _%$%hd273010273284%_))
                    (_%__kont273945273946%_
                     _%$%g273048273211%_
                     _%$%g273049273212%_
                     _%$%g273050273213%_
                     _%$%g273051273214%_))
                  (_%__kont273947273948%_))
              (_%__kont273947273948%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont273947273948%_))))
                                      (_%__kont273947273948%_))
                                  (_%__kont273947273948%_))
                              (_%__kont273947273948%_))))
                      (_%__kont273947273948%_))))
              (_%__kont273947273948%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont273947273948%_))))
                                          (_%__kont273947273948%_))
                                      (_%__kont273947273948%_))
                                  (_%__kont273947273948%_))))
                          (_%__kont273947273948%_))))
                  (_%__kont273947273948%_))
              (_%__kont273947273948%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont273947273948%_))
                                          (_%__kont273947273948%_))
                                      (_%__kont273947273948%_))))
                              (_%__kont273947273948%_))))
                      (_%__kont273947273948%_))
                  (_%__kont273947273948%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont273947273948%_))
                                              (_%__kont273947273948%_))
                                          (_%__kont273947273948%_))))
                                  (_%__kont273947273948%_))))
                          (_%__kont273947273948%_))))
                  (_%__kont273947273948%_)))))))
    (define gxc#generate-ssxi-begin-annotation%
      (lambda (_%self272812%_ _%stx272813%_)
        (let* ((_%__stx274185274186%_ _%stx272813%_)
               (_%$%g272816272856%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx274185274186%_)))))
          (let ((_%__kont274187274188%_
                 (lambda (_%$%g272818272962%_ _%$%g272819272963%_)
                   (cons 'declare-inline-rule!
                         (cons (let ()
                                 (declare (not safe))
                                 (gxc#identifier-symbol _%$%g272819272963%_))
                               (cons _%$%g272818272962%_ '())))))
                (_%__kont274189274190%_
                 (lambda (_%$%g272841272885%_ _%$%g272842272886%_) '(begin))))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx274185274186%_))
                (let ((_%$%e272820272906%_
                       (let ()
                         (declare (not safe))
                         (gx#stx-e _%__stx274185274186%_))))
                  (let ((_%$%tl272822272911%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e272820272906%_)))
                        (_%$%hd272821272909%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e272820272906%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl272822272911%_))
                        (let ((_%$%e272823272914%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl272822272911%_))))
                          (let ((_%$%tl272825272919%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e272823272914%_)))
                                (_%$%hd272824272917%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e272823272914%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%hd272824272917%_))
                                (let ((_%$%e272826272922%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%hd272824272917%_))))
                                  (let ((_%$%tl272828272927%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e272826272922%_)))
                                        (_%$%hd272827272925%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e272826272922%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#identifier?
                                           _%$%hd272827272925%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-eq?
                                               '@inline
                                               _%$%hd272827272925%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl272828272927%_))
                                                (let ((_%$%e272829272930%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl272828272927%_))))
                                                  (let ((_%$%tl272831272935%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e272829272930%_)))
                                                        (_%$%hd272830272933%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e272829272930%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl272831272935%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl272825272919%_))
                                                            (let ((_%$%e272832272938%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl272825272919%_))))
                      (let ((_%$%tl272834272943%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e272832272938%_)))
                            (_%$%hd272833272941%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e272832272938%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%hd272833272941%_))
                            (let ((_%$%e272835272946%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%hd272833272941%_))))
                              (let ((_%$%tl272837272951%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e272835272946%_)))
                                    (_%$%hd272836272949%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e272835272946%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#identifier? _%$%hd272836272949%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-eq?
                                           '%#quote
                                           _%$%hd272836272949%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl272837272951%_))
                                            (let ((_%$%e272838272954%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl272837272951%_))))
                                              (let ((_%$%tl272840272959%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e272838272954%_)))
                                                    (_%$%hd272839272957%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e272838272954%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl272840272959%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl272834272943%_))
                                                        (_%__kont274187274188%_
                                                         _%$%hd272839272957%_
                                                         _%$%hd272830272933%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g272816272856%_)))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl272834272943%_))
                                                        (_%__kont274189274190%_
                                                         _%$%hd272833272941%_
                                                         _%$%hd272824272917%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g272816272856%_))))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl272834272943%_))
                                                (_%__kont274189274190%_
                                                 _%$%hd272833272941%_
                                                 _%$%hd272824272917%_)
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g272816272856%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl272834272943%_))
                                            (_%__kont274189274190%_
                                             _%$%hd272833272941%_
                                             _%$%hd272824272917%_)
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g272816272856%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl272834272943%_))
                                        (_%__kont274189274190%_
                                         _%$%hd272833272941%_
                                         _%$%hd272824272917%_)
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g272816272856%_))))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl272834272943%_))
                                (_%__kont274189274190%_
                                 _%$%hd272833272941%_
                                 _%$%hd272824272917%_)
                                (let ()
                                  (declare (not safe))
                                  (_%$%g272816272856%_))))))
                    (let () (declare (not safe)) (_%$%g272816272856%_)))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%$%tl272825272919%_))
                    (let ((_%$%e272849272877%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl272825272919%_))))
                      (let ((_%$%tl272851272882%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e272849272877%_)))
                            (_%$%hd272850272880%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e272849272877%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl272851272882%_))
                            (_%__kont274189274190%_
                             _%$%hd272850272880%_
                             _%$%hd272824272917%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g272816272856%_)))))
                    (let () (declare (not safe)) (_%$%g272816272856%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl272825272919%_))
                                                    (let ((_%$%e272849272877%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%tl272825272919%_))))
                                                      (let ((_%$%tl272851272882%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e272849272877%_)))
                    (_%$%hd272850272880%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e272849272877%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl272851272882%_))
                    (_%__kont274189274190%_
                     _%$%hd272850272880%_
                     _%$%hd272824272917%_)
                    (let () (declare (not safe)) (_%$%g272816272856%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g272816272856%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl272825272919%_))
                                                (let ((_%$%e272849272877%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl272825272919%_))))
                                                  (let ((_%$%tl272851272882%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e272849272877%_)))
                                                        (_%$%hd272850272880%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e272849272877%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl272851272882%_))
                                                        (_%__kont274189274190%_
                                                         _%$%hd272850272880%_
                                                         _%$%hd272824272917%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g272816272856%_)))))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g272816272856%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl272825272919%_))
                                            (let ((_%$%e272849272877%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl272825272919%_))))
                                              (let ((_%$%tl272851272882%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e272849272877%_)))
                                                    (_%$%hd272850272880%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e272849272877%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl272851272882%_))
                                                    (_%__kont274189274190%_
                                                     _%$%hd272850272880%_
                                                     _%$%hd272824272917%_)
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g272816272856%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g272816272856%_))))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%tl272825272919%_))
                                    (let ((_%$%e272849272877%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%tl272825272919%_))))
                                      (let ((_%$%tl272851272882%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e272849272877%_)))
                                            (_%$%hd272850272880%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e272849272877%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl272851272882%_))
                                            (_%__kont274189274190%_
                                             _%$%hd272850272880%_
                                             _%$%hd272824272917%_)
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g272816272856%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g272816272856%_))))))
                        (let () (declare (not safe)) (_%$%g272816272856%_)))))
                (let () (declare (not safe)) (_%$%g272816272856%_)))))))
    (define gxc#!nullable-type::typedecl
      (lambda (_%self272799%_)
        (let ((_%self272802%_ _%self272799%_))
          (list 'optimizer-resolve-type-expression
                ''typedecl
                (list 'quote
                      (let ()
                        (declare (not safe))
                        (gxc#optimizer-type-expression _%self272802%_)))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!nullable-type::t
       'typedecl
       gxc#!nullable-type::typedecl
       '#f))
    (define gxc#!alias::typedecl
      (lambda (_%self272664%_)
        (let ((_%self272667%_ _%self272664%_))
          (cons '@alias
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self272667%_ '1 '#f '#f))
                      '())))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!alias::t 'typedecl gxc#!alias::typedecl '#f))
    (define gxc#!class::typedecl
      (lambda (_%self272438%_)
        (let* ((_%self272441%_ _%self272438%_)
               (_%$%self272450272466%_ _%self272441%_)
               (_%$%E272452272469%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (error '"No clause matching"
                           _%$%self272450272466%_
                           '((!class id
                                     super
                                     precendence-list
                                     slots
                                     fields
                                     constructor
                                     struct?
                                     final?
                                     system?
                                     metaclass
                                     methods))))
                  '#!void))
               (_%$%K272453272484%_
                (lambda (_%methods272472%_
                         _%metaclass272473%_
                         _%system?272474%_
                         _%final?272475%_
                         _%struct?272476%_
                         _%constructor272477%_
                         _%fields272478%_
                         _%slots272479%_
                         _%precendence-list272480%_
                         _%super272481%_
                         _%id272482%_)
                  (cons '@class
                        (cons _%id272482%_
                              (cons _%super272481%_
                                    (cons _%precendence-list272480%_
                                          (cons _%slots272479%_
                                                (cons _%fields272478%_
                                                      (cons _%constructor272477%_
                                                            (cons _%struct?272476%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%final?272475%_
                                (cons _%system?272474%_
                                      (cons _%metaclass272473%_
                                            (cons (if _%methods272472%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (hash->list
                                                         _%methods272472%_))
                                                      '#f)
                                                  '()))))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
               (_%$%e272454272487%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '1
                   '#f
                   '#f)))
               (_%id272490%_ _%$%e272454272487%_)
               (_%$%e272455272492%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '2
                   '#f
                   '#f)))
               (_%super272495%_ _%$%e272455272492%_)
               (_%$%e272456272497%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '3
                   '#f
                   '#f)))
               (_%precendence-list272500%_ _%$%e272456272497%_)
               (_%$%e272457272502%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '4
                   '#f
                   '#f)))
               (_%slots272505%_ _%$%e272457272502%_)
               (_%$%e272458272507%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '5
                   '#f
                   '#f)))
               (_%fields272510%_ _%$%e272458272507%_)
               (_%$%e272459272512%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '6
                   '#f
                   '#f)))
               (_%constructor272515%_ _%$%e272459272512%_)
               (_%$%e272460272517%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '7
                   '#f
                   '#f)))
               (_%struct?272520%_ _%$%e272460272517%_)
               (_%$%e272461272522%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '8
                   '#f
                   '#f)))
               (_%final?272525%_ _%$%e272461272522%_)
               (_%$%e272462272527%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '9
                   '#f
                   '#f)))
               (_%system?272530%_ _%$%e272462272527%_)
               (_%$%e272463272532%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '10
                   '#f
                   '#f)))
               (_%metaclass272535%_ _%$%e272463272532%_)
               (_%$%e272464272537%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self272450272466%_
                   '11
                   '#f
                   '#f)))
               (_%methods272540%_ _%$%e272464272537%_))
          (_%$%K272453272484%_
           _%methods272540%_
           _%metaclass272535%_
           _%system?272530%_
           _%final?272525%_
           _%struct?272520%_
           _%constructor272515%_
           _%fields272510%_
           _%slots272505%_
           _%precendence-list272500%_
           _%super272495%_
           _%id272490%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!class::t 'typedecl gxc#!class::typedecl '#f))
    (define gxc#!predicate::typedecl
      (lambda (_%self272303%_)
        (let ((_%self272306%_ _%self272303%_))
          (cons '@predicate
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self272306%_ '1 '#f '#f))
                      '())))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!predicate::t
       'typedecl
       gxc#!predicate::typedecl
       '#f))
    (define gxc#!constructor::typedecl
      (lambda (_%self272168%_)
        (let ((_%self272171%_ _%self272168%_))
          (cons '@constructor
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self272171%_ '1 '#f '#f))
                      '())))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!constructor::t
       'typedecl
       gxc#!constructor::typedecl
       '#f))
    (define gxc#!accessor::typedecl
      (lambda (_%self272033%_)
        (let ((_%self272036%_ _%self272033%_))
          (cons '@accessor
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self272036%_ '1 '#f '#f))
                      (cons (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               _%self272036%_
                               '3
                               '#f
                               '#f))
                            (cons (let ()
                                    (declare (not safe))
                                    (##unchecked-structure-ref
                                     _%self272036%_
                                     '4
                                     '#f
                                     '#f))
                                  '())))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!accessor::t
       'typedecl
       gxc#!accessor::typedecl
       '#f))
    (define gxc#!mutator::typedecl
      (lambda (_%self271898%_)
        (let ((_%self271901%_ _%self271898%_))
          (cons '@mutator
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self271901%_ '1 '#f '#f))
                      (cons (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               _%self271901%_
                               '3
                               '#f
                               '#f))
                            (cons (let ()
                                    (declare (not safe))
                                    (##unchecked-structure-ref
                                     _%self271901%_
                                     '4
                                     '#f
                                     '#f))
                                  '())))))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!mutator::t 'typedecl gxc#!mutator::typedecl '#f))
    (define gxc#!interface::typedecl
      (lambda (_%self271763%_)
        (let ((_%self271766%_ _%self271763%_))
          (cons '@interface
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self271766%_ '1 '#f '#f))
                      (cons (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               _%self271766%_
                               '2
                               '#f
                               '#f))
                            '()))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!interface::t
       'typedecl
       gxc#!interface::typedecl
       '#f))
    (define gxc#!lambda::typedecl
      (lambda (_%self271577%_)
        (let* ((_%self271580%_ _%self271577%_)
               (_%$%self271589271598%_ _%self271580%_)
               (_%$%E271591271601%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (error '"No clause matching"
                           _%$%self271589271598%_
                           '((!lambda _ signature arity dispatch))))
                  '#!void))
               (_%$%K271592271620%_
                (lambda (_%dispatch271604%_
                         _%arity271605%_
                         _%signature271606%_)
                  (if _%signature271606%_
                      (let ((_%signature271608%_ _%signature271606%_))
                        (cons '@lambda
                              (cons _%arity271605%_
                                    (cons _%dispatch271604%_
                                          (cons 'signature:
                                                (cons (cons 'return:
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%signature271608%_
                             '1
                             '#f
                             '#f))
                          (cons 'effect:
                                (cons (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-ref
                                         _%signature271608%_
                                         '2
                                         '#f
                                         '#f))
                                      (cons 'arguments:
                                            (cons (let ()
                                                    (declare (not safe))
                                                    (##unchecked-structure-ref
                                                     _%signature271608%_
                                                     '3
                                                     '#f
                                                     '#f))
                                                  (cons 'unchecked:
                                                        (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##unchecked-structure-ref
                         _%signature271608%_
                         '4
                         '#f
                         '#f))
                      (cons 'origin:
                            (cons (let ()
                                    (declare (not safe))
                                    (##unchecked-structure-ref
                                     _%signature271608%_
                                     '5
                                     '#f
                                     '#f))
                                  '()))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
              '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                      (cons '@lambda
                            (cons _%arity271605%_
                                  (cons _%dispatch271604%_ '()))))))
               (_%$%e271593271623%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self271589271598%_
                   '1
                   '#f
                   '#f)))
               (_%$%e271594271626%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self271589271598%_
                   '2
                   '#f
                   '#f)))
               (_%signature271629%_ _%$%e271594271626%_)
               (_%$%e271595271631%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self271589271598%_
                   '3
                   '#f
                   '#f)))
               (_%arity271634%_ _%$%e271595271631%_)
               (_%$%e271596271636%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref
                   _%$%self271589271598%_
                   '4
                   '#f
                   '#f)))
               (_%dispatch271639%_ _%$%e271596271636%_))
          (_%$%K271592271620%_
           _%dispatch271639%_
           _%arity271634%_
           _%signature271629%_))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!lambda::t 'typedecl gxc#!lambda::typedecl '#f))
    (define gxc#!case-lambda::typedecl
      (lambda (_%self271437%_)
        (let ((_%self271440%_ _%self271437%_))
          (letrec ((_%clause-e271451%_
                    (lambda (_%clause271453%_)
                      (cdr (let ((__method274273
                                  (let ()
                                    (declare (not safe))
                                    (__method-ref
                                     _%clause271453%_
                                     'typedecl))))
                             (if __method274273
                                 (let ()
                                   (declare (not safe))
                                   (__method274273 _%clause271453%_))
                                 (begin
                                   (let ()
                                     (declare (not safe))
                                     (error '"Missing method"
                                            _%clause271453%_
                                            'typedecl))
                                   '#!void)))))))
            (cons '@case-lambda
                  (map _%clause-e271451%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%self271440%_
                          '3
                          '#f
                          '#f))))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!case-lambda::t
       'typedecl
       gxc#!case-lambda::typedecl
       '#f))
    (define gxc#!kw-lambda::typedecl
      (lambda (_%self271302%_)
        (let ((_%self271305%_ _%self271302%_))
          (cons '@kw-lambda
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self271305%_ '3 '#f '#f))
                      (cons (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               _%self271305%_
                               '4
                               '#f
                               '#f))
                            '()))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!kw-lambda::t
       'typedecl
       gxc#!kw-lambda::typedecl
       '#f))
    (define gxc#!kw-lambda-primary::typedecl
      (lambda (_%self271167%_)
        (let ((_%self271170%_ _%self271167%_))
          (cons '@kw-lambda-dispatch
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self271170%_ '3 '#f '#f))
                      (cons (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               _%self271170%_
                               '4
                               '#f
                               '#f))
                            '()))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!kw-lambda-primary::t
       'typedecl
       gxc#!kw-lambda-primary::typedecl
       '#f))
    (define gxc#!primitive-predicate::typedecl
      (lambda (_%self271032%_)
        (let ((_%self271035%_ _%self271032%_))
          (cons '@primitive-predicate
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%self271035%_ '1 '#f '#f))
                      '())))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!primitive-predicate::t
       'typedecl
       gxc#!primitive-predicate::typedecl
       '#f))))
