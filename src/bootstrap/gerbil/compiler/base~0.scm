(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/base::timestamp 1795039817)
  (begin
    (define gxc#__DEBUG-COMPILE
      (if (string? __DEBUG)
          (let ()
            (declare (not safe))
            (##string-contains __DEBUG '"compilation"))
          '#f))
    (define gxc#current-compile-symbol-table (make-parameter '#f))
    (define gxc#current-compile-runtime-sections (make-parameter '#f))
    (define gxc#current-compile-runtime-names (make-parameter '#f))
    (define gxc#current-compile-output-dir (make-parameter '#f))
    (define gxc#current-compile-invoke-gsc (make-parameter '#f))
    (define gxc#current-compile-gsc-options (make-parameter '#f))
    (define gxc#current-compile-keep-scm (make-parameter '#f))
    (define gxc#current-compile-verbose
      (make-parameter
       (let ((_%$%verbosity203045203047%_
              (let ()
                (declare (not safe))
                (##getenv '"GERBIL_BUILD_VERBOSE" '#f))))
         (if _%$%verbosity203045203047%_
             (let* ((_%verbosity203049%_ _%$%verbosity203045203047%_)
                    (_%$e203051%_ (string->number _%verbosity203049%_)))
               (if _%$e203051%_ _%$e203051%_ _%verbosity203049%_))
             '#f))))
    (define gxc#current-compile-optimize (make-parameter '#f))
    (define gxc#current-compile-debug (make-parameter '#f))
    (define gxc#current-compile-generate-ssxi (make-parameter '#f))
    (define gxc#current-compile-static (make-parameter '#f))
    (define gxc#current-compile-timestamp (make-parameter '#f))
    (define gxc#current-compile-decls (make-parameter '#f))
    (define gxc#current-compile-context (make-parameter '#f))
    (define gxc#current-compile-parallel (make-parameter '#f))
    (define gxc#current-compile-lift (make-parameter '#f))
    (define gxc#current-compile-marks (make-parameter '#f))
    (define gxc#current-compile-identifiers (make-parameter '#f))
    (define gxc#current-compile-boolean-context (make-parameter '#f))
    (define gxc#make-bound-identifier-table
      (lambda ()
        (letrec ((_%hash-e203042%_
                  (lambda (_%id203044%_)
                    (symbol-hash
                     (let () (declare (not safe)) (gx#stx-e _%id203044%_))))))
          (let ()
            (declare (not safe))
            (make-hash-table__%
             '#f
             absent-value
             absent-value
             gx#bound-identifier=?
             _%hash-e203042%_
             absent-value
             absent-value
             absent-value
             absent-value)))))
    (define gxc#current-compile-local-env (make-parameter '()))
    (define gxc#symbol-table::t
      (let ((__tmp203106 (list)) (__tmp203105 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#symbol-table::t
         'symbol-table
         __tmp203106
         '(gensyms bindings)
         __tmp203105
         ':init!)))
    (define gxc#symbol-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#symbol-table::t)))
    (define gxc#make-symbol-table
      (lambda _%$args203038%_
        (apply make-instance gxc#symbol-table::t _%$args203038%_)))
    (define gxc#symbol-table-gensyms
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#symbol-table::t 'gensyms)))
    (define gxc#symbol-table-bindings
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#symbol-table::t 'bindings)))
    (define gxc#symbol-table-gensyms-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#symbol-table::t 'gensyms)))
    (define gxc#symbol-table-bindings-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#symbol-table::t 'bindings)))
    (define gxc#&symbol-table-gensyms
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#symbol-table::t 'gensyms)))
    (define gxc#&symbol-table-bindings
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#symbol-table::t 'bindings)))
    (define gxc#&symbol-table-gensyms-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#symbol-table::t 'gensyms)))
    (define gxc#&symbol-table-bindings-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#symbol-table::t 'bindings)))
    (define gxc#symbol-table:::init!
      (lambda (_%self203025%_)
        (let ((_%self203028%_ _%self203025%_))
          (if (let ((__tmp203107
                     (let ()
                       (declare (not safe))
                       (##structure-length _%self203028%_))))
                (declare (not safe))
                (##fx< '2 __tmp203107))
              (begin
                (let ((__tmp203108
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self203028%_
                   __tmp203108
                   '1
                   '#f
                   '#f))
                (let ((__tmp203109
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self203028%_
                   __tmp203109
                   '2
                   '#f
                   '#f))
                '#!void)
              (let ((__tmp203110
                     (let ()
                       (declare (not safe))
                       (##structure-length _%self203028%_))))
                (declare (not safe))
                (error '"struct-instance-init!: too many arguments for struct"
                       _%self203028%_
                       '2
                       __tmp203110))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#symbol-table::t
       ':init!
       gxc#symbol-table:::init!
       '#f))
    (define gxc#raise-compile-error
      (lambda (_%message202894%_ _%stx202895%_ . _%details202896%_)
        (let ((_%ctx202901%_
               (let ((_%$e202898%_
                      (let ()
                        (declare (not safe))
                        (gxc#current-compile-context))))
                 (if _%$e202898%_ _%$e202898%_ '(compile)))))
          (apply gx#raise-syntax-error
                 _%ctx202901%_
                 _%message202894%_
                 _%stx202895%_
                 _%details202896%_))))
    (define gxc#verbose
      (lambda _%args202891%_
        (if (let () (declare (not safe)) (gxc#current-compile-verbose))
            (let ((__tmp203111
                   (lambda ()
                     (let ()
                       (declare (not safe))
                       (##apply displayln _%args202891%_)))))
              (declare (not safe))
              (__with-lock gxc#__verbose-mutex __tmp203111))
            '#!void)))
    (define gxc#__verbose-mutex (make-mutex 'compiler/driver))
    (define gxc#module-path-reserved-chars '":#<>&!?*;()[]{}|'`\"\\")
    (define gxc#module-id->path-string
      (lambda (_%id202873%_)
        (let* ((_%str202875%_
                (if (symbol? _%id202873%_)
                    (let ()
                      (declare (not safe))
                      (##symbol->string _%id202873%_))
                    _%id202873%_))
               (_%len202877%_ (string-length _%str202875%_))
               (_%res202879%_
                (let () (declare (not safe)) (##make-string _%len202877%_))))
          (let _%lp202882%_ ((_%i202884%_ '0))
            (if (let () (declare (not safe)) (##fx< _%i202884%_ _%len202877%_))
                (let* ((_%char202886%_ (string-ref _%str202875%_ _%i202884%_))
                       (_%xchar202888%_
                        (if (let ()
                              (declare (not safe))
                              (string-index__0
                               gxc#module-path-reserved-chars
                               _%char202886%_))
                            '#\_
                            _%char202886%_)))
                  (string-set! _%res202879%_ _%i202884%_ _%xchar202888%_)
                  (_%lp202882%_
                   (let () (declare (not safe)) (##fx+ _%i202884%_ '1))))
                _%res202879%_)))))
    (define gxc#map*
      (lambda (_%proc202815%_ _%maybe-improper-list202816%_)
        (let _%recur202818%_ ((_%rest202820%_ _%maybe-improper-list202816%_))
          (let* ((_%$%rest202821202832%_ _%rest202820%_)
                 (_%$%E202825202836%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (error '"No clause matching"
                             _%$%rest202821202832%_
                             '([hd . rest])
                             '([])
                             '(tail)))
                    '#!void)))
            (let ((_%$%K202828202861%_
                   (lambda (_%rest202858%_ _%hd202859%_)
                     (cons (_%proc202815%_ _%hd202859%_)
                           (_%recur202818%_ _%rest202858%_))))
                  (_%$%K202827202852%_ (lambda () '()))
                  (_%$%K202826202842%_
                   (lambda (_%tail202840%_) (_%proc202815%_ _%tail202840%_))))
              (let ((_%$%try-match202823202855%_
                     (lambda ()
                       (if (null? _%$%rest202821202832%_)
                           (_%$%K202827202852%_)
                           (let ((_%tail202845%_ _%$%rest202821202832%_))
                             (declare (not safe))
                             (_%proc202815%_ _%tail202845%_))))))
                (if (pair? _%$%rest202821202832%_)
                    (let ((_%$%tl202830202866%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest202821202832%_)))
                          (_%$%hd202829202864%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest202821202832%_))))
                      (let ((_%hd202869%_ _%$%hd202829202864%_)
                            (_%rest202871%_ _%$%tl202830202866%_))
                        (_%$%K202828202861%_ _%rest202871%_ _%hd202869%_)))
                    (_%$%try-match202823202855%_))))))))
    (define gxc#symbol-in-local-scope?
      (lambda (_%sym202810%_)
        (let ((_%$e202812%_ (not (gxc#gensym-reference? _%sym202810%_))))
          (if _%$e202812%_
              _%$e202812%_
              (memq _%sym202810%_
                    (let ()
                      (declare (not safe))
                      (gxc#current-compile-local-env)))))))
    (define gxc#gensym-reference?
      (lambda (_%sym202806%_)
        (let ((_%str202808%_ (symbol->string _%sym202806%_)))
          (if (let ()
                (declare (not safe))
                (##string-prefix? '"_%" _%str202808%_))
              (let ()
                (declare (not safe))
                (##string-suffix? '"%_" _%str202808%_))
              '#f))))
    (define gxc#generate-runtime-binding-id
      (lambda (_%id202777%_)
        (let ((_%$e202779%_
               (if (let ()
                     (declare (not safe))
                     (##structure-direct-instance-of?
                      _%id202777%_
                      'gx#syntax-quote::t))
                   (let ()
                     (declare (not safe))
                     (gx#resolve-identifier__0 _%id202777%_))
                   '#f)))
          (if _%$e202779%_
              (let ((_%eid202784%_
                     (##structure-ref _%$e202779%_ '1 gx#binding::t '#f))
                    (_%ht202785%_
                     (##structure-ref
                      (let ()
                        (declare (not safe))
                        (gxc#current-compile-symbol-table))
                      '2
                      gxc#symbol-table::t
                      '#f)))
                (if (let ()
                      (declare (not safe))
                      (interned-symbol? _%eid202784%_))
                    _%eid202784%_
                    (let ((_%$e202788%_
                           (let ()
                             (declare (not safe))
                             (hash-get _%ht202785%_ _%eid202784%_))))
                      (if _%$e202788%_
                          _%$e202788%_
                          (if (let ()
                                (declare (not safe))
                                (##structure-instance-of?
                                 _%$e202779%_
                                 'gx#local-binding::t))
                              (let ((_%gid202792%_
                                     (gxc#generate-runtime-gensym-reference__0
                                      _%eid202784%_)))
                                (let ()
                                  (declare (not safe))
                                  (hash-put!
                                   _%ht202785%_
                                   _%eid202784%_
                                   _%gid202792%_))
                                _%gid202792%_)
                              (if (let ()
                                    (declare (not safe))
                                    (##structure-instance-of?
                                     _%$e202779%_
                                     'gx#module-binding::t))
                                  (let ((_%gid202801%_
                                         (let ((_%$e202795%_
                                                (##structure-ref
                                                 (let ()
                                                   (declare (not safe))
                                                   (##unchecked-structure-ref
                                                    _%$e202779%_
                                                    '7
                                                    '#f
                                                    '#f))
                                                 '6
                                                 gx#module-context::t
                                                 '#f)))
                                           (if _%$e202795%_
                                               (let ()
                                                 (declare (not safe))
                                                 (make-symbol__1
                                                  _%$e202795%_
                                                  '"#"
                                                  _%eid202784%_))
                                               (gxc#generate-runtime-gensym-reference__0
                                                _%eid202784%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (hash-put!
                                       _%ht202785%_
                                       _%eid202784%_
                                       _%gid202801%_))
                                    _%gid202801%_)
                                  (gxc#raise-compile-error
                                   '"Cannot compile reference to uninterned binding"
                                   _%id202777%_
                                   _%eid202784%_
                                   _%$e202779%_)))))))
              (if (let ((__tmp203112
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%id202777%_))))
                    (declare (not safe))
                    (interned-symbol? __tmp203112))
                  (let () (declare (not safe)) (gx#stx-e _%id202777%_))
                  (gxc#raise-compile-error
                   '"Cannot compile reference to uninterned identifier"
                   _%id202777%_))))))
    (define gxc#generate-runtime-binding-id*
      (lambda (_%id202775%_)
        (if (let () (declare (not safe)) (gx#identifier? _%id202775%_))
            (gxc#generate-runtime-binding-id _%id202775%_)
            (gxc#generate-runtime-temporary__0))))
    (define gxc#generate-runtime-temporary__%
      (lambda (_%top202762%_)
        (if _%top202762%_
            (let ((_%ns202764%_
                   (##structure-ref
                    (let ((__tmp203113
                           (let ()
                             (declare (not safe))
                             (gx#current-expander-context))))
                      (declare (not safe))
                      (gx#core-context-top__1 __tmp203113))
                    '6
                    gx#module-context::t
                    '#f))
                  (_%phi202765%_
                   (let () (declare (not safe)) (gx#current-expander-phi))))
              (if _%ns202764%_
                  (if (fxpositive? _%phi202765%_)
                      (let ((__tmp203115 (number->string _%phi202765%_))
                            (__tmp203114
                             (let () (declare (not safe)) (##gensym))))
                        (declare (not safe))
                        (make-symbol__1
                         _%ns202764%_
                         '"["
                         __tmp203115
                         '"]#_"
                         __tmp203114
                         '"_"))
                      (let ((__tmp203116
                             (let () (declare (not safe)) (##gensym))))
                        (declare (not safe))
                        (make-symbol__1 _%ns202764%_ '"#_" __tmp203116 '"_")))
                  (if (fxpositive? _%phi202765%_)
                      (let ((__tmp203118 (number->string _%phi202765%_))
                            (__tmp203117
                             (let () (declare (not safe)) (##gensym))))
                        (declare (not safe))
                        (make-symbol__1
                         '"["
                         __tmp203118
                         '"]#_"
                         __tmp203117
                         '"_"))
                      (let ((__tmp203119
                             (let () (declare (not safe)) (##gensym))))
                        (declare (not safe))
                        (make-symbol__1 '"_" __tmp203119 '"_")))))
            (let ((__tmp203120 (let () (declare (not safe)) (##gensym))))
              (declare (not safe))
              (make-symbol__1 '"_" __tmp203120 '"_")))))
    (define gxc#generate-runtime-temporary__0
      (lambda ()
        (let ((_%top202771%_ '#f))
          (gxc#generate-runtime-temporary__% _%top202771%_))))
    (define gxc#generate-runtime-temporary
      (lambda _g203121_
        (let ((_g203122_ (let () (declare (not safe)) (##length _g203121_))))
          (cond ((let () (declare (not safe)) (##fx= _g203122_ 0))
                 (apply gxc#generate-runtime-temporary__0 _g203121_))
                ((let () (declare (not safe)) (##fx= _g203122_ 1))
                 (apply gxc#generate-runtime-temporary__% _g203121_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#generate-runtime-temporary
                  _g203121_))))))
    (define gxc#generate-runtime-gensym-reference__%
      (lambda (_%sym202740%_ _%quote?202741%_)
        (let* ((_%ht202743%_
                (##structure-ref
                 (let ()
                   (declare (not safe))
                   (gxc#current-compile-symbol-table))
                 '1
                 gxc#symbol-table::t
                 '#f))
               (_%$e202745%_
                (let ()
                  (declare (not safe))
                  (hash-get _%ht202743%_ _%sym202740%_))))
          (if _%$e202745%_
              _%$e202745%_
              (let ((_%g202749%_
                     (if _%quote?202741%_
                         (let ((__tmp203123
                                (let ()
                                  (declare (not safe))
                                  (gxc#current-compile-timestamp))))
                           (declare (not safe))
                           (make-symbol__1
                            '"__"
                            _%sym202740%_
                            '"__"
                            __tmp203123))
                         (let ()
                           (declare (not safe))
                           (make-symbol__1 '"_%" _%sym202740%_ '"%_")))))
                (let ()
                  (declare (not safe))
                  (hash-put! _%ht202743%_ _%sym202740%_ _%g202749%_))
                _%g202749%_)))))
    (define gxc#generate-runtime-gensym-reference__0
      (lambda (_%sym202754%_)
        (let ((_%quote?202756%_ '#f))
          (gxc#generate-runtime-gensym-reference__%
           _%sym202754%_
           _%quote?202756%_))))
    (define gxc#generate-runtime-gensym-reference
      (lambda _g203124_
        (let ((_g203125_ (let () (declare (not safe)) (##length _g203124_))))
          (cond ((let () (declare (not safe)) (##fx= _g203125_ 1))
                 (apply gxc#generate-runtime-gensym-reference__0 _g203124_))
                ((let () (declare (not safe)) (##fx= _g203125_ 2))
                 (apply gxc#generate-runtime-gensym-reference__% _g203124_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#generate-runtime-gensym-reference
                  _g203124_))))))
    (define gxc#generate-runtime-identifier
      (lambda (_%id202737%_)
        (gxc#generate-runtime-identifier-key
         (let () (declare (not safe)) (gx#core-identifier-key _%id202737%_)))))
    (define gxc#generate-runtime-identifier-key
      (lambda (_%key202692%_)
        (if (let () (declare (not safe)) (interned-symbol? _%key202692%_))
            _%key202692%_
            (if (uninterned-symbol? _%key202692%_)
                (gxc#generate-runtime-gensym-reference__0 _%key202692%_)
                (let* ((_%$%key202696202703%_ _%key202692%_)
                       (_%$%E202698202707%_
                        (lambda ()
                          (let ()
                            (declare (not safe))
                            (error '"No clause matching"
                                   _%$%key202696202703%_
                                   '([eid . mark])))
                          '#!void))
                       (_%$%K202699202725%_
                        (lambda (_%mark202710%_ _%eid202711%_)
                          (let ((_%$e202713%_
                                 (##structure-ref
                                  _%mark202710%_
                                  '1
                                  gx#expander-mark::t
                                  '#f)))
                            (if _%$e202713%_
                                (let ((_%$e202718%_
                                       (let ()
                                         (declare (not safe))
                                         (hash-get
                                          _%$e202713%_
                                          _%eid202711%_))))
                                  (if _%$e202718%_
                                      (if (let ()
                                            (declare (not safe))
                                            (interned-symbol? _%$e202718%_))
                                          _%$e202718%_
                                          (gxc#generate-runtime-gensym-reference__0
                                           _%$e202718%_))
                                      (gxc#generate-runtime-identifier-key
                                       _%eid202711%_)))
                                (gxc#generate-runtime-identifier-key
                                 _%eid202711%_))))))
                  (if (pair? _%$%key202696202703%_)
                      (let ((_%$%hd202700202728%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%key202696202703%_)))
                            (_%$%tl202701202730%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%key202696202703%_))))
                        (let* ((_%eid202733%_ _%$%hd202700202728%_)
                               (_%mark202735%_ _%$%tl202701202730%_))
                          (_%$%K202699202725%_ _%mark202735%_ _%eid202733%_)))
                      (_%$%E202698202707%_)))))))
    (define gxc#runtime-identifier=?
      (lambda (_%id1202685%_ _%id2202686%_)
        (letrec ((_%symbol-e202688%_
                  (lambda (_%id202690%_)
                    (if (symbol? _%id202690%_)
                        _%id202690%_
                        (gxc#generate-runtime-binding-id _%id202690%_)))))
          (eq? (_%symbol-e202688%_ _%id1202685%_)
               (_%symbol-e202688%_ _%id2202686%_)))))
    (define gxc#identifier-symbol
      (lambda (_%stx202683%_)
        (if (let ()
              (declare (not safe))
              (##structure-direct-instance-of?
               _%stx202683%_
               'gx#syntax-quote::t))
            (gxc#generate-runtime-binding-id _%stx202683%_)
            (let () (declare (not safe)) (gx#stx-e _%stx202683%_)))))
    (define gxc#runtime-identifier-properties
      (lambda (_%id202605%_)
        (let* ((_%bind202607%_
                (let ()
                  (declare (not safe))
                  (gx#resolve-identifier__0 _%id202605%_)))
               (_%runtime-props202636%_
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of?
                       _%bind202607%_
                       'gx#runtime-binding::t))
                    (let* ((_%props202616%_
                            (let ((_%$e202610%_
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%bind202607%_
                                      '6
                                      '#f
                                      '#f))))
                              (if _%$e202610%_
                                  (cons 'macro:
                                        (cons (gxc#generate-runtime-identifier
                                               _%$e202610%_)
                                              '()))
                                  '())))
                           (_%props202632%_
                            (let ((_%$e202618%_
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%bind202607%_
                                      '5
                                      '#f
                                      '#f))))
                              (if _%$e202618%_
                                  (let ((_%$e202623%_
                                         (let ()
                                           (declare (not safe))
                                           (__method-ref
                                            _%$e202618%_
                                            ':repr))))
                                    (if _%$e202623%_
                                        (let ((_%repr202628%_
                                               (_%$e202623%_ _%$e202618%_)))
                                          (cons 'type:
                                                (cons _%repr202628%_
                                                      _%props202616%_)))
                                        (gxc#raise-compile-error
                                         '"unrepresentable type"
                                         _%id202605%_
                                         _%$e202618%_)))
                                  _%props202616%_))))
                      _%props202632%_)
                    '()))
               (_%$e202639%_
                (##structure-ref _%bind202607%_ '4 gx#binding::t '#f)))
          (if _%$e202639%_
              (let ((__tmp203126
                     (lambda (_%prop202644%_ _%props202645%_)
                       (let* ((_%$%prop202646202653%_ _%prop202644%_)
                              (_%$%E202648202656%_
                               (lambda ()
                                 (let ()
                                   (declare (not safe))
                                   (error '"No clause matching"
                                          _%$%prop202646202653%_
                                          '([key . value])))
                                 '#!void))
                              (_%$%K202649202670%_
                               (lambda (_%value202659%_ _%key202660%_)
                                 (let ((_%$e202662%_
                                        (let ()
                                          (declare (not safe))
                                          (__method-ref
                                           _%value202659%_
                                           ':repr))))
                                   (if _%$e202662%_
                                       (let ((_%repr202667%_
                                              (_%$e202662%_ _%value202659%_)))
                                         (cons _%key202660%_
                                               (cons _%repr202667%_
                                                     _%props202645%_)))
                                       (cons _%key202660%_
                                             (cons (cons 'quote
                                                         (cons _%value202659%_
                                                               '()))
                                                   _%props202645%_)))))))
                         (if (pair? _%$%prop202646202653%_)
                             (let ((_%$%hd202650202673%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%prop202646202653%_)))
                                   (_%$%tl202651202675%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%prop202646202653%_))))
                               (let* ((_%key202678%_ _%$%hd202650202673%_)
                                      (_%value202680%_ _%$%tl202651202675%_))
                                 (_%$%K202649202670%_
                                  _%value202680%_
                                  _%key202678%_)))
                             (_%$%E202648202656%_))))))
                (declare (not safe))
                (foldl__0 __tmp203126 _%runtime-props202636%_ _%$e202639%_))
              _%runtime-props202636%_))))
    (define gxc#__compile-jobs '())
    (define gxc#__available-cores
      (string->number
       (let () (declare (not safe)) (##getenv '"GERBIL_BUILD_CORES" '"1"))))
    (define gxc#__jobs-mx (make-mutex))
    (define gxc#__jobs-cv (make-condition-variable))
    (define gxc#add-compile-job!__%
      (lambda (_%thunk202590%_ _%name202591%_)
        (mutex-lock! gxc#__jobs-mx)
        (let ((_%job202593%_
               (gxc#make-compile-job _%thunk202590%_ _%name202591%_)))
          (set! gxc#__compile-jobs (cons _%job202593%_ gxc#__compile-jobs)))
        (mutex-unlock! gxc#__jobs-mx)))
    (define gxc#add-compile-job!__0
      (lambda (_%thunk202598%_)
        (let ((_%name202600%_
               (let () (declare (not safe)) (gxc#current-compile-context))))
          (gxc#add-compile-job!__% _%thunk202598%_ _%name202600%_))))
    (define gxc#add-compile-job!
      (lambda _g203127_
        (let ((_g203128_ (let () (declare (not safe)) (##length _g203127_))))
          (cond ((let () (declare (not safe)) (##fx= _g203128_ 1))
                 (apply gxc#add-compile-job!__0 _g203127_))
                ((let () (declare (not safe)) (##fx= _g203128_ 2))
                 (apply gxc#add-compile-job!__% _g203127_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#add-compile-job!
                  _g203127_))))))
    (define gxc#pending-compile-jobs
      (lambda ()
        (mutex-lock! gxc#__jobs-mx)
        (let ((_%result202587%_ (reverse! gxc#__compile-jobs)))
          (set! gxc#__compile-jobs '())
          (mutex-unlock! gxc#__jobs-mx)
          _%result202587%_)))
    (define gxc#execute-pending-compile-jobs!
      (lambda ()
        (let _%loop202581%_ ()
          (let ((_%pending202584%_ (gxc#pending-compile-jobs)))
            (if (null? _%pending202584%_)
                '#!void
                (begin
                  (let ()
                    (declare (not safe))
                    (##for-each thread-start! _%pending202584%_))
                  (let ()
                    (declare (not safe))
                    (##for-each gxc#join! _%pending202584%_))))))))
    (define gxc#make-compile-job
      (lambda (_%thunk202570%_ _%name202571%_)
        (make-thread
         (lambda ()
           (let _%loop202574%_ ()
             (mutex-lock! gxc#__jobs-mx)
             (if (> gxc#__available-cores '0)
                 (begin
                   (set! gxc#__available-cores (- gxc#__available-cores '1))
                   (mutex-unlock! gxc#__jobs-mx)
                   (let ((__tmp203129
                          (lambda ()
                            (let ()
                              (declare (not safe))
                              (displayln
                               '"... execute compile job "
                               _%name202571%_)))))
                     (declare (not safe))
                     (__with-lock gxc#__verbose-mutex __tmp203129))
                   (let ((__tmp203131 (lambda () (_%thunk202570%_)))
                         (__tmp203130
                          (lambda ()
                            (mutex-lock! gxc#__jobs-mx)
                            (set! gxc#__available-cores
                                  (let ()
                                    (declare (not safe))
                                    (##fx+ gxc#__available-cores '1)))
                            (condition-variable-signal! gxc#__jobs-cv)
                            (mutex-unlock! gxc#__jobs-mx))))
                     (declare (not safe))
                     (__with-unwind-protect __tmp203131 __tmp203130)))
                 (begin
                   (mutex-unlock! gxc#__jobs-mx gxc#__jobs-cv)
                   (_%loop202574%_)))))
         _%name202571%_)))
    (define gxc#join!
      (lambda (_%thread202565%_)
        (let ((__tmp203133
               (lambda (_%exn202567%_)
                 (if (let ()
                       (declare (not safe))
                       (uncaught-exception? _%exn202567%_))
                     (let ((__tmp203134
                            (let ()
                              (declare (not safe))
                              (uncaught-exception-reason _%exn202567%_))))
                       (declare (not safe))
                       (raise __tmp203134))
                     (let () (declare (not safe)) (raise _%exn202567%_)))))
              (__tmp203132 (lambda () (thread-join! _%thread202565%_))))
          (declare (not safe))
          (__with-catch __tmp203133 __tmp203132))))))
