(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/driver::timestamp 1795039825)
  (begin
    (define gxc#default-gerbil-gsc
      (path-expand '"gsc" (path-expand '"bin" (path-expand '"~~"))))
    (define gxc#default-gerbil-gcc '"gcc")
    (define gxc#default-gerbil-ar '"ar")
    (define gxc#+driver-mutex+ (make-mutex 'compiler/driver))
    (define gxc#compile-timestamp
      (lambda ()
        (inexact->exact
         (floor (let ((__tmp276199 (current-time)))
                  (declare (not safe))
                  (##time->seconds __tmp276199))))))
    (define gxc#compile-timestamp-nanos
      (lambda ()
        (let ((__tmp276200 (current-time)))
          (declare (not safe))
          (##time->seconds __tmp276200))))
    (define gxc#scheme-file-settings
      '(permissions: 420 char-encoding: UTF-8 eol-encoding: lf))
    (define gxc#with-output-to-scheme-file
      (lambda (_%path276056%_ _%fun276057%_)
        (with-output-to-file
         (cons 'path: (cons _%path276056%_ gxc#scheme-file-settings))
         _%fun276057%_)))
    (define gxc#+gerbil-gsc+ '#f)
    (define gxc#gerbil-gsc
      (lambda ()
        (if gxc#+gerbil-gsc+
            '#!void
            (set! gxc#+gerbil-gsc+
                  (let ()
                    (declare (not safe))
                    (##getenv '"GERBIL_GSC" gxc#default-gerbil-gsc))))
        gxc#+gerbil-gsc+))
    (define gxc#+gerbil-gcc+ '#f)
    (define gxc#gerbil-gcc
      (lambda ()
        (if gxc#+gerbil-gcc+
            '#!void
            (set! gxc#+gerbil-gcc+
                  (let ()
                    (declare (not safe))
                    (##getenv '"GERBIL_GCC" gxc#default-gerbil-gcc))))
        gxc#+gerbil-gcc+))
    (define gxc#+gerbil-ar+ '#f)
    (define gxc#gerbil-ar
      (lambda ()
        (if gxc#+gerbil-ar+
            '#!void
            (set! gxc#+gerbil-ar+
                  (let ()
                    (declare (not safe))
                    (##getenv '"GERBIL_AR" gxc#default-gerbil-ar))))
        gxc#+gerbil-ar+))
    (define gxc#gerbil-rpath
      (lambda (_%gerbil-libdir276051%_)
        (string-append '"-Wl,-rpath=" _%gerbil-libdir276051%_)))
    (define gxc#compiler-obj-suffix '".o")
    (define gxc#include-source
      (lambda (_%path276049%_)
        (let ((__tmp276201 (object->string _%path276049%_)))
          (declare (not safe))
          (##string-append '"(include " __tmp276201 '")"))))
    (define gxc#gerbil-runtime-modules
      '("gerbil/runtime/gambit"
        "gerbil/runtime/util"
        "gerbil/runtime/table"
        "gerbil/runtime/control"
        "gerbil/runtime/system"
        "gerbil/runtime/c3"
        "gerbil/runtime/mop"
        "gerbil/runtime/mop-system-classes"
        "gerbil/runtime/error"
        "gerbil/runtime/interface"
        "gerbil/runtime/hash"
        "gerbil/runtime/thread"
        "gerbil/runtime/syntax"
        "gerbil/runtime/eval"
        "gerbil/runtime/repl"
        "gerbil/runtime/loader"
        "gerbil/runtime/init"
        "gerbil/runtime"))
    (define gxc#delete-directory*
      (lambda (_%dir276047%_) (delete-file-or-directory _%dir276047%_ '#t)))
    (define gxc#compile-module__%
      (lambda (_%srcpath275990%_ _%opts275991%_)
        (if (string? _%srcpath275990%_)
            '#!void
            (let ()
              (declare (not safe))
              (gxc#raise-compile-error
               '"Invalid module source path"
               _%srcpath275990%_)))
        (let* ((_%outdir275993%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'output-dir: _%opts275991%_)))
               (_%invoke-gsc?275995%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'invoke-gsc: _%opts275991%_)))
               (_%target276000%_
                (let ((_%$e275997%_
                       (let ()
                         (declare (not safe))
                         (pgetq__0 'target: _%opts275991%_))))
                  (if _%$e275997%_ _%$e275997%_ 'C)))
               (_%gsc-options276005%_
                (append (cons '"-target"
                              (cons (symbol->string _%target276000%_) '()))
                        (let ((_%$e276002%_
                               (let ()
                                 (declare (not safe))
                                 (pgetq__0 'gsc-options: _%opts275991%_))))
                          (if _%$e276002%_ _%$e276002%_ '()))))
               (_%keep-scm?276007%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'keep-scm: _%opts275991%_)))
               (_%verbosity276009%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'verbose: _%opts275991%_)))
               (_%optimize276011%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'optimize: _%opts275991%_)))
               (_%debug276013%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'debug: _%opts275991%_)))
               (_%gen-ssxi276015%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'generate-ssxi: _%opts275991%_)))
               (_%parallel?276017%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'parallel: _%opts275991%_))))
          (if _%outdir275993%_
              (let ((__tmp276202
                     (lambda ()
                       (let ()
                         (declare (not safe))
                         (create-directory*__0 _%outdir275993%_)))))
                (declare (not safe))
                (__with-lock gxc#+driver-mutex+ __tmp276202))
              '#!void)
          (if _%optimize276011%_
              (let ((__tmp276203
                     (lambda ()
                       (let ()
                         (declare (not safe))
                         (gxc#optimizer-info-init!)))))
                (declare (not safe))
                (__with-lock gxc#+driver-mutex+ __tmp276203))
              '#!void)
          (let ((__tmp276204
                 (lambda ()
                   (let ((__tmp276205
                          (lambda ()
                            (let ((__tmp276206
                                   (lambda ()
                                     (let ((__tmp276207
                                            (lambda ()
                                              (let ((__tmp276208
                                                     (lambda ()
                                                       (let ((__tmp276209
                                                              (lambda ()
                                                                (let ((__tmp276210
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (lambda ()
                                 (let ((__tmp276211
                                        (lambda ()
                                          (let ((__tmp276213
                                                 (lambda ()
                                                   (let ((__tmp276215
                                                          (lambda ()
                                                            (let ((__tmp276217
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (lambda ()
                             (let ((__tmp276218
                                    (lambda ()
                                      (let ((__tmp276219
                                             (lambda ()
                                               (let ((__tmp276220
                                                      (lambda ()
                                                        (let ()
                                                          (declare (not safe))
                                                          (gxc#verbose
                                                           '"compile "
                                                           _%srcpath275990%_))
                                                        (gxc#compile-top-module
                                                         (let ((__tmp276221
                                                                (lambda ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#import-module__0 _%srcpath275990%_)))))
                   (declare (not safe))
                   (__with-lock gxc#+driver-mutex+ __tmp276221))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (declare (not safe))
                                                 (call-with-parameters__1
                                                  __tmp276220
                                                  gx#current-expander-compiling?
                                                  '#t)))))
                                        (declare (not safe))
                                        (call-with-parameters__1
                                         __tmp276219
                                         gx#current-compilation-target
                                         _%target276000%_)))))
                               (declare (not safe))
                               (call-with-parameters__1
                                __tmp276218
                                gxc#current-compile-parallel
                                _%parallel?276017%_))))
                          (__tmp276216
                           (let ()
                             (declare (not safe))
                             (gxc#make-bound-identifier-table))))
                      (declare (not safe))
                      (call-with-parameters__1
                       __tmp276217
                       gxc#current-compile-identifiers
                       __tmp276216))))
                 (__tmp276214 (list (list 'compile-module _%srcpath275990%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (call-with-parameters__1
                                                      __tmp276215
                                                      gxc#current-compile-context
                                                      __tmp276214))))
                                                (__tmp276212
                                                 (gxc#compile-timestamp)))
                                            (declare (not safe))
                                            (call-with-parameters__1
                                             __tmp276213
                                             gxc#current-compile-timestamp
                                             __tmp276212)))))
                                   (declare (not safe))
                                   (call-with-parameters__1
                                    __tmp276211
                                    gxc#current-compile-generate-ssxi
                                    _%gen-ssxi276015%_)))))
                          (declare (not safe))
                          (call-with-parameters__1
                           __tmp276210
                           gxc#current-compile-debug
                           _%debug276013%_)))))
                 (declare (not safe))
                 (call-with-parameters__1
                  __tmp276209
                  gxc#current-compile-optimize
                  _%optimize276011%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (declare (not safe))
                                                (call-with-parameters__1
                                                 __tmp276208
                                                 gxc#current-compile-verbose
                                                 _%verbosity276009%_)))))
                                       (declare (not safe))
                                       (call-with-parameters__1
                                        __tmp276207
                                        gxc#current-compile-keep-scm
                                        _%keep-scm?276007%_)))))
                              (declare (not safe))
                              (call-with-parameters__1
                               __tmp276206
                               gxc#current-compile-gsc-options
                               _%gsc-options276005%_)))))
                     (declare (not safe))
                     (call-with-parameters__1
                      __tmp276205
                      gxc#current-compile-invoke-gsc
                      _%invoke-gsc?275995%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp276204
             gxc#current-compile-output-dir
             _%outdir275993%_)))))
    (define gxc#compile-module__0
      (lambda (_%srcpath276040%_)
        (let ((_%opts276042%_ '()))
          (gxc#compile-module__% _%srcpath276040%_ _%opts276042%_))))
    (define gxc#compile-module
      (lambda _g276222_
        (let ((_g276223_ (let () (declare (not safe)) (##length _g276222_))))
          (cond ((let () (declare (not safe)) (##fx= _g276223_ 1))
                 (apply gxc#compile-module__0 _g276222_))
                ((let () (declare (not safe)) (##fx= _g276223_ 2))
                 (apply gxc#compile-module__% _g276222_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#compile-module
                  _g276222_))))))
    (define gxc#compile-exe__%
      (lambda (_%srcpath275939%_ _%opts275940%_)
        (if (string? _%srcpath275939%_)
            '#!void
            (let ()
              (declare (not safe))
              (gxc#raise-compile-error
               '"Invalid module source path"
               _%srcpath275939%_)))
        (let* ((_%outdir275942%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'output-dir: _%opts275940%_)))
               (_%invoke-gsc?275944%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'invoke-gsc: _%opts275940%_)))
               (_%target275949%_
                (let ((_%$e275946%_
                       (let ()
                         (declare (not safe))
                         (pgetq__0 'target: _%opts275940%_))))
                  (if _%$e275946%_ _%$e275946%_ 'C)))
               (_%gsc-options275954%_
                (append (cons '"-target"
                              (cons (symbol->string _%target275949%_) '()))
                        (let ((_%$e275951%_
                               (let ()
                                 (declare (not safe))
                                 (pgetq__0 'gsc-options: _%opts275940%_))))
                          (if _%$e275951%_ _%$e275951%_ '()))))
               (_%keep-scm?275956%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'keep-scm: _%opts275940%_)))
               (_%verbosity275958%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'verbose: _%opts275940%_)))
               (_%debug275960%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'debug: _%opts275940%_)))
               (_%parallel?275962%_
                (let ()
                  (declare (not safe))
                  (pgetq__0 'parallel: _%opts275940%_))))
          (if _%outdir275942%_
              (let ((__tmp276224
                     (lambda ()
                       (let ()
                         (declare (not safe))
                         (create-directory*__0 _%outdir275942%_)))))
                (declare (not safe))
                (__with-lock gxc#+driver-mutex+ __tmp276224))
              '#!void)
          (let ((__tmp276225
                 (lambda ()
                   (let ((__tmp276226
                          (lambda ()
                            (let ((__tmp276227
                                   (lambda ()
                                     (let ((__tmp276228
                                            (lambda ()
                                              (let ((__tmp276229
                                                     (lambda ()
                                                       (let ((__tmp276230
                                                              (lambda ()
                                                                (let ((__tmp276231
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (lambda ()
                                 (let ((__tmp276233
                                        (lambda ()
                                          (let ((__tmp276235
                                                 (lambda ()
                                                   (let ((__tmp276237
                                                          (lambda ()
                                                            (let ((__tmp276238
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (lambda ()
                             (let ((__tmp276239
                                    (lambda ()
                                      (let ()
                                        (declare (not safe))
                                        (gxc#verbose
                                         '"compile exe "
                                         _%srcpath275939%_))
                                      (gxc#compile-executable-module
                                       (let ((__tmp276240
                                              (lambda ()
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#import-module__0
                                                   _%srcpath275939%_)))))
                                         (declare (not safe))
                                         (__with-lock
                                          gxc#+driver-mutex+
                                          __tmp276240))
                                       _%opts275940%_))))
                               (declare (not safe))
                               (call-with-parameters__1
                                __tmp276239
                                gx#current-expander-compiling?
                                '#t)))))
                      (declare (not safe))
                      (call-with-parameters__1
                       __tmp276238
                       gxc#current-compile-parallel
                       _%parallel?275962%_))))
                 (__tmp276236
                  (let ()
                    (declare (not safe))
                    (gxc#make-bound-identifier-table))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (call-with-parameters__1
                                                      __tmp276237
                                                      gxc#current-compile-identifiers
                                                      __tmp276236))))
                                                (__tmp276234
                                                 (list (list 'compile-exe
                                                             _%srcpath275939%_))))
                                            (declare (not safe))
                                            (call-with-parameters__1
                                             __tmp276235
                                             gxc#current-compile-context
                                             __tmp276234))))
                                       (__tmp276232 (gxc#compile-timestamp)))
                                   (declare (not safe))
                                   (call-with-parameters__1
                                    __tmp276233
                                    gxc#current-compile-timestamp
                                    __tmp276232)))))
                          (declare (not safe))
                          (call-with-parameters__1
                           __tmp276231
                           gxc#current-compile-debug
                           _%debug275960%_)))))
                 (declare (not safe))
                 (call-with-parameters__1
                  __tmp276230
                  gxc#current-compile-verbose
                  _%verbosity275958%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (declare (not safe))
                                                (call-with-parameters__1
                                                 __tmp276229
                                                 gxc#current-compile-keep-scm
                                                 _%keep-scm?275956%_)))))
                                       (declare (not safe))
                                       (call-with-parameters__1
                                        __tmp276228
                                        gxc#current-compile-gsc-options
                                        _%gsc-options275954%_)))))
                              (declare (not safe))
                              (call-with-parameters__1
                               __tmp276227
                               gx#current-compilation-target
                               _%target275949%_)))))
                     (declare (not safe))
                     (call-with-parameters__1
                      __tmp276226
                      gxc#current-compile-invoke-gsc
                      _%invoke-gsc?275944%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp276225
             gxc#current-compile-output-dir
             _%outdir275942%_)))))
    (define gxc#compile-exe__0
      (lambda (_%srcpath275982%_)
        (let ((_%opts275984%_ '()))
          (gxc#compile-exe__% _%srcpath275982%_ _%opts275984%_))))
    (define gxc#compile-exe
      (lambda _g276241_
        (let ((_g276242_ (let () (declare (not safe)) (##length _g276241_))))
          (cond ((let () (declare (not safe)) (##fx= _g276242_ 1))
                 (apply gxc#compile-exe__0 _g276241_))
                ((let () (declare (not safe)) (##fx= _g276242_ 2))
                 (apply gxc#compile-exe__% _g276241_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#compile-exe
                  _g276241_))))))
    (define gxc#compile-executable-module
      (lambda (_%ctx275935%_ _%opts275936%_)
        (if (let ()
              (declare (not safe))
              (pgetq__0 'full-program-optimization: _%opts275936%_))
            (gxc#compile-executable-module/full-program-optimization
             _%ctx275935%_
             _%opts275936%_)
            (gxc#compile-executable-module/separate
             _%ctx275935%_
             _%opts275936%_))))
    (define gxc#compile-executable-module/separate
      (lambda (_%ctx275661%_ _%opts275662%_)
        (letrec ((_%generate-stub275664%_
                  (lambda (_%builtin-modules275931%_)
                    (let ((_%mod-main275933%_
                           (gxc#find-runtime-symbol _%ctx275661%_ 'main)))
                      (let ((__tmp276243
                             (list 'define
                                   'builtin-modules
                                   (list 'quote _%builtin-modules275931%_))))
                        (declare (not safe))
                        (##write __tmp276243))
                      (let ((__tmp276244
                             (list 'define
                                   '(gerbil-main)
                                   (cons 'with-unwind-protect
                                         (cons (list 'lambda
                                                     '()
                                                     '(gerbil-runtime-init!
                                                       builtin-modules)
                                                     (cons 'apply
                                                           (cons _%mod-main275933%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '((cdr (command-line))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               '((lambda ()
                                                   (with-catch
                                                    void
                                                    (lambda ()
                                                      (force-output
                                                       (current-output-port))))
                                                   (with-catch
                                                    void
                                                    (lambda ()
                                                      (force-output
                                                       (current-error-port)))))))))))
                        (declare (not safe))
                        (##write __tmp276244))
                      (let () (declare (not safe)) (##write '(gerbil-main)))
                      (newline))))
                 (_%get-libgerbil-ld-opts275665%_
                  (lambda (_%gerbil-libdir275929%_)
                    (let ((__tmp276245
                           (path-expand
                            '"libgerbil.ldd"
                            _%gerbil-libdir275929%_)))
                      (declare (not safe))
                      (##call-with-input-file __tmp276245 read))))
                 (_%replace-extension275666%_
                  (lambda (_%path275926%_ _%ext275927%_)
                    (string-append
                     (path-strip-extension _%path275926%_)
                     _%ext275927%_)))
                 (_%replace-extension-with-c275667%_
                  (lambda (_%path275924%_)
                    (_%replace-extension275666%_ _%path275924%_ '".c")))
                 (_%replace-extension-with-object275668%_
                  (lambda (_%path275922%_)
                    (_%replace-extension275666%_
                     _%path275922%_
                     gxc#compiler-obj-suffix)))
                 (_%userlib-module?275669%_
                  (lambda (_%ctx275920%_)
                    (if (_%exclude-module?275671%_ _%ctx275920%_)
                        '#f
                        (not (_%libgerbil-module?275670%_ _%ctx275920%_)))))
                 (_%libgerbil-module?275670%_
                  (lambda (_%ctx275913%_)
                    (let ((_%id-str275915%_
                           (symbol->string
                            (##structure-ref
                             _%ctx275913%_
                             '1
                             gx#expander-context::t
                             '#f))))
                      (if (_%exclude-module?275671%_ _%id-str275915%_)
                          '#f
                          (let ((_%$e275917%_
                                 (let ()
                                   (declare (not safe))
                                   (##string-prefix?
                                    '"gerbil/"
                                    _%id-str275915%_))))
                            (if _%$e275917%_
                                _%$e275917%_
                                (let ()
                                  (declare (not safe))
                                  (##string-prefix?
                                   '"std/"
                                   _%id-str275915%_))))))))
                 (_%exclude-module?275671%_
                  (lambda (_%ctx-or-str275909%_)
                    (let ((_%str275911%_
                           (if (string? _%ctx-or-str275909%_)
                               _%ctx-or-str275909%_
                               (symbol->string
                                (##structure-ref
                                 _%ctx-or-str275909%_
                                 '1
                                 gx#expander-context::t
                                 '#f)))))
                      (declare (not safe))
                      (##string-prefix? '"gerbil/core" _%str275911%_))))
                 (_%not-file-empty?275672%_
                  (lambda (_%path275907%_)
                    (not (gxc#file-empty? _%path275907%_))))
                 (_%fold-libgerbil-runtime-scm275673%_
                  (lambda (_%gerbil-staticdir275900%_ _%libgerbil-scm275901%_)
                    (let ((_%gerbil-runtime-scm275905%_
                           (let ((__tmp276246
                                  (lambda (_%rtm275903%_)
                                    (path-expand
                                     (let ((__tmp276247
                                            (let ((__tmp276248
                                                   (let ()
                                                     (declare (not safe))
                                                     (string-split
                                                      _%rtm275903%_
                                                      '#\/))))
                                              (declare (not safe))
                                              (string-join
                                               __tmp276248
                                               '"__"))))
                                       (declare (not safe))
                                       (##string-append __tmp276247 '".scm"))
                                     _%gerbil-staticdir275900%_))))
                             (declare (not safe))
                             (##map __tmp276246 gxc#gerbil-runtime-modules))))
                      (_%remove-duplicates275674%_
                       (append _%gerbil-runtime-scm275905%_
                               _%libgerbil-scm275901%_)))))
                 (_%remove-duplicates275674%_
                  (lambda (_%strlst275860%_)
                    (let _%loop275862%_ ((_%rest275864%_ _%strlst275860%_)
                                         (_%result275865%_ '()))
                      (let* ((_%$%rest275866275874%_ _%rest275864%_)
                             (_%$%else275868275882%_
                              (lambda () (reverse! _%result275865%_)))
                             (_%$%K275870275888%_
                              (lambda (_%rest275885%_ _%path275886%_)
                                (if (member _%path275886%_ _%result275865%_)
                                    (_%loop275862%_
                                     _%rest275885%_
                                     _%result275865%_)
                                    (_%loop275862%_
                                     _%rest275885%_
                                     (cons _%path275886%_
                                           _%result275865%_))))))
                        (if (pair? _%$%rest275866275874%_)
                            (let ((_%$%hd275871275891%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest275866275874%_)))
                                  (_%$%tl275872275893%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest275866275874%_))))
                              (let* ((_%path275896%_ _%$%hd275871275891%_)
                                     (_%rest275898%_ _%$%tl275872275893%_))
                                (_%$%K275870275888%_
                                 _%rest275898%_
                                 _%path275896%_)))
                            (_%$%else275868275882%_))))))
                 (_%compile-stub275675%_
                  (lambda (_%output-scm275682%_ _%output-bin275683%_)
                    (let* ((_%gerbil-home275685%_
                            (let ((__tmp276249
                                   (let ()
                                     (declare (not safe))
                                     (gerbil-home))))
                              (declare (not safe))
                              (##getenv '"GERBIL_BUILD_PREFIX" __tmp276249)))
                           (_%gerbil-libdir275687%_
                            (path-expand '"lib" _%gerbil-home275685%_))
                           (_%gerbil-staticdir275689%_
                            (path-expand '"static" _%gerbil-libdir275687%_))
                           (_%deps275691%_
                            (gxc#find-runtime-module-deps _%ctx275661%_))
                           (_%libgerbil-deps275693%_
                            (let ()
                              (declare (not safe))
                              (##filter
                               _%libgerbil-module?275670%_
                               _%deps275691%_)))
                           (_%libgerbil-scm275695%_
                            (let ()
                              (declare (not safe))
                              (##map gxc#find-static-module-file
                                     _%libgerbil-deps275693%_)))
                           (_%libgerbil-scm275697%_
                            (_%fold-libgerbil-runtime-scm275673%_
                             _%gerbil-staticdir275689%_
                             _%libgerbil-scm275695%_))
                           (_%libgerbil-c275699%_
                            (map _%replace-extension-with-c275667%_
                                 _%libgerbil-scm275697%_))
                           (_%libgerbil-o275701%_
                            (map _%replace-extension-with-object275668%_
                                 _%libgerbil-scm275697%_))
                           (_%src-deps275703%_
                            (let ()
                              (declare (not safe))
                              (##filter
                               _%userlib-module?275669%_
                               _%deps275691%_)))
                           (_%src-deps-scm275705%_
                            (let ()
                              (declare (not safe))
                              (##map gxc#find-static-module-file
                                     _%src-deps275703%_)))
                           (_%src-deps-scm275707%_
                            (let ()
                              (declare (not safe))
                              (##filter
                               _%not-file-empty?275672%_
                               _%src-deps-scm275705%_)))
                           (_%src-deps-scm275709%_
                            (let ()
                              (declare (not safe))
                              (##map path-expand _%src-deps-scm275707%_)))
                           (_%src-deps-c275711%_
                            (let ()
                              (declare (not safe))
                              (##map _%replace-extension-with-c275667%_
                                     _%src-deps-scm275709%_)))
                           (_%src-deps-o275713%_
                            (let ()
                              (declare (not safe))
                              (##map _%replace-extension-with-object275668%_
                                     _%src-deps-scm275709%_)))
                           (_%src-bin-scm275715%_
                            (gxc#find-static-module-file _%ctx275661%_))
                           (_%src-bin-scm275717%_
                            (path-expand _%src-bin-scm275715%_))
                           (_%src-bin-c275719%_
                            (_%replace-extension-with-c275667%_
                             _%src-bin-scm275717%_))
                           (_%src-bin-o275721%_
                            (_%replace-extension-with-object275668%_
                             _%src-bin-scm275717%_))
                           (_%output-bin275723%_
                            (path-expand _%output-bin275683%_))
                           (_%output-scm275725%_
                            (path-expand _%output-scm275682%_))
                           (_%output-c275727%_
                            (_%replace-extension-with-c275667%_
                             _%output-scm275725%_))
                           (_%output-o275729%_
                            (_%replace-extension-with-object275668%_
                             _%output-scm275725%_))
                           (_%output_-c275731%_
                            (_%replace-extension275666%_
                             _%output-scm275725%_
                             '"_.c"))
                           (_%output_-o275733%_
                            (_%replace-extension275666%_
                             _%output-scm275725%_
                             (let ()
                               (declare (not safe))
                               (##string-append
                                '"_"
                                gxc#compiler-obj-suffix))))
                           (_%gsc-link-opts275735%_ (gxc#gsc-link-options__0))
                           (_%gsc-cc-opts275737%_
                            (gxc#gsc-cc-options__%__0 '#f '#t))
                           (_%gsc-static-opts275739%_
                            (gxc#gsc-static-include-options
                             _%gerbil-staticdir275689%_))
                           (_%output-ld-opts275741%_ (gxc#gcc-ld-options))
                           (_%libgerbil-ld-opts275743%_
                            (_%get-libgerbil-ld-opts275665%_
                             _%gerbil-libdir275687%_))
                           (_%rpath275745%_
                            (gxc#gerbil-rpath _%gerbil-libdir275687%_))
                           (_%builtin-modules275749%_
                            (_%remove-duplicates275674%_
                             (let ((__tmp276250
                                    (let ((__tmp276252
                                           (lambda (_%mod275747%_)
                                             (symbol->string
                                              (##structure-ref
                                               _%mod275747%_
                                               '1
                                               gx#expander-context::t
                                               '#f))))
                                          (__tmp276251
                                           (cons _%ctx275661%_
                                                 _%deps275691%_)))
                                      (declare (not safe))
                                      (##map __tmp276252 __tmp276251))))
                               (declare (not safe))
                               (##append
                                gxc#gerbil-runtime-modules
                                __tmp276250)))))
                      (letrec ((_%compile-obj275752%_
                                (lambda (_%scm-path275759%_ _%c-path275760%_)
                                  (let* ((_%o-path275762%_
                                          (_%replace-extension275666%_
                                           _%c-path275760%_
                                           gxc#compiler-obj-suffix))
                                         (_%lock275764%_
                                          (let ()
                                            (declare (not safe))
                                            (##string-append
                                             _%o-path275762%_
                                             '".lock")))
                                         (_%locked275766%_ '#f)
                                         (_%unlock275769%_
                                          (lambda ()
                                            (close-port _%locked275766%_)
                                            (let ()
                                              (declare (not safe))
                                              (##delete-file
                                               _%lock275764%_)))))
                                    (let _%retry275772%_ ()
                                      (if (let ()
                                            (declare (not safe))
                                            (##file-exists? _%lock275764%_))
                                          (begin
                                            (thread-sleep! '.01)
                                            (_%retry275772%_))
                                          (begin
                                            (set! _%locked275766%_
                                                  (let* ((_%handler275775%_
                                                          false)
                                                         (_%thunk275779%_
                                                          (lambda ()
                                                            (open-file
                                                             (cons 'path:
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%lock275764%_
                                 (cons 'create: (cons '#t '())))))))
                 (_%handler275784%_ _%handler275775%_)
                 (_%thunk275840%_ _%thunk275779%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (__with-catch
                                                     _%handler275784%_
                                                     _%thunk275840%_)))
                                            (if _%locked275766%_
                                                '#!void
                                                (_%retry275772%_)))))
                                    (let ((__tmp276254
                                           (lambda ()
                                             (if (or (not (let ()
                                                            (declare
                                                              (not safe))
                                                            (##file-exists?
                                                             _%o-path275762%_)))
                                                     (not _%scm-path275759%_)
                                                     (let ()
                                                       (declare (not safe))
                                                       (file-newer?
                                                        _%scm-path275759%_
                                                        _%o-path275762%_)))
                                                 (let ((_%gsc-cc-opts275857%_
                                                        (gxc#gsc-cc-options__%__0
                                                         '#f
                                                         '#f)))
                                                   (gxc#invoke__%
                                                    '#f
                                                    absent-value
                                                    absent-value
                                                    (gxc#gerbil-gsc)
                                                    (cons '"-obj"
                                                          (let ((__tmp276255
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ((__tmp276256 (cons _%c-path275760%_ '())))
                           (declare (not safe))
                           (##append _%gsc-static-opts275739%_ __tmp276256))))
                    (declare (not safe))
                    (##append _%gsc-cc-opts275857%_ __tmp276255)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '#!void)))
                                          (__tmp276253
                                           (lambda () (_%unlock275769%_))))
                                      (declare (not safe))
                                      (__with-unwind-protect
                                       __tmp276254
                                       __tmp276253))))))
                        (let ((__tmp276257
                               (lambda ()
                                 (let ((__tmp276258
                                        (path-directory _%output-bin275723%_)))
                                   (declare (not safe))
                                   (create-directory*__0 __tmp276258)))))
                          (declare (not safe))
                          (__with-lock gxc#+driver-mutex+ __tmp276257))
                        (gxc#with-output-to-scheme-file
                         _%output-scm275725%_
                         (lambda ()
                           (_%generate-stub275664%_
                            _%builtin-modules275749%_)))
                        (if (let ()
                              (declare (not safe))
                              (gxc#current-compile-invoke-gsc))
                            (let ((_%compile-it275757%_
                                   (lambda ()
                                     (gxc#invoke__%
                                      '#f
                                      absent-value
                                      absent-value
                                      (gxc#gerbil-gsc)
                                      (cons '"-link"
                                            (let ((__tmp276259
                                                   (let ((__tmp276260
                                                          (let ((__tmp276261
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons _%src-bin-scm275717%_
                               (cons _%output-scm275725%_ '()))))
                    (declare (not safe))
                    (##append _%src-deps-scm275709%_ __tmp276261))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##append
                                                      _%libgerbil-c275699%_
                                                      __tmp276260))))
                                              (declare (not safe))
                                              (##append
                                               _%gsc-link-opts275735%_
                                               __tmp276259))))
                                     (let ((__tmp276264
                                            (let ((__tmp276265
                                                   (cons _%src-bin-scm275717%_
                                                         (cons _%output-scm275725%_
                                                               (cons '#f
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (##append
                                               _%src-deps-scm275709%_
                                               __tmp276265)))
                                           (__tmp276262
                                            (let ((__tmp276263
                                                   (cons _%src-bin-c275719%_
                                                         (cons _%output-c275727%_
                                                               (cons _%output_-c275731%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (##append
                                               _%src-deps-c275711%_
                                               __tmp276263))))
                                       (declare (not safe))
                                       (##for-each
                                        _%compile-obj275752%_
                                        __tmp276264
                                        __tmp276262))
                                     (gxc#invoke__%
                                      '#f
                                      absent-value
                                      absent-value
                                      (gxc#gerbil-gcc)
                                      (cons '"-w"
                                            (cons '"-o"
                                                  (cons _%output-bin275723%_
                                                        (let ((__tmp276266
                                                               (cons _%src-bin-o275721%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (cons _%output-o275729%_
                                   (cons _%output_-o275733%_
                                         (let ((__tmp276267
                                                (let ((__tmp276268
                                                       (let ((__tmp276270
                                                              (if (gxc#gerbil-enable-shared?)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%rpath275745%_ '())
                          '()))
                     (__tmp276269
                      (cons '"-L"
                            (cons _%gerbil-libdir275687%_
                                  (cons '"-lgambit"
                                        _%libgerbil-ld-opts275743%_)))))
                 (declare (not safe))
                 (##append __tmp276270 __tmp276269))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (##append
                                                   _%output-ld-opts275741%_
                                                   __tmp276268))))
                                           (declare (not safe))
                                           (##append
                                            _%libgerbil-o275701%_
                                            __tmp276267)))))))
                  (declare (not safe))
                  (##append _%src-deps-o275713%_ __tmp276266))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (let ((__tmp276271
                                            (cons _%output-c275727%_
                                                  (cons _%output_-c275731%_
                                                        (cons _%output-o275729%_
                                                              (cons _%output_-o275733%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (declare (not safe))
                                       (##for-each delete-file __tmp276271)))))
                              (if (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-parallel))
                                  (let ()
                                    (declare (not safe))
                                    (gxc#add-compile-job!__0
                                     _%compile-it275757%_))
                                  (_%compile-it275757%_)))
                            '#!void))))))
          (let* ((_%output-bin275677%_
                  (gxc#compile-exe-output-file _%ctx275661%_ _%opts275662%_))
                 (_%output-scm275679%_
                  (let ()
                    (declare (not safe))
                    (##string-append _%output-bin275677%_ '"__exe.scm"))))
            (_%compile-stub275675%_
             _%output-scm275679%_
             _%output-bin275677%_)))))
    (define gxc#compile-executable-module/full-program-optimization
      (lambda (_%ctx275483%_ _%opts275484%_)
        (letrec ((_%reset-declare275486%_
                  (lambda ()
                    '(declare
                       (gambit-scheme)
                       (block)
                       (core)
                       (inline)
                       (inline-primitives)
                       (inlining-limit 350)
                       (constant-fold)
                       (lambda-lift)
                       (standard-bindings)
                       (extended-bindings)
                       (run-time-bindings)
                       (safe)
                       (interrupts-enabled)
                       (proper-tail-calls)
                       (not generative-lambda)
                       (optimize-dead-local-variables)
                       (optimize-dead-definitions)
                       (generic)
                       (mostly-fixnum-flonum))))
                 (_%generate-stub275487%_
                  (lambda (_%deps275652%_)
                    (let ((_%mod-main275654%_
                           (gxc#find-runtime-symbol _%ctx275483%_ 'main))
                          (_%reset-decl275655%_ (_%reset-declare275486%_))
                          (_%user-decl275656%_ (_%user-declare275488%_)))
                      (for-each
                       (lambda (_%dep275658%_)
                         (let ()
                           (declare (not safe))
                           (##write '(##namespace (""))))
                         (newline)
                         (let ()
                           (declare (not safe))
                           (##write _%reset-decl275655%_))
                         (newline)
                         (if _%user-decl275656%_
                             (begin
                               (let ()
                                 (declare (not safe))
                                 (##write _%user-decl275656%_))
                               (newline))
                             '#!void)
                         (let ((__tmp276272 (list 'include _%dep275658%_)))
                           (declare (not safe))
                           (##write __tmp276272))
                         (newline))
                       _%deps275652%_)
                      (let ((__tmp276273
                             (list 'define
                                   '(gerbil-main)
                                   '(gerbil-runtime-init! '())
                                   (cons 'apply
                                         (cons _%mod-main275654%_
                                               '((cdr (command-line))))))))
                        (declare (not safe))
                        (##write __tmp276273))
                      (let () (declare (not safe)) (##write '(gerbil-main)))
                      (newline))))
                 (_%user-declare275488%_
                  (lambda ()
                    (let* ((_%gsc-opts275557%_
                            (let ()
                              (declare (not safe))
                              (pgetq__0 'gsc-options: _%opts275484%_)))
                           (_%gsc-prelude275559%_
                            (if _%gsc-opts275557%_
                                (member '"-prelude" _%gsc-opts275557%_)
                                '#f))
                           (_%gsc-prelude275561%_
                            (if _%gsc-prelude275559%_
                                (read (open-input-string
                                       (cadr _%gsc-prelude275559%_)))
                                '#f)))
                      (let _%lp275564%_ ((_%rest275566%_
                                          (cons _%gsc-prelude275561%_ '()))
                                         (_%user-decls275567%_ '()))
                        (let* ((_%$%rest275568275576%_ _%rest275566%_)
                               (_%$%else275570275584%_
                                (lambda ()
                                  (if (null? _%user-decls275567%_)
                                      '#f
                                      (cons 'declare
                                            (reverse _%user-decls275567%_)))))
                               (_%$%K275572275640%_
                                (lambda (_%rest275587%_ _%expr275588%_)
                                  (let* ((_%$%expr275589275601%_
                                          _%expr275588%_)
                                         (_%$%else275592275609%_
                                          (lambda ()
                                            (_%lp275564%_
                                             _%rest275587%_
                                             _%user-decls275567%_))))
                                    (let ((_%$%K275597275630%_
                                           (lambda (_%decls275628%_)
                                             (_%lp275564%_
                                              _%rest275587%_
                                              (let ()
                                                (declare (not safe))
                                                (foldl__0
                                                 cons
                                                 _%user-decls275567%_
                                                 _%decls275628%_)))))
                                          (_%$%K275594275615%_
                                           (lambda (_%exprs275613%_)
                                             (_%lp275564%_
                                              (append _%exprs275613%_
                                                      _%rest275587%_)
                                              _%user-decls275567%_))))
                                      (if (pair? _%$%expr275589275601%_)
                                          (let ((_%$%tl275599275635%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%expr275589275601%_)))
                                                (_%$%hd275598275633%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%expr275589275601%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##eq? _%$%hd275598275633%_
                                                         'declare))
                                                (let ((_%decls275638%_
                                                       _%$%tl275599275635%_))
                                                  (_%$%K275597275630%_
                                                   _%decls275638%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##eq? _%$%hd275598275633%_
                                                             'begin))
                                                    (let ((_%exprs275623%_
                                                           _%$%tl275599275635%_))
                                                      (_%$%K275594275615%_
                                                       _%exprs275623%_))
                                                    (_%$%else275592275609%_))))
                                          (_%$%else275592275609%_)))))))
                          (if (pair? _%$%rest275568275576%_)
                              (let ((_%$%hd275573275643%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest275568275576%_)))
                                    (_%$%tl275574275645%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest275568275576%_))))
                                (let* ((_%expr275648%_ _%$%hd275573275643%_)
                                       (_%rest275650%_ _%$%tl275574275645%_))
                                  (_%$%K275572275640%_
                                   _%rest275650%_
                                   _%expr275648%_)))
                              (_%$%else275570275584%_)))))))
                 (_%compile-stub275489%_
                  (lambda (_%output-scm275496%_ _%output-bin275497%_)
                    (let* ((_%gerbil-home275499%_
                            (let ((__tmp276274
                                   (let ()
                                     (declare (not safe))
                                     (gerbil-home))))
                              (declare (not safe))
                              (##getenv '"GERBIL_BUILD_PREFIX" __tmp276274)))
                           (_%gerbil-libdir275501%_
                            (path-expand '"lib" _%gerbil-home275499%_))
                           (_%runtime275503%_
                            (let ()
                              (declare (not safe))
                              (##map gxc#find-static-module-file
                                     gxc#gerbil-runtime-modules)))
                           (_%gambit-sharp275505%_
                            (path-expand
                             '"lib/_gambit#.scm"
                             _%gerbil-home275499%_))
                           (_%include-gambit-sharp275507%_
                            (gxc#include-source _%gambit-sharp275505%_))
                           (_%bin-scm275509%_
                            (gxc#find-static-module-file _%ctx275483%_))
                           (_%deps275511%_
                            (gxc#find-runtime-module-deps _%ctx275483%_))
                           (_%deps275513%_
                            (let ()
                              (declare (not safe))
                              (##map gxc#find-static-module-file
                                     _%deps275511%_)))
                           (_%deps275518%_
                            (let ((__tmp276275
                                   (lambda (_%$obj275515%_)
                                     (not (gxc#file-empty? _%$obj275515%_)))))
                              (declare (not safe))
                              (##filter __tmp276275 _%deps275513%_)))
                           (_%deps275522%_
                            (let ((__tmp276276
                                   (lambda (_%f275520%_)
                                     (not (let ()
                                            (declare (not safe))
                                            (##member
                                             _%f275520%_
                                             _%runtime275503%_))))))
                              (declare (not safe))
                              (##filter __tmp276276 _%deps275518%_)))
                           (_%output-base275524%_
                            (let ((__tmp276277
                                   (path-strip-extension
                                    _%output-scm275496%_)))
                              (declare (not safe))
                              (##string-append __tmp276277)))
                           (_%output-c275526%_
                            (let ()
                              (declare (not safe))
                              (##string-append _%output-base275524%_ '".c")))
                           (_%output-o275528%_
                            (let ()
                              (declare (not safe))
                              (##string-append
                               _%output-base275524%_
                               gxc#compiler-obj-suffix)))
                           (_%output-c_275530%_
                            (let ()
                              (declare (not safe))
                              (##string-append _%output-base275524%_ '"_.c")))
                           (_%output-o_275532%_
                            (let ((__tmp276278
                                   (let ()
                                     (declare (not safe))
                                     (##string-append
                                      '"_"
                                      gxc#compiler-obj-suffix))))
                              (declare (not safe))
                              (##string-append
                               _%output-base275524%_
                               __tmp276278)))
                           (_%gsc-link-opts275534%_ (gxc#gsc-link-options__0))
                           (_%gsc-cc-opts275536%_
                            (gxc#gsc-cc-options__%__0 '#f '#t))
                           (_%gsc-static-opts275538%_
                            (gxc#gsc-static-include-options
                             (path-expand '"static" _%gerbil-libdir275501%_)))
                           (_%output-ld-opts275540%_ (gxc#gcc-ld-options))
                           (_%gsc-gx-macros275542%_
                            (if (let ()
                                  (declare (not safe))
                                  (gerbil-runtime-smp?))
                                (cons '"-e"
                                      (cons '"(define-cond-expand-feature|enable-smp|)"
                                            (cons '"-e"
                                                  (cons _%include-gambit-sharp275507%_
                                                        '()))))
                                (cons '"-e"
                                      (cons _%include-gambit-sharp275507%_
                                            '()))))
                           (_%gsc-link-opts275544%_
                            (let ()
                              (declare (not safe))
                              (##append
                               _%gsc-link-opts275534%_
                               _%gsc-gx-macros275542%_)))
                           (_%rpath275546%_
                            (gxc#gerbil-rpath _%gerbil-libdir275501%_))
                           (_%default-ld-options275548%_
                            (cons '"-ldl" (cons '"-lm" '()))))
                      (let ((__tmp276279
                             (lambda ()
                               (let ((__tmp276280
                                      (path-directory _%output-bin275497%_)))
                                 (declare (not safe))
                                 (create-directory*__0 __tmp276280)))))
                        (declare (not safe))
                        (__with-lock gxc#+driver-mutex+ __tmp276279))
                      (gxc#with-output-to-scheme-file
                       _%output-scm275496%_
                       (lambda ()
                         (_%generate-stub275487%_
                          (let ((__tmp276281
                                 (let ((__tmp276282
                                        (cons _%bin-scm275509%_ '())))
                                   (declare (not safe))
                                   (##append _%deps275522%_ __tmp276282))))
                            (declare (not safe))
                            (##append _%runtime275503%_ __tmp276281)))))
                      (if (let ()
                            (declare (not safe))
                            (gxc#current-compile-invoke-gsc))
                          (let ((_%compile-it275554%_
                                 (lambda ()
                                   (gxc#invoke__%
                                    '#f
                                    absent-value
                                    absent-value
                                    (gxc#gerbil-gsc)
                                    (cons '"-link"
                                          (cons '"-o"
                                                (cons _%output-c_275530%_
                                                      (let ((__tmp276283
                                                             (cons _%output-scm275496%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
                (declare (not safe))
                (##append _%gsc-link-opts275544%_ __tmp276283))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                   (gxc#invoke__%
                                    '#f
                                    absent-value
                                    absent-value
                                    (gxc#gerbil-gsc)
                                    (cons '"-obj"
                                          (let ((__tmp276284
                                                 (let ((__tmp276285
                                                        (cons _%output-c275526%_
                                                              (cons _%output-c_275530%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (declare (not safe))
                                                   (##append
                                                    _%gsc-static-opts275538%_
                                                    __tmp276285))))
                                            (declare (not safe))
                                            (##append
                                             _%gsc-cc-opts275536%_
                                             __tmp276284))))
                                   (gxc#invoke__%
                                    '#f
                                    absent-value
                                    absent-value
                                    (gxc#gerbil-gcc)
                                    (cons '"-w"
                                          (cons '"-o"
                                                (cons _%output-bin275497%_
                                                      (cons _%output-o275528%_
                                                            (cons _%output-o_275532%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ((__tmp276286
                                 (let ((__tmp276288
                                        (if (gxc#gerbil-enable-shared?)
                                            (cons _%rpath275546%_ '())
                                            '()))
                                       (__tmp276287
                                        (cons '"-L"
                                              (cons _%gerbil-libdir275501%_
                                                    (cons '"-lgambit"
                                                          _%default-ld-options275548%_)))))
                                   (declare (not safe))
                                   (##append __tmp276288 __tmp276287))))
                            (declare (not safe))
                            (##append
                             _%output-ld-opts275540%_
                             __tmp276286)))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                            (if (let ()
                                  (declare (not safe))
                                  (gxc#current-compile-parallel))
                                (let ()
                                  (declare (not safe))
                                  (gxc#add-compile-job!__0
                                   _%compile-it275554%_))
                                (_%compile-it275554%_)))
                          '#!void)))))
          (let* ((_%output-bin275491%_
                  (gxc#compile-exe-output-file _%ctx275483%_ _%opts275484%_))
                 (_%output-scm275493%_
                  (let ()
                    (declare (not safe))
                    (##string-append _%output-bin275491%_ '"__exe.scm"))))
            (_%compile-stub275489%_
             _%output-scm275493%_
             _%output-bin275491%_)))))
    (define gxc#find-export-binding
      (lambda (_%ctx275432%_ _%id275433%_)
        (let ((_%$e275479%_
               (let ((__tmp276290
                      (lambda (_%$%e275434275436%_)
                        (let* ((_%$%$%e275434275438275448%_
                                _%$%e275434275436%_)
                               (_%$%else275440275456%_ (lambda () '#f))
                               (_%$%K275442275460%_ (lambda () '#t)))
                          (if (let ()
                                (declare (not safe))
                                (##structure-direct-instance-of?
                                 _%$%$%e275434275438275448%_
                                 'gx#module-export::t))
                              (let* ((_%$%e275443275463%_
                                      (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-ref
                                         _%$%$%e275434275438275448%_
                                         '1
                                         '#f
                                         '#f)))
                                     (_%$%e275444275466%_
                                      (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-ref
                                         _%$%$%e275434275438275448%_
                                         '2
                                         '#f
                                         '#f)))
                                     (_%$%e275445275469%_
                                      (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-ref
                                         _%$%$%e275434275438275448%_
                                         '3
                                         '#f
                                         '#f))))
                                (if (let ()
                                      (declare (not safe))
                                      (##eq? _%$%e275445275469%_ '0))
                                    (let ((_%$%e275446275472%_
                                           (let ()
                                             (declare (not safe))
                                             (##unchecked-structure-ref
                                              _%$%$%e275434275438275448%_
                                              '4
                                              '#f
                                              '#f))))
                                      (if (eq? _%$%e275446275472%_
                                               _%id275433%_)
                                          (_%$%K275442275460%_)
                                          (_%$%else275440275456%_)))
                                    (_%$%else275440275456%_)))
                              (_%$%else275440275456%_)))))
                     (__tmp276289
                      (##structure-ref
                       _%ctx275432%_
                       '9
                       gx#module-context::t
                       '#f)))
                 (declare (not safe))
                 (__find __tmp276290 __tmp276289))))
          (if _%$e275479%_
              (let ()
                (declare (not safe))
                (gx#core-resolve-module-export _%$e275479%_))
              '#f))))
    (define gxc#find-runtime-symbol
      (lambda (_%ctx275423%_ _%id275424%_)
        (let ((_%$e275426%_
               (gxc#find-export-binding _%ctx275423%_ _%id275424%_)))
          (if _%$e275426%_
              (let ()
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of?
                       _%$e275426%_
                       'gx#runtime-binding::t))
                    '#!void
                    (let ()
                      (declare (not safe))
                      (gxc#raise-compile-error
                       '"export is not a runtime binding"
                       _%id275424%_)))
                (##structure-ref _%$e275426%_ '1 gx#binding::t '#f))
              (let ((__tmp276291
                     (##structure-ref
                      _%ctx275423%_
                      '1
                      gx#expander-context::t
                      '#f)))
                (declare (not safe))
                (gxc#raise-compile-error
                 '"module does not export symbol"
                 __tmp276291
                 _%id275424%_))))))
    (define gxc#find-runtime-module-deps
      (lambda (_%ctx275289%_)
        (letrec* ((_%ht275291%_
                   (let () (declare (not safe)) (make-hash-table-eq)))
                  (_%import-set-template275292%_
                   (lambda (_%in275368%_ _%phi275369%_)
                     (let ((_%iphi275371%_
                            (fx+ _%phi275369%_
                                 (##direct-structure-ref
                                  _%in275368%_
                                  '2
                                  gx#import-set::t
                                  '#f)))
                           (_%imports275372%_
                            (##structure-ref
                             (##direct-structure-ref
                              _%in275368%_
                              '1
                              gx#import-set::t
                              '#f)
                             '8
                             gx#module-context::t
                             '#f)))
                       (let _%lp275374%_ ((_%rest275376%_ _%imports275372%_)
                                          (_%r275377%_ '()))
                         (let* ((_%$%rest275378275386%_ _%rest275376%_)
                                (_%$%else275380275394%_
                                 (lambda () _%r275377%_))
                                (_%$%K275382275411%_
                                 (lambda (_%rest275397%_ _%in275398%_)
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-instance-of?
                                          _%in275398%_
                                          'gx#module-context::t))
                                       (if (let ()
                                             (declare (not safe))
                                             (##fxzero? _%iphi275371%_))
                                           (_%lp275374%_
                                            _%rest275397%_
                                            (cons _%in275398%_ _%r275377%_))
                                           (_%lp275374%_
                                            _%rest275397%_
                                            _%r275377%_))
                                       (if (let ()
                                             (declare (not safe))
                                             (##structure-direct-instance-of?
                                              _%in275398%_
                                              'gx#module-import::t))
                                           (let ((_%iphi275402%_
                                                  (fx+ _%phi275369%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##unchecked-structure-ref
                                                          _%in275398%_
                                                          '3
                                                          '#f
                                                          '#f)))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (##fxzero? _%iphi275402%_))
                                                 (_%lp275374%_
                                                  _%rest275397%_
                                                  (cons (##direct-structure-ref
                                                         (let ()
                                                           (declare (not safe))
                                                           (##unchecked-structure-ref
                                                            _%in275398%_
                                                            '1
                                                            '#f
                                                            '#f))
                                                         '1
                                                         gx#module-export::t
                                                         '#f)
                                                        _%r275377%_))
                                                 (_%lp275374%_
                                                  _%rest275397%_
                                                  _%r275377%_)))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (##structure-direct-instance-of?
                                                  _%in275398%_
                                                  'gx#import-set::t))
                                               (let ((_%xphi275405%_
                                                      (fx+ _%iphi275371%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##unchecked-structure-ref
                                                              _%in275398%_
                                                              '2
                                                              '#f
                                                              '#f)))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (##fxzero?
                                                        _%xphi275405%_))
                                                     (_%lp275374%_
                                                      _%rest275397%_
                                                      (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (##unchecked-structure-ref
                                                               _%in275398%_
                                                               '1
                                                               '#f
                                                               '#f))
                                                            _%r275377%_))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (##fxpositive?
                                                            _%xphi275405%_))
                                                         (_%lp275374%_
                                                          _%rest275397%_
                                                          (let ((__tmp276292
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (_%import-set-template275292%_
                          _%in275398%_
                          _%iphi275371%_)))
                    (declare (not safe))
                    (foldl__0 cons _%r275377%_ __tmp276292)))
                 (_%lp275374%_ _%rest275397%_ _%r275377%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%lp275374%_
                                                _%rest275397%_
                                                _%r275377%_)))))))
                           (if (pair? _%$%rest275378275386%_)
                               (let ((_%$%hd275383275414%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%rest275378275386%_)))
                                     (_%$%tl275384275416%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%rest275378275386%_))))
                                 (let* ((_%in275419%_ _%$%hd275383275414%_)
                                        (_%rest275421%_ _%$%tl275384275416%_))
                                   (_%$%K275382275411%_
                                    _%rest275421%_
                                    _%in275419%_)))
                               (_%$%else275380275394%_)))))))
                  (_%find-deps275293%_
                   (lambda (_%rest275301%_ _%deps275302%_)
                     (let* ((_%$%rest275303275311%_ _%rest275301%_)
                            (_%$%else275305275319%_ (lambda () _%deps275302%_))
                            (_%$%K275307275356%_
                             (lambda (_%rest275322%_ _%hd275323%_)
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      _%hd275323%_
                                      'gx#module-context::t))
                                   (let ((_%id275326%_
                                          (let ()
                                            (declare (not safe))
                                            (##unchecked-structure-ref
                                             _%hd275323%_
                                             '1
                                             '#f
                                             '#f)))
                                         (_%imports275327%_
                                          (let ()
                                            (declare (not safe))
                                            (##unchecked-structure-ref
                                             _%hd275323%_
                                             '8
                                             '#f
                                             '#f))))
                                     (if (let ()
                                           (declare (not safe))
                                           (__hash-get
                                            _%ht275291%_
                                            _%id275326%_))
                                         (_%find-deps275293%_
                                          _%rest275322%_
                                          _%deps275302%_)
                                         (let ((_%$e275330%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#core-context-prelude__%
                                                   _%hd275323%_))))
                                           (if _%$e275330%_
                                               (let ((_%xdeps275335%_
                                                      (_%find-deps275293%_
                                                       (cons _%$e275330%_
                                                             _%imports275327%_)
                                                       _%deps275302%_)))
                                                 (let ()
                                                   (declare (not safe))
                                                   (__hash-put!
                                                    _%ht275291%_
                                                    _%id275326%_
                                                    _%hd275323%_))
                                                 (_%find-deps275293%_
                                                  _%rest275322%_
                                                  (cons _%hd275323%_
                                                        _%xdeps275335%_)))
                                               (let ((_%xdeps275338%_
                                                      (_%find-deps275293%_
                                                       _%imports275327%_
                                                       _%deps275302%_)))
                                                 (let ()
                                                   (declare (not safe))
                                                   (__hash-put!
                                                    _%ht275291%_
                                                    _%id275326%_
                                                    _%hd275323%_))
                                                 (_%find-deps275293%_
                                                  _%rest275322%_
                                                  (cons _%hd275323%_
                                                        _%xdeps275338%_)))))))
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-instance-of?
                                          _%hd275323%_
                                          'gx#prelude-context::t))
                                       (let ((_%id275341%_
                                              (let ()
                                                (declare (not safe))
                                                (##unchecked-structure-ref
                                                 _%hd275323%_
                                                 '1
                                                 '#f
                                                 '#f))))
                                         (if (let ()
                                               (declare (not safe))
                                               (__hash-get
                                                _%ht275291%_
                                                _%id275341%_))
                                             (_%find-deps275293%_
                                              _%rest275322%_
                                              _%deps275302%_)
                                             (let ((_%xdeps275345%_
                                                    (_%find-deps275293%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##unchecked-structure-ref
                                                        _%hd275323%_
                                                        '7
                                                        '#f
                                                        '#f))
                                                     _%deps275302%_)))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (__hash-get
                                                      _%ht275291%_
                                                      _%id275341%_))
                                                   (_%find-deps275293%_
                                                    _%rest275322%_
                                                    _%xdeps275345%_)
                                                   (begin
                                                     (let ()
                                                       (declare (not safe))
                                                       (__hash-put!
                                                        _%ht275291%_
                                                        _%id275341%_
                                                        _%hd275323%_))
                                                     (_%find-deps275293%_
                                                      _%rest275322%_
                                                      (cons _%hd275323%_
                                                            _%xdeps275345%_)))))))
                                       (if (let ()
                                             (declare (not safe))
                                             (##structure-direct-instance-of?
                                              _%hd275323%_
                                              'gx#module-import::t))
                                           (if (fxzero? (let ()
                                                          (declare (not safe))
                                                          (##unchecked-structure-ref
                                                           _%hd275323%_
                                                           '3
                                                           '#f
                                                           '#f)))
                                               (_%find-deps275293%_
                                                (cons (let ()
                                                        (declare (not safe))
                                                        (##unchecked-structure-ref
                                                         _%hd275323%_
                                                         '1
                                                         '#f
                                                         '#f))
                                                      _%rest275322%_)
                                                _%deps275302%_)
                                               (_%find-deps275293%_
                                                _%rest275322%_
                                                _%deps275302%_))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (##structure-direct-instance-of?
                                                  _%hd275323%_
                                                  'gx#module-export::t))
                                               (_%find-deps275293%_
                                                (cons (let ()
                                                        (declare (not safe))
                                                        (##unchecked-structure-ref
                                                         _%hd275323%_
                                                         '1
                                                         '#f
                                                         '#f))
                                                      _%rest275322%_)
                                                _%deps275302%_)
                                               (if (let ()
                                                     (declare (not safe))
                                                     (##structure-direct-instance-of?
                                                      _%hd275323%_
                                                      'gx#import-set::t))
                                                   (if (fxzero? (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (##unchecked-structure-ref _%hd275323%_ '2 '#f '#f)))
               (_%find-deps275293%_
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref _%hd275323%_ '1 '#f '#f))
                      _%rest275322%_)
                _%deps275302%_)
               (if (fxpositive?
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-ref _%hd275323%_ '2 '#f '#f)))
                   (let ((_%xdeps275352%_
                          (_%import-set-template275292%_ _%hd275323%_ '0)))
                     (_%find-deps275293%_
                      (let ()
                        (declare (not safe))
                        (foldl__0 cons _%rest275322%_ _%xdeps275352%_))
                      _%deps275302%_))
                   (_%find-deps275293%_ _%rest275322%_ _%deps275302%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (let ()
                                                     (declare (not safe))
                                                     (error '"Unexpected module import"
                                                            _%hd275323%_))))))))))
                       (if (pair? _%$%rest275303275311%_)
                           (let ((_%$%hd275308275359%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%rest275303275311%_)))
                                 (_%$%tl275309275361%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%rest275303275311%_))))
                             (let* ((_%hd275364%_ _%$%hd275308275359%_)
                                    (_%rest275366%_ _%$%tl275309275361%_))
                               (_%$%K275307275356%_
                                _%rest275366%_
                                _%hd275364%_)))
                           (_%$%else275305275319%_))))))
          (let ((__tmp276293
                 (filter gx#expander-context-id
                         (_%find-deps275293%_
                          (let ((_%$e275295%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#core-context-prelude__%
                                    _%ctx275289%_))))
                            (if _%$e275295%_
                                (cons _%$e275295%_
                                      (##structure-ref
                                       _%ctx275289%_
                                       '8
                                       gx#module-context::t
                                       '#f))
                                (##structure-ref
                                 _%ctx275289%_
                                 '8
                                 gx#module-context::t
                                 '#f)))
                          '()))))
            (declare (not safe))
            (##reverse __tmp276293)))))
    (define gxc#find-static-module-file
      (lambda (_%ctx275219%_)
        (let* ((_%context-id275221%_
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of?
                       _%ctx275219%_
                       'gx#module-context::t))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-ref _%ctx275219%_ '1 '#f '#f))
                    (string->symbol _%ctx275219%_)))
               (_%scm275223%_
                (let ((__tmp276294
                       (gxc#static-module-name _%context-id275221%_)))
                  (declare (not safe))
                  (##string-append __tmp276294 '".scm")))
               (_%dirs275225%_ (let () (declare (not safe)) (load-path)))
               (_%dirs275231%_
                (let ((_%user-libpath275227%_
                       (let ()
                         (declare (not safe))
                         (##getenv '"GERBIL_PATH" '#f))))
                  (if _%user-libpath275227%_
                      (let ((_%user-libpath275229%_
                             (path-expand '"lib" _%user-libpath275227%_)))
                        (if (let ()
                              (declare (not safe))
                              (##member _%user-libpath275229%_ _%dirs275225%_))
                            _%dirs275225%_
                            (cons _%user-libpath275229%_ _%dirs275225%_)))
                      _%dirs275225%_)))
               (_%dirs275241%_
                (let ((_%$e275233%_
                       (let ()
                         (declare (not safe))
                         (gxc#current-compile-output-dir))))
                  (if _%$e275233%_
                      (cons _%$e275233%_ _%dirs275231%_)
                      _%dirs275231%_)))
               (_%dirs275247%_
                (let ((__tmp276295
                       (lambda (_%$%g275242275244%_)
                         (path-expand '"static" _%$%g275242275244%_))))
                  (declare (not safe))
                  (##map __tmp276295 _%dirs275241%_))))
          (let _%lp275250%_ ((_%rest275252%_ _%dirs275247%_))
            (let* ((_%$%rest275253275261%_ _%rest275252%_)
                   (_%$%else275255275269%_
                    (lambda ()
                      (let ((__tmp276296
                             (##structure-ref
                              _%ctx275219%_
                              '1
                              gx#expander-context::t
                              '#f)))
                        (declare (not safe))
                        (gxc#raise-compile-error
                         '"cannot find static module"
                         __tmp276296
                         _%scm275223%_))))
                   (_%$%K275257275277%_
                    (lambda (_%rest275272%_ _%dir275273%_)
                      (let ((_%path275275%_
                             (path-expand _%scm275223%_ _%dir275273%_)))
                        (if (let ()
                              (declare (not safe))
                              (##file-exists? _%path275275%_))
                            _%path275275%_
                            (_%lp275250%_ _%rest275272%_))))))
              (if (pair? _%$%rest275253275261%_)
                  (let ((_%$%hd275258275280%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest275253275261%_)))
                        (_%$%tl275259275282%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest275253275261%_))))
                    (let* ((_%dir275285%_ _%$%hd275258275280%_)
                           (_%rest275287%_ _%$%tl275259275282%_))
                      (_%$%K275257275277%_ _%rest275287%_ _%dir275285%_)))
                  (_%$%else275255275269%_)))))))
    (define gxc#file-empty?
      (lambda (_%path275217%_)
        (zero? (let ((__tmp276297 (file-info _%path275217%_ '#t)))
                 (declare (not safe))
                 (##file-info-size __tmp276297)))))
    (define gxc#compile-top-module
      (lambda (_%ctx275208%_)
        (let ((__tmp276298
               (lambda ()
                 (let ((__tmp276299
                        (lambda ()
                          (let ((__tmp276300
                                 (lambda ()
                                   (let ((__tmp276302
                                          (lambda ()
                                            (let ((__tmp276304
                                                   (lambda ()
                                                     (let ((__tmp276306
                                                            (lambda ()
                                                              (let ((__tmp276307
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (##structure-ref
                              _%ctx275208%_
                              '1
                              gx#expander-context::t
                              '#f)))
                        (declare (not safe))
                        (gxc#verbose '"compile " __tmp276307))
                      (if (let ()
                            (declare (not safe))
                            (gxc#current-compile-optimize))
                          (let ((__tmp276308
                                 (lambda ()
                                   (let ()
                                     (declare (not safe))
                                     (gxc#optimize! _%ctx275208%_)))))
                            (declare (not safe))
                            (__with-lock gxc#+driver-mutex+ __tmp276308))
                          '#!void)
                      (gxc#collect-bindings _%ctx275208%_)
                      (gxc#compile-runtime-code _%ctx275208%_)
                      (gxc#compile-meta-code _%ctx275208%_)
                      (if (and (let ()
                                 (declare (not safe))
                                 (gxc#current-compile-optimize))
                               (let ()
                                 (declare (not safe))
                                 (gxc#current-compile-generate-ssxi)))
                          (gxc#compile-ssxi-code _%ctx275208%_)
                          '#!void)))
                   (__tmp276305
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
                       absent-value))))
               (declare (not safe))
               (call-with-parameters__1
                __tmp276306
                gxc#current-compile-runtime-names
                __tmp276305))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (__tmp276303
                                                   (let ()
                                                     (declare (not safe))
                                                     (make-hash-table-eq))))
                                              (declare (not safe))
                                              (call-with-parameters__1
                                               __tmp276304
                                               gxc#current-compile-runtime-sections
                                               __tmp276303))))
                                         (__tmp276301
                                          (let ((__obj276197
                                                 (let ()
                                                   (declare (not safe))
                                                   (##structure
                                                    gxc#symbol-table::t
                                                    '#f
                                                    '#f))))
                                            (let ()
                                              (declare (not safe))
                                              (gxc#symbol-table:::init!
                                               __obj276197))
                                            __obj276197)))
                                     (declare (not safe))
                                     (call-with-parameters__1
                                      __tmp276302
                                      gxc#current-compile-symbol-table
                                      __tmp276301)))))
                            (declare (not safe))
                            (call-with-parameters__1
                             __tmp276300
                             gx#current-expander-marks
                             '())))))
                   (declare (not safe))
                   (call-with-parameters__1
                    __tmp276299
                    gx#current-expander-phi
                    '0)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp276298
           gx#current-expander-context
           _%ctx275208%_))))
    (define gxc#collect-bindings
      (lambda (_%ctx275206%_)
        (let ((__tmp276309
               (##structure-ref _%ctx275206%_ '11 gx#module-context::t '#f)))
          (declare (not safe))
          (gxc#apply-collect-bindings __tmp276309))))
    (define gxc#compile-runtime-code
      (lambda (_%ctx275151%_)
        (letrec ((_%compile1275153%_
                  (lambda (_%ctx275195%_)
                    (let* ((_%code275197%_
                            (##structure-ref
                             _%ctx275195%_
                             '11
                             gx#module-context::t
                             '#f))
                           (_%rtm275201%_
                            (let ((_%idstr275199%_
                                   (let ((__tmp276310
                                          (##structure-ref
                                           _%ctx275195%_
                                           '1
                                           gx#expander-context::t
                                           '#f)))
                                     (declare (not safe))
                                     (gxc#module-id->path-string
                                      __tmp276310))))
                              (declare (not safe))
                              (##string-append _%idstr275199%_ '"~0")))
                           (_%rtc?275203%_
                            (let ()
                              (declare (not safe))
                              (gxc#apply-find-runtime-code _%code275197%_))))
                      (if _%rtc?275203%_
                          (let ((__tmp276311
                                 (let ()
                                   (declare (not safe))
                                   (gxc#current-compile-runtime-sections))))
                            (declare (not safe))
                            (hash-put!
                             __tmp276311
                             _%ctx275195%_
                             _%rtm275201%_))
                          '#!void)
                      (_%generate-runtime-code275155%_
                       _%ctx275195%_
                       _%code275197%_
                       (if _%rtc?275203%_ _%rtm275201%_ '#f)))))
                 (_%context-timestamp275154%_
                  (lambda (_%ctx275193%_)
                    (let ((__tmp276312
                           (let ((__tmp276313
                                  (symbol->string
                                   (##structure-ref
                                    _%ctx275193%_
                                    '1
                                    gx#expander-context::t
                                    '#f))))
                             (declare (not safe))
                             (##string-append __tmp276313 '"::timestamp"))))
                      (declare (not safe))
                      (##string->symbol __tmp276312))))
                 (_%generate-runtime-code275155%_
                  (lambda (_%ctx275162%_ _%code275163%_ _%rtm275164%_)
                    (let* ((_%runtime-code?275166%_ (if _%rtm275164%_ '#t '#f))
                           (_%lifts275168%_ (box '()))
                           (_%runtime-code275174%_
                            (if _%runtime-code?275166%_
                                (let ((__tmp276314
                                       (lambda ()
                                         (let ((__tmp276315
                                                (lambda ()
                                                  (let ((__tmp276316
                                                         (lambda ()
                                                           (let ((__tmp276318
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (lambda ()
                            (let ()
                              (declare (not safe))
                              (gxc#apply-generate-runtime _%code275163%_))))
                         (__tmp276317
                          (let () (declare (not safe)) (make-hash-table-eq))))
                     (declare (not safe))
                     (call-with-parameters__1
                      __tmp276318
                      gxc#current-compile-marks
                      __tmp276317)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (call-with-parameters__1
                                                     __tmp276316
                                                     gxc#current-compile-lift
                                                     _%lifts275168%_)))))
                                           (declare (not safe))
                                           (call-with-parameters__1
                                            __tmp276315
                                            gx#current-expander-phi
                                            '0)))))
                                  (declare (not safe))
                                  (call-with-parameters__1
                                   __tmp276314
                                   gx#current-expander-context
                                   _%ctx275162%_))
                                '#f))
                           (_%runtime-code275176%_
                            (if _%runtime-code?275166%_
                                (if (null? (unbox _%lifts275168%_))
                                    _%runtime-code275174%_
                                    (cons 'begin
                                          (let ((__tmp276320
                                                 (reverse (unbox _%lifts275168%_)))
                                                (__tmp276319
                                                 (cons _%runtime-code275174%_
                                                       '())))
                                            (declare (not safe))
                                            (##append
                                             __tmp276320
                                             __tmp276319))))
                                '#f))
                           (_%runtime-code275178%_
                            (if _%runtime-code?275166%_
                                (cons 'begin
                                      (cons (list 'define
                                                  (_%context-timestamp275154%_
                                                   _%ctx275162%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#current-compile-timestamp)))
                                            (cons _%runtime-code275176%_ '())))
                                '#f))
                           (_%loader-code275181%_
                            (let ((__tmp276321
                                   (lambda ()
                                     (let ()
                                       (declare (not safe))
                                       (gxc#apply-generate-loader
                                        _%code275163%_)))))
                              (declare (not safe))
                              (call-with-parameters__1
                               __tmp276321
                               gx#current-expander-context
                               _%ctx275162%_)))
                           (_%loader-code275183%_
                            (cons 'begin
                                  (cons _%loader-code275181%_
                                        (cons (if _%runtime-code?275166%_
                                                  (cons 'load-module
                                                        (cons _%rtm275164%_
                                                              '()))
                                                  '(begin))
                                              '()))))
                           (_%scm0275185%_
                            (gxc#compile-output-file _%ctx275162%_ '0 '".scm"))
                           (_%scmrt275187%_
                            (gxc#compile-output-file
                             _%ctx275162%_
                             '#f
                             '".scm"))
                           (_%scms275189%_
                            (gxc#compile-static-output-file _%ctx275162%_)))
                      (if _%runtime-code?275166%_
                          (gxc#compile-scm-file__0
                           _%scm0275185%_
                           _%runtime-code275178%_)
                          '#!void)
                      (let ((__tmp276322
                             (lambda ()
                               (gxc#compile-scm-file__0
                                _%scmrt275187%_
                                _%loader-code275183%_))))
                        (declare (not safe))
                        (call-with-parameters__1
                         __tmp276322
                         gxc#current-compile-gsc-options
                         '#f))
                      (if (let ()
                            (declare (not safe))
                            (##file-exists? _%scms275189%_))
                          (let ()
                            (declare (not safe))
                            (##delete-file _%scms275189%_))
                          '#!void)
                      (if _%runtime-code?275166%_
                          (let ()
                            (declare (not safe))
                            (##copy-file _%scm0275185%_ _%scms275189%_))
                          (let ()
                            (declare (not safe))
                            (##call-with-output-file _%scms275189%_ void)))))))
          (let* ((_%all-modules275157%_
                  (cons _%ctx275151%_ (gxc#lift-nested-modules _%ctx275151%_)))
                 (__tmp276323
                  (lambda (_%ctx275159%_)
                    (let ((__tmp276324
                           (lambda () (_%compile1275153%_ _%ctx275159%_))))
                      (declare (not safe))
                      (call-with-parameters__1
                       __tmp276324
                       gxc#current-compile-decls
                       '())))))
            (declare (not safe))
            (##for-each __tmp276323 _%all-modules275157%_)))))
    (define gxc#compile-meta-code
      (lambda (_%ctx275050%_)
        (letrec ((_%compile-ssi275052%_
                  (lambda (_%code275119%_)
                    (let* ((_%path275121%_
                            (gxc#compile-output-file
                             _%ctx275050%_
                             '#f
                             '".ssi"))
                           (_%prelude275133%_
                            (let* ((_%super275123%_
                                    (##structure-ref
                                     _%ctx275050%_
                                     '3
                                     gx#phi-context::t
                                     '#f))
                                   (_%$e275125%_
                                    (##structure-ref
                                     _%super275123%_
                                     '1
                                     gx#expander-context::t
                                     '#f)))
                              (if _%$e275125%_
                                  (let ()
                                    (declare (not safe))
                                    (make-symbol__1 '":" _%$e275125%_))
                                  ':<root>)))
                           (_%ns275135%_
                            (##structure-ref
                             _%ctx275050%_
                             '6
                             gx#module-context::t
                             '#f))
                           (_%idstr275137%_
                            (symbol->string
                             (##structure-ref
                              _%ctx275050%_
                              '1
                              gx#expander-context::t
                              '#f)))
                           (_%pkg275145%_
                            (let ((_%$e275139%_
                                   (let ()
                                     (declare (not safe))
                                     (string-rindex__0 _%idstr275137%_ '#\/))))
                              (if _%$e275139%_
                                  (let ((__tmp276325
                                         (substring
                                          _%idstr275137%_
                                          '0
                                          _%$e275139%_)))
                                    (declare (not safe))
                                    (##string->symbol __tmp276325))
                                  '#f)))
                           (_%rt275147%_
                            (let ((__tmp276326
                                   (let ()
                                     (declare (not safe))
                                     (gxc#current-compile-runtime-sections))))
                              (declare (not safe))
                              (hash-get __tmp276326 _%ctx275050%_))))
                      (let ()
                        (declare (not safe))
                        (gxc#verbose '"compile " _%path275121%_))
                      (gxc#with-output-to-scheme-file
                       _%path275121%_
                       (lambda ()
                         (let ()
                           (declare (not safe))
                           (displayln '"prelude:" '" " _%prelude275133%_))
                         (if _%pkg275145%_
                             (let ()
                               (declare (not safe))
                               (displayln '"package:" '" " _%pkg275145%_))
                             '#!void)
                         (let ()
                           (declare (not safe))
                           (displayln '"namespace:" '" " _%ns275135%_))
                         (newline)
                         (pretty-print _%code275119%_)
                         (if _%rt275147%_
                             (pretty-print
                              (cons '%#call
                                    (cons (cons '%#ref (cons 'load-module '()))
                                          (cons (cons '%#quote
                                                      (cons _%rt275147%_ '()))
                                                '()))))
                             '#!void))))))
                 (_%compile-phi275053%_
                  (lambda (_%part275058%_)
                    (let* ((_%$%part275059275072%_ _%part275058%_)
                           (_%$%E275061275076%_
                            (lambda ()
                              (let ()
                                (declare (not safe))
                                (error '"No clause matching"
                                       _%$%part275059275072%_
                                       '([phi-ctx phi n code])))
                              '#!void))
                           (_%$%K275062275088%_
                            (lambda (_%code275079%_
                                     _%n275080%_
                                     _%phi275081%_
                                     _%phi-ctx275082%_)
                              (let ((_%code275086%_
                                     (let ((__tmp276327
                                            (lambda ()
                                              (let ((__tmp276328
                                                     (lambda ()
                                                       (gxc#generate-runtime-phi
                                                        _%code275079%_))))
                                                (declare (not safe))
                                                (call-with-parameters__1
                                                 __tmp276328
                                                 gx#current-expander-phi
                                                 _%phi275081%_)))))
                                       (declare (not safe))
                                       (call-with-parameters__1
                                        __tmp276327
                                        gx#current-expander-context
                                        _%phi-ctx275082%_))))
                                (gxc#compile-scm-file__%
                                 (gxc#compile-output-file
                                  _%ctx275050%_
                                  _%n275080%_
                                  '".scm")
                                 _%code275086%_
                                 '#t)))))
                      (if (pair? _%$%part275059275072%_)
                          (let ((_%$%hd275063275091%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%part275059275072%_)))
                                (_%$%tl275064275093%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%part275059275072%_))))
                            (let ((_%phi-ctx275096%_ _%$%hd275063275091%_))
                              (if (pair? _%$%tl275064275093%_)
                                  (let ((_%$%hd275065275098%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%tl275064275093%_)))
                                        (_%$%tl275066275100%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%tl275064275093%_))))
                                    (let ((_%phi275103%_ _%$%hd275065275098%_))
                                      (if (pair? _%$%tl275066275100%_)
                                          (let ((_%$%hd275067275105%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%tl275066275100%_)))
                                                (_%$%tl275068275107%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%tl275066275100%_))))
                                            (let ((_%n275110%_
                                                   _%$%hd275067275105%_))
                                              (if (pair? _%$%tl275068275107%_)
                                                  (let ((_%$%hd275069275112%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%tl275068275107%_)))
                                                        (_%$%tl275070275114%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%tl275068275107%_))))
                                                    (let ((_%code275117%_
                                                           _%$%hd275069275112%_))
                                                      (if (null? _%$%tl275070275114%_)
                                                          (_%$%K275062275088%_
                                                           _%code275117%_
                                                           _%n275110%_
                                                           _%phi275103%_
                                                           _%phi-ctx275096%_)
                                                          (_%$%E275061275076%_))))
                                                  (_%$%E275061275076%_))))
                                          (_%$%E275061275076%_))))
                                  (_%$%E275061275076%_))))
                          (_%$%E275061275076%_))))))
          (let ((_g276329_ (gxc#generate-meta-code _%ctx275050%_)))
            (begin
              (let ((_g276330_
                     (let ()
                       (declare (not safe))
                       (if (##values? _g276329_)
                           (##values-length _g276329_)
                           1))))
                (if (not (let () (declare (not safe)) (##fx= _g276330_ 2)))
                    (error "Context expects 2 values" _g276330_)))
              (let ((_%ssi-code275055%_
                     (let () (declare (not safe)) (##values-ref _g276329_ 0)))
                    (_%phi-code275056%_
                     (let () (declare (not safe)) (##values-ref _g276329_ 1))))
                (begin
                  (_%compile-ssi275052%_ _%ssi-code275055%_)
                  (for-each _%compile-phi275053%_ _%phi-code275056%_))))))))
    (define gxc#compile-ssxi-code
      (lambda (_%ctx275032%_)
        (let* ((_%path275034%_
                (gxc#compile-output-file _%ctx275032%_ '#f '".ssxi.ss"))
               (_%code275036%_
                (let ((__tmp276331
                       (##structure-ref
                        _%ctx275032%_
                        '11
                        gx#module-context::t
                        '#f)))
                  (declare (not safe))
                  (gxc#apply-generate-ssxi __tmp276331)))
               (_%idstr275038%_
                (symbol->string
                 (##structure-ref
                  _%ctx275032%_
                  '1
                  gx#expander-context::t
                  '#f)))
               (_%pkg275046%_
                (let ((_%$e275040%_
                       (let ()
                         (declare (not safe))
                         (string-rindex__0 _%idstr275038%_ '#\/))))
                  (if _%$e275040%_
                      (let ((__tmp276332
                             (substring _%idstr275038%_ '0 _%$e275040%_)))
                        (declare (not safe))
                        (##string->symbol __tmp276332))
                      '#f))))
          (let ()
            (declare (not safe))
            (gxc#verbose '"compile " _%path275034%_))
          (gxc#with-output-to-scheme-file
           _%path275034%_
           (lambda ()
             (let ()
               (declare (not safe))
               (displayln '"prelude: :gerbil/compiler/ssxi"))
             (if _%pkg275046%_
                 (let ()
                   (declare (not safe))
                   (displayln '"package: " _%pkg275046%_))
                 '#!void)
             (newline)
             (pretty-print _%code275036%_))))))
    (define gxc#generate-meta-code
      (lambda (_%ctx275025%_)
        (let* ((_%state275027%_
                (let ((__obj276198
                       (let ()
                         (declare (not safe))
                         (##structure gxc#meta-state::t '#f '#f '#f '#f))))
                  (let ()
                    (declare (not safe))
                    (gxc#meta-state:::init! __obj276198 _%ctx275025%_))
                  __obj276198))
               (_%ssi-code275029%_
                (let ((__tmp276333
                       (##structure-ref
                        _%ctx275025%_
                        '11
                        gx#module-context::t
                        '#f)))
                  (declare (not safe))
                  (gxc#apply-generate-meta__%
                   '#f
                   _%state275027%_
                   __tmp276333))))
          (values _%ssi-code275029%_
                  (let ()
                    (declare (not safe))
                    (gxc#meta-state-end! _%state275027%_))))))
    (define gxc#generate-runtime-phi
      (lambda (_%stx275017%_)
        (let* ((_%lifts275019%_ (box '()))
               (__tmp276334
                (lambda ()
                  (let ((__tmp276336
                         (lambda ()
                           (let ((_%code275023%_
                                  (let ()
                                    (declare (not safe))
                                    (gxc#apply-generate-runtime-phi
                                     _%stx275017%_))))
                             (if (null? (unbox _%lifts275019%_))
                                 _%code275023%_
                                 (cons 'begin
                                       (let ((__tmp276338
                                              (reverse (unbox _%lifts275019%_)))
                                             (__tmp276337
                                              (cons _%code275023%_ '())))
                                         (declare (not safe))
                                         (##append
                                          __tmp276338
                                          __tmp276337)))))))
                        (__tmp276335
                         (let () (declare (not safe)) (make-hash-table-eq))))
                    (declare (not safe))
                    (call-with-parameters__1
                     __tmp276336
                     gxc#current-compile-marks
                     __tmp276335)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp276334
           gxc#current-compile-lift
           _%lifts275019%_))))
    (define gxc#lift-nested-modules
      (lambda (_%ctx275013%_)
        (let ((_%modules275015%_ (box '())))
          (let ((__tmp276339
                 (##structure-ref _%ctx275013%_ '11 gx#module-context::t '#f)))
            (declare (not safe))
            (gxc#apply-lift-modules__% '#f _%modules275015%_ __tmp276339))
          (reverse (unbox _%modules275015%_)))))
    (define gxc#compile-scm-file__%
      (lambda (_%path274993%_ _%code274994%_ _%phi?274995%_)
        (let () (declare (not safe)) (gxc#verbose '"compile " _%path274993%_))
        (gxc#with-output-to-scheme-file
         _%path274993%_
         (lambda ()
           (pretty-print
            (cons 'declare
                  (cons '(block)
                        (cons '(standard-bindings)
                              (cons '(extended-bindings)
                                    (if _%phi?274995%_
                                        '((inlining-limit 200))
                                        '()))))))
           (pretty-print _%code274994%_)))
        (if (let () (declare (not safe)) (gxc#current-compile-invoke-gsc))
            (let ((_%compile-it274999%_
                   (lambda ()
                     (gxc#gsc-compile-file _%path274993%_ _%phi?274995%_))))
              (if (let () (declare (not safe)) (gxc#current-compile-parallel))
                  (let ((__tmp276340 (list 'compile-file _%path274993%_)))
                    (declare (not safe))
                    (gxc#add-compile-job!__% _%compile-it274999%_ __tmp276340))
                  (_%compile-it274999%_)))
            '#!void)))
    (define gxc#compile-scm-file__0
      (lambda (_%path275004%_ _%code275005%_)
        (let ((_%phi?275007%_ '#f))
          (gxc#compile-scm-file__%
           _%path275004%_
           _%code275005%_
           _%phi?275007%_))))
    (define gxc#compile-scm-file
      (lambda _g276341_
        (let ((_g276342_ (let () (declare (not safe)) (##length _g276341_))))
          (cond ((let () (declare (not safe)) (##fx= _g276342_ 2))
                 (apply gxc#compile-scm-file__0 _g276341_))
                ((let () (declare (not safe)) (##fx= _g276342_ 3))
                 (apply gxc#compile-scm-file__% _g276341_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#compile-scm-file
                  _g276341_))))))
    (define gxc#gsc-link-options__%
      (lambda (_%phi?274894%_)
        (let _%lp274896%_ ((_%rest274898%_
                            (let ()
                              (declare (not safe))
                              (gxc#current-compile-gsc-options)))
                           (_%opts274899%_ '()))
          (let* ((_%$%rest274900274920%_ _%rest274898%_)
                 (_%$%else274904274928%_
                  (lambda ()
                    (if (let ()
                          (declare (not safe))
                          (gxc#current-compile-debug))
                        (cons '"-debug-source"
                              (cons '"-track-scheme" (reverse _%opts274899%_)))
                        (reverse _%opts274899%_)))))
            (let ((_%$%K274914274971%_
                   (lambda (_%rest274969%_)
                     (_%lp274896%_ _%rest274969%_ _%opts274899%_)))
                  (_%$%K274909274953%_
                   (lambda (_%rest274951%_)
                     (_%lp274896%_ _%rest274951%_ _%opts274899%_)))
                  (_%$%K274906274935%_
                   (lambda (_%rest274932%_ _%opt274933%_)
                     (_%lp274896%_
                      _%rest274932%_
                      (cons _%opt274933%_ _%opts274899%_)))))
              (if (pair? _%$%rest274900274920%_)
                  (let ((_%$%tl274916274976%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest274900274920%_)))
                        (_%$%hd274915274974%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest274900274920%_))))
                    (if (equal? _%$%hd274915274974%_ '"-cc-options")
                        (if (pair? _%$%tl274916274976%_)
                            (let* ((_%$%tl274918274979%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%tl274916274976%_)))
                                   (_%rest274982%_ _%$%tl274918274979%_))
                              (_%$%K274914274971%_ _%rest274982%_))
                            (let ((_%opt274943%_ _%$%hd274915274974%_)
                                  (_%rest274945%_ _%$%tl274916274976%_))
                              (_%$%K274906274935%_
                               _%rest274945%_
                               _%opt274943%_)))
                        (if (equal? _%$%hd274915274974%_ '"-ld-options")
                            (if (pair? _%$%tl274916274976%_)
                                (let* ((_%$%tl274913274961%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%tl274916274976%_)))
                                       (_%rest274964%_ _%$%tl274913274961%_))
                                  (_%$%K274909274953%_ _%rest274964%_))
                                (let ((_%opt274943%_ _%$%hd274915274974%_)
                                      (_%rest274945%_ _%$%tl274916274976%_))
                                  (_%$%K274906274935%_
                                   _%rest274945%_
                                   _%opt274943%_)))
                            (let ((_%opt274943%_ _%$%hd274915274974%_)
                                  (_%rest274945%_ _%$%tl274916274976%_))
                              (_%$%K274906274935%_
                               _%rest274945%_
                               _%opt274943%_)))))
                  (_%$%else274904274928%_)))))))
    (define gxc#gsc-link-options__0
      (lambda ()
        (let ((_%phi?274988%_ '#f)) (gxc#gsc-link-options__% _%phi?274988%_))))
    (define gxc#gsc-link-options
      (lambda _g276343_
        (let ((_g276344_ (let () (declare (not safe)) (##length _g276343_))))
          (cond ((let () (declare (not safe)) (##fx= _g276344_ 0))
                 (apply gxc#gsc-link-options__0 _g276343_))
                ((let () (declare (not safe)) (##fx= _g276344_ 1))
                 (apply gxc#gsc-link-options__% _g276343_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#gsc-link-options
                  _g276343_))))))
    (define gxc#gsc-cc-options__%__%
      (lambda (_%@@keywords274744%_ _%$%static?274740274745%_ _%phi?274746%_)
        (let ((_%static?274748%_
               (if (eq? _%$%static?274740274745%_ absent-value)
                   '#f
                   _%$%static?274740274745%_)))
          (if _%phi?274746%_
              (if (let () (declare (not safe)) (gxc#current-compile-debug))
                  (cons '"-cc-options" (cons '"-g" '()))
                  '())
              (let _%lp274750%_ ((_%rest274752%_
                                  (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-gsc-options)))
                                 (_%opts274753%_ '()))
                (let* ((_%$%rest274754274780%_ _%rest274752%_)
                       (_%$%else274759274788%_
                        (lambda ()
                          (if (let ()
                                (declare (not safe))
                                (gxc#current-compile-debug))
                              (cons '"-cc-options"
                                    (cons '"-g" (reverse! _%opts274753%_)))
                              (reverse! _%opts274753%_)))))
                  (let ((_%$%K274774274851%_
                         (lambda (_%rest274848%_ _%opt274849%_)
                           (if _%static?274748%_
                               (_%lp274750%_
                                _%rest274848%_
                                (cons _%opt274849%_
                                      (cons '"-cc-options" _%opts274753%_)))
                               (_%lp274750%_ _%rest274848%_ _%opts274753%_))))
                        (_%$%K274769274828%_
                         (lambda (_%rest274825%_ _%opt274826%_)
                           (_%lp274750%_
                            _%rest274825%_
                            (cons _%opt274826%_
                                  (cons '"-cc-options" _%opts274753%_)))))
                        (_%$%K274764274808%_
                         (lambda (_%rest274806%_)
                           (_%lp274750%_ _%rest274806%_ _%opts274753%_)))
                        (_%$%K274761274794%_
                         (lambda (_%rest274792%_)
                           (_%lp274750%_ _%rest274792%_ _%opts274753%_))))
                    (if (pair? _%$%rest274754274780%_)
                        (let ((_%$%tl274776274856%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%rest274754274780%_)))
                              (_%$%hd274775274854%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%rest274754274780%_))))
                          (if (equal? _%$%hd274775274854%_ '"-cc-options")
                              (if (pair? _%$%tl274776274856%_)
                                  (let ((_%$%tl274778274861%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%tl274776274856%_)))
                                        (_%$%hd274777274859%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%tl274776274856%_))))
                                    (if (equal? _%$%hd274777274859%_
                                                '"-Bstatic")
                                        (let ((_%opt274864%_
                                               _%$%hd274777274859%_)
                                              (_%rest274866%_
                                               _%$%tl274778274861%_))
                                          (_%$%K274774274851%_
                                           _%rest274866%_
                                           _%opt274864%_))
                                        (let ((_%opt274841%_
                                               _%$%hd274777274859%_)
                                              (_%rest274843%_
                                               _%$%tl274778274861%_))
                                          (_%$%K274769274828%_
                                           _%rest274843%_
                                           _%opt274841%_))))
                                  (let ((_%rest274800%_ _%$%tl274776274856%_))
                                    (_%$%K274761274794%_ _%rest274800%_)))
                              (if (equal? _%$%hd274775274854%_ '"-ld-options")
                                  (if (pair? _%$%tl274776274856%_)
                                      (let* ((_%$%tl274768274816%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%tl274776274856%_)))
                                             (_%rest274819%_
                                              _%$%tl274768274816%_))
                                        (_%$%K274764274808%_ _%rest274819%_))
                                      (let ((_%rest274800%_
                                             _%$%tl274776274856%_))
                                        (_%$%K274761274794%_ _%rest274800%_)))
                                  (let ((_%rest274800%_ _%$%tl274776274856%_))
                                    (_%$%K274761274794%_ _%rest274800%_)))))
                        (_%$%else274759274788%_)))))))))
    (define gxc#gsc-cc-options__%__0
      (lambda (_%@@keywords274871%_ _%$%static?274740274872%_)
        (let ((_%phi?274874%_ '#f))
          (gxc#gsc-cc-options__%__%
           _%@@keywords274871%_
           _%$%static?274740274872%_
           _%phi?274874%_))))
    (define gxc#gsc-cc-options__%
      (lambda _g276345_
        (let ((_g276346_ (let () (declare (not safe)) (##length _g276345_))))
          (cond ((let () (declare (not safe)) (##fx= _g276346_ 2))
                 (apply gxc#gsc-cc-options__%__0 _g276345_))
                ((let () (declare (not safe)) (##fx= _g276346_ 3))
                 (apply gxc#gsc-cc-options__%__% _g276345_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#gsc-cc-options__%
                  _g276345_))))))
    (define gxc#gsc-cc-options__@
      (lambda (_%@@keywords274883%_ . _%args274884%_)
        (apply gxc#gsc-cc-options__%
               _%@@keywords274883%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords274883%_
                  'static:
                  absent-value))
               _%args274884%_)))
    (define gxc#gsc-cc-options
      (lambda _%$%args274741274890%_
        (apply keyword-dispatch
               '#(static:)
               gxc#gsc-cc-options__@
               _%$%args274741274890%_)))
    (define gxc#gsc-ld-options__%__%
      (lambda (_%@@keywords274590%_ _%$%static?274586274591%_ _%phi?274592%_)
        (let ((_%static?274594%_
               (if (eq? _%$%static?274586274591%_ absent-value)
                   '#f
                   _%$%static?274586274591%_)))
          (if _%phi?274592%_
              '()
              (let _%lp274596%_ ((_%rest274598%_
                                  (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-gsc-options)))
                                 (_%opts274599%_ '()))
                (let* ((_%$%rest274600274626%_ _%rest274598%_)
                       (_%$%else274605274634%_
                        (lambda () (reverse! _%opts274599%_))))
                  (let ((_%$%K274620274697%_
                         (lambda (_%rest274694%_ _%opt274695%_)
                           (if _%static?274594%_
                               (_%lp274596%_
                                _%rest274694%_
                                (cons _%opt274695%_
                                      (cons '"-ld-options" _%opts274599%_)))
                               (_%lp274596%_ _%rest274694%_ _%opts274599%_))))
                        (_%$%K274615274674%_
                         (lambda (_%rest274671%_ _%opt274672%_)
                           (_%lp274596%_
                            _%rest274671%_
                            (cons _%opt274672%_
                                  (cons '"-ld-options" _%opts274599%_)))))
                        (_%$%K274610274654%_
                         (lambda (_%rest274652%_)
                           (_%lp274596%_ _%rest274652%_ _%opts274599%_)))
                        (_%$%K274607274640%_
                         (lambda (_%rest274638%_)
                           (_%lp274596%_ _%rest274638%_ _%opts274599%_))))
                    (if (pair? _%$%rest274600274626%_)
                        (let ((_%$%tl274622274702%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%rest274600274626%_)))
                              (_%$%hd274621274700%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%rest274600274626%_))))
                          (if (equal? _%$%hd274621274700%_ '"-ld-options")
                              (if (pair? _%$%tl274622274702%_)
                                  (let ((_%$%tl274624274707%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%tl274622274702%_)))
                                        (_%$%hd274623274705%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%tl274622274702%_))))
                                    (if (equal? _%$%hd274623274705%_
                                                '"-static")
                                        (let ((_%opt274710%_
                                               _%$%hd274623274705%_)
                                              (_%rest274712%_
                                               _%$%tl274624274707%_))
                                          (_%$%K274620274697%_
                                           _%rest274712%_
                                           _%opt274710%_))
                                        (let ((_%opt274687%_
                                               _%$%hd274623274705%_)
                                              (_%rest274689%_
                                               _%$%tl274624274707%_))
                                          (_%$%K274615274674%_
                                           _%rest274689%_
                                           _%opt274687%_))))
                                  (let ((_%rest274646%_ _%$%tl274622274702%_))
                                    (_%$%K274607274640%_ _%rest274646%_)))
                              (if (equal? _%$%hd274621274700%_ '"-cc-options")
                                  (if (pair? _%$%tl274622274702%_)
                                      (let* ((_%$%tl274614274662%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%tl274622274702%_)))
                                             (_%rest274665%_
                                              _%$%tl274614274662%_))
                                        (_%$%K274610274654%_ _%rest274665%_))
                                      (let ((_%rest274646%_
                                             _%$%tl274622274702%_))
                                        (_%$%K274607274640%_ _%rest274646%_)))
                                  (let ((_%rest274646%_ _%$%tl274622274702%_))
                                    (_%$%K274607274640%_ _%rest274646%_)))))
                        (_%$%else274605274634%_)))))))))
    (define gxc#gsc-ld-options__%__0
      (lambda (_%@@keywords274717%_ _%$%static?274586274718%_)
        (let ((_%phi?274720%_ '#f))
          (gxc#gsc-ld-options__%__%
           _%@@keywords274717%_
           _%$%static?274586274718%_
           _%phi?274720%_))))
    (define gxc#gsc-ld-options__%
      (lambda _g276347_
        (let ((_g276348_ (let () (declare (not safe)) (##length _g276347_))))
          (cond ((let () (declare (not safe)) (##fx= _g276348_ 2))
                 (apply gxc#gsc-ld-options__%__0 _g276347_))
                ((let () (declare (not safe)) (##fx= _g276348_ 3))
                 (apply gxc#gsc-ld-options__%__% _g276347_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#gsc-ld-options__%
                  _g276347_))))))
    (define gxc#gsc-ld-options__@
      (lambda (_%@@keywords274729%_ . _%args274730%_)
        (apply gxc#gsc-ld-options__%
               _%@@keywords274729%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords274729%_
                  'static:
                  absent-value))
               _%args274730%_)))
    (define gxc#gsc-ld-options
      (lambda _%$%args274587274736%_
        (apply keyword-dispatch
               '#(static:)
               gxc#gsc-ld-options__@
               _%$%args274587274736%_)))
    (define gxc#gsc-static-include-options
      (lambda (_%staticdir274581%_)
        (let ((_%user-staticdir274583%_
               (path-expand
                (path-expand
                 '"lib/static"
                 (let () (declare (not safe)) (gerbil-path))))))
          (cons '"-cc-options"
                (cons (string-append
                       '"-I "
                       _%staticdir274581%_
                       '" -I "
                       _%user-staticdir274583%_)
                      '())))))
    (define gxc#gcc-ld-options
      (lambda ()
        (let _%lp274493%_ ((_%rest274495%_
                            (let ()
                              (declare (not safe))
                              (gxc#current-compile-gsc-options)))
                           (_%opts274496%_ '()))
          (let* ((_%$%rest274497274517%_ _%rest274495%_)
                 (_%$%else274501274525%_ (lambda () _%opts274496%_)))
            (let ((_%$%K274511274568%_
                   (lambda (_%rest274566%_)
                     (_%lp274493%_ _%rest274566%_ _%opts274496%_)))
                  (_%$%K274506274546%_
                   (lambda (_%rest274543%_ _%opt274544%_)
                     (_%lp274493%_
                      _%rest274543%_
                      (let ((__tmp276349
                             (let ((__tmp276350
                                    (let ()
                                      (declare (not safe))
                                      (string-split _%opt274544%_ '#\space))))
                               (declare (not safe))
                               (##filter gxc#not-string-empty? __tmp276350))))
                        (declare (not safe))
                        (##append _%opts274496%_ __tmp276349)))))
                  (_%$%K274503274531%_
                   (lambda (_%rest274529%_)
                     (_%lp274493%_ _%rest274529%_ _%opts274496%_))))
              (if (pair? _%$%rest274497274517%_)
                  (let ((_%$%tl274513274573%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest274497274517%_)))
                        (_%$%hd274512274571%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest274497274517%_))))
                    (if (equal? _%$%hd274512274571%_ '"-cc-options")
                        (if (pair? _%$%tl274513274573%_)
                            (let* ((_%$%tl274515274576%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%tl274513274573%_)))
                                   (_%rest274579%_ _%$%tl274515274576%_))
                              (_%$%K274511274568%_ _%rest274579%_))
                            (let ((_%rest274537%_ _%$%tl274513274573%_))
                              (_%$%K274503274531%_ _%rest274537%_)))
                        (if (equal? _%$%hd274512274571%_ '"-ld-options")
                            (if (pair? _%$%tl274513274573%_)
                                (let ((_%$%tl274510274556%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%tl274513274573%_)))
                                      (_%$%hd274509274554%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%tl274513274573%_))))
                                  (let ((_%opt274559%_ _%$%hd274509274554%_)
                                        (_%rest274561%_ _%$%tl274510274556%_))
                                    (_%$%K274506274546%_
                                     _%rest274561%_
                                     _%opt274559%_)))
                                (let ((_%rest274537%_ _%$%tl274513274573%_))
                                  (_%$%K274503274531%_ _%rest274537%_)))
                            (let ((_%rest274537%_ _%$%tl274513274573%_))
                              (_%$%K274503274531%_ _%rest274537%_)))))
                  (_%$%else274501274525%_)))))))
    (define gxc#not-string-empty?
      (lambda (_%str274490%_)
        (not (let () (declare (not safe)) (string-empty? _%str274490%_)))))
    (define gxc#gsc-compile-file
      (lambda (_%path274483%_ _%phi?274484%_)
        (let ((_%gsc-link-opts274486%_
               (gxc#gsc-link-options__% _%phi?274484%_))
              (_%gsc-cc-opts274487%_
               (gxc#gsc-cc-options__%__% '#f absent-value _%phi?274484%_))
              (_%gsc-ld-opts274488%_
               (gxc#gsc-ld-options__%__% '#f absent-value _%phi?274484%_)))
          (gxc#invoke__%
           '#f
           absent-value
           absent-value
           (gxc#gerbil-gsc)
           (let ((__tmp276351
                  (let ((__tmp276352
                         (let ((__tmp276353 (cons _%path274483%_ '())))
                           (declare (not safe))
                           (##append _%gsc-link-opts274486%_ __tmp276353))))
                    (declare (not safe))
                    (##append _%gsc-ld-opts274488%_ __tmp276352))))
             (declare (not safe))
             (##append _%gsc-cc-opts274487%_ __tmp276351))))))
    (define gxc#compile-output-file
      (lambda (_%ctx274449%_ _%n274450%_ _%ext274451%_)
        (letrec ((_%module-relative-path274453%_
                  (lambda (_%ctx274481%_)
                    (path-strip-directory
                     (let ((__tmp276354
                            (##structure-ref
                             _%ctx274481%_
                             '1
                             gx#expander-context::t
                             '#f)))
                       (declare (not safe))
                       (gxc#module-id->path-string __tmp276354)))))
                 (_%module-source-directory274454%_
                  (lambda (_%ctx274477%_)
                    (path-directory
                     (let ((_%mpath274479%_
                            (##structure-ref
                             _%ctx274477%_
                             '7
                             gx#module-context::t
                             '#f)))
                       (if (string? _%mpath274479%_)
                           _%mpath274479%_
                           (last _%mpath274479%_))))))
                 (_%section-string274455%_
                  (lambda (_%n274471%_)
                    (if (number? _%n274471%_)
                        (let ()
                          (declare (not safe))
                          (##number->string _%n274471%_))
                        (if (symbol? _%n274471%_)
                            (let ()
                              (declare (not safe))
                              (##symbol->string _%n274471%_))
                            (if (string? _%n274471%_)
                                _%n274471%_
                                (let ()
                                  (declare (not safe))
                                  (gxc#raise-compile-error
                                   '"Unexpected section"
                                   _%n274471%_)))))))
                 (_%file-name274456%_
                  (lambda (_%path274469%_)
                    (if _%n274450%_
                        (string-append
                         _%path274469%_
                         '"~"
                         (_%section-string274455%_ _%n274450%_)
                         _%ext274451%_)
                        (string-append _%path274469%_ _%ext274451%_))))
                 (_%file-path274457%_
                  (lambda ()
                    (let ((_%$e274463%_
                           (let ()
                             (declare (not safe))
                             (gxc#current-compile-output-dir))))
                      (if _%$e274463%_
                          (path-expand
                           (_%file-name274456%_
                            (let ((__tmp276355
                                   (##structure-ref
                                    _%ctx274449%_
                                    '1
                                    gx#expander-context::t
                                    '#f)))
                              (declare (not safe))
                              (gxc#module-id->path-string __tmp276355)))
                           _%$e274463%_)
                          (path-expand
                           (_%file-name274456%_
                            (_%module-relative-path274453%_ _%ctx274449%_))
                           (_%module-source-directory274454%_
                            _%ctx274449%_)))))))
          (let ((_%path274459%_ (_%file-path274457%_)))
            (let ((__tmp276356
                   (lambda ()
                     (let ((__tmp276357 (path-directory _%path274459%_)))
                       (declare (not safe))
                       (create-directory*__0 __tmp276357)))))
              (declare (not safe))
              (__with-lock gxc#+driver-mutex+ __tmp276356))
            _%path274459%_))))
    (define gxc#compile-static-output-file
      (lambda (_%ctx274430%_)
        (letrec ((_%file-name274432%_
                  (lambda (_%id274447%_)
                    (let ((__tmp276358 (gxc#static-module-name _%id274447%_)))
                      (declare (not safe))
                      (##string-append __tmp276358 '".scm"))))
                 (_%file-path274433%_
                  (lambda ()
                    (let* ((_%file274439%_
                            (_%file-name274432%_
                             (##structure-ref
                              _%ctx274430%_
                              '1
                              gx#expander-context::t
                              '#f)))
                           (_%$e274441%_
                            (let ()
                              (declare (not safe))
                              (gxc#current-compile-output-dir))))
                      (if _%$e274441%_
                          (path-expand
                           _%file274439%_
                           (path-expand '"static" _%$e274441%_))
                          (path-expand _%file274439%_ '"static"))))))
          (let ((_%path274435%_ (_%file-path274433%_)))
            (let ((__tmp276359
                   (lambda ()
                     (let ((__tmp276360 (path-directory _%path274435%_)))
                       (declare (not safe))
                       (create-directory*__0 __tmp276360)))))
              (declare (not safe))
              (__with-lock gxc#+driver-mutex+ __tmp276359))
            _%path274435%_))))
    (define gxc#compile-exe-output-file
      (lambda (_%ctx274423%_ _%opts274424%_)
        (let ((_%$e274426%_
               (let ()
                 (declare (not safe))
                 (pgetq__0 'output-file: _%opts274424%_))))
          (if _%$e274426%_
              _%$e274426%_
              (path-strip-directory
               (symbol->string
                (##structure-ref
                 _%ctx274423%_
                 '1
                 gx#expander-context::t
                 '#f)))))))
    (define gxc#static-module-name
      (lambda (_%idstr274413%_)
        (if (string? _%idstr274413%_)
            (let* ((_%str274416%_
                    (let ()
                      (declare (not safe))
                      (gxc#module-id->path-string _%idstr274413%_)))
                   (_%strs274418%_
                    (let ()
                      (declare (not safe))
                      (string-split _%str274416%_ '#\/))))
              (declare (not safe))
              (string-join _%strs274418%_ '"__"))
            (if (symbol? _%idstr274413%_)
                (gxc#static-module-name
                 (let ()
                   (declare (not safe))
                   (##symbol->string _%idstr274413%_)))
                (let ()
                  (declare (not safe))
                  (error '"Bad module id" _%idstr274413%_))))))
    (define gxc#gerbil-enable-shared?
      (lambda ()
        (let ((__tmp276361
               (let ((__tmp276362 (configure-command-string)))
                 (declare (not safe))
                 (__string-split __tmp276362 '#\'))))
          (declare (not safe))
          (##member '"--enable-shared" __tmp276361))))
    (define gxc#invoke__%
      (lambda (_%@@keywords274379%_
               _%$%stdout-redirection274375274380%_
               _%$%stderr-redirection274376274381%_
               _%program274382%_
               _%args274383%_)
        (let* ((_%stdout-redirection274385%_
                (if (eq? _%$%stdout-redirection274375274380%_ absent-value)
                    '#f
                    _%$%stdout-redirection274375274380%_))
               (_%stderr-redirection274387%_
                (if (eq? _%$%stderr-redirection274376274381%_ absent-value)
                    '#f
                    _%$%stderr-redirection274376274381%_)))
          (let ((__tmp276363 (cons _%program274382%_ _%args274383%_)))
            (declare (not safe))
            (gxc#verbose '"invoke " __tmp276363))
          (let* ((_%proc274389%_
                  (open-process
                   (cons 'path:
                         (cons _%program274382%_
                               (cons 'arguments:
                                     (cons _%args274383%_
                                           (cons 'stdout-redirection:
                                                 (cons _%stdout-redirection274385%_
                                                       (cons 'stderr-redirection:
                                                             (cons _%stderr-redirection274387%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '()))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                 (_%output274394%_
                  (if (or _%stdout-redirection274385%_
                          _%stderr-redirection274387%_)
                      (read-line _%proc274389%_ '#f)
                      '#f))
                 (_%status274397%_ (process-status _%proc274389%_)))
            (let () (declare (not safe)) (##close-port _%proc274389%_))
            (if (zero? _%status274397%_)
                '#!void
                (begin
                  (display _%output274394%_)
                  (let ((__tmp276364 (cons _%program274382%_ _%args274383%_)))
                    (declare (not safe))
                    (gxc#raise-compile-error
                     '"Compilation error; process exit with nonzero status"
                     __tmp276364
                     _%status274397%_))))))))
    (define gxc#invoke__@
      (lambda (_%@@keywords274402%_ . _%args274403%_)
        (apply gxc#invoke__%
               _%@@keywords274402%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords274402%_
                  'stdout-redirection:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords274402%_
                  'stderr-redirection:
                  absent-value))
               _%args274403%_)))
    (define gxc#invoke
      (lambda _%$%args274377274409%_
        (apply keyword-dispatch
               '#(stderr-redirection: stdout-redirection:)
               gxc#invoke__@
               _%$%args274377274409%_)))))
