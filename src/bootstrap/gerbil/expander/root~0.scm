(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/root::timestamp 1795039817)
  (begin
    (declare (not safe))
    (define gx#*core-syntax-expanders*
      (list (list '%#begin
                  'top:
                  gx#core-expand-begin%
                  gx#core-compile-top-begin%)
            (list '%#begin-syntax
                  'top:
                  gx#core-expand-begin-syntax%
                  gx#core-compile-top-begin-syntax%)
            (list '%#begin-foreign
                  'top:
                  gx#core-expand-begin-foreign%
                  gx#core-compile-top-begin-foreign%)
            (cons '%#begin-module
                  (cons 'top: (cons gx#core-expand-begin-module% '(#f))))
            (list '%#extern
                  'top:
                  gx#core-expand-extern%
                  gx#core-compile-top-extern%)
            (list '%#import
                  'top:
                  gx#core-expand-import%
                  gx#core-compile-top-import%)
            (list '%#module
                  'top:
                  gx#core-expand-module%
                  gx#core-compile-top-module%)
            (list '%#export
                  'top:
                  gx#core-expand-export%
                  gx#core-compile-top-export%)
            (list '%#provide
                  'module:
                  gx#core-expand-provide%
                  gx#core-compile-top-provide%)
            (list '%#declare
                  'module:
                  gx#core-expand-declare%
                  gx#core-compile-top-declare%)
            (cons '%#cond-expand
                  (cons 'special: (cons gx#core-expand-cond-expand% '(#f))))
            (cons '%#include
                  (cons 'special: (cons gx#core-expand-include% '(#f))))
            (list '%#define-values
                  'define:
                  gx#core-expand-define-values%
                  gx#core-compile-top-define-values%)
            (list '%#define-syntax
                  'define:
                  gx#core-expand-define-syntax%
                  gx#core-compile-top-define-syntax%)
            (list '%#define-alias
                  'define:
                  gx#core-expand-define-alias%
                  gx#core-compile-top-define-alias%)
            (list '%#define-runtime
                  'define:
                  gx#core-expand-define-runtime%
                  gx#core-compile-top-define-runtime%)
            (list '%#begin-annotation
                  'expr:
                  gx#core-expand-begin-annotation%
                  gx#core-compile-top-begin-annotation%)
            (list '%#lambda
                  'expr:
                  gx#core-expand-lambda%
                  gx#core-compile-top-lambda%)
            (list '%#case-lambda
                  'expr:
                  gx#core-expand-case-lambda%
                  gx#core-compile-top-case-lambda%)
            (list '%#let-values
                  'expr:
                  gx#core-expand-let-values%
                  gx#core-compile-top-let-values%)
            (list '%#letrec-values
                  'expr:
                  gx#core-expand-letrec-values%
                  gx#core-compile-top-letrec-values%)
            (list '%#letrec*-values
                  'expr:
                  gx#core-expand-letrec*-values%
                  gx#core-compile-top-letrec*-values%)
            (cons '%#let-syntax
                  (cons 'expr: (cons gx#core-expand-let-syntax% '(#f))))
            (cons '%#letrec-syntax
                  (cons 'expr: (cons gx#core-expand-letrec-syntax% '(#f))))
            (list '%#quote
                  'expr:
                  gx#core-expand-quote%
                  gx#core-compile-top-quote%)
            (list '%#quote-syntax
                  'expr:
                  gx#core-expand-quote-syntax%
                  gx#core-compile-top-quote-syntax%)
            (list '%#call
                  'expr:
                  gx#core-expand-call%
                  gx#core-compile-top-call%)
            (list '%#if 'expr: gx#core-expand-if% gx#core-compile-top-if%)
            (list '%#ref 'expr: gx#core-expand-ref% gx#core-compile-top-ref%)
            (list '%#set!
                  'expr:
                  gx#core-expand-setq%
                  gx#core-compile-top-setq%)
            (cons '%#expression
                  (cons 'expr: (cons gx#core-expand-expression% '(#f))))
            (cons '%#bind-runtime-properties!
                  (cons 'special:
                        (cons gx#core-expand-bind-runtime-properties%
                              '(#f))))))
    (define gx#*core-macro-expanders*
      (cons '(begin => %#begin)
            (cons '(begin-syntax => %#begin-syntax)
                  (cons '(begin-foreign => %#begin-foreign)
                        (cons '(begin-annotation => %#begin-annotation)
                              (cons '(import => %#import)
                                    (cons '(module => %#module)
                                          (cons '(export => %#export)
                                                (cons '(provide => %#provide)
                                                      (cons '(declare
                                                               =>
                                                               %#declare)
                                                            (cons '(include =>
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    %#include)
                          (cons '(cond-expand => %#cond-expand)
                                (cons '(quote => %#quote)
                                      (cons '(quote-syntax => %#quote-syntax)
                                            (cons '(let-syntax => %#let-syntax)
                                                  (cons '(letrec-syntax
                                                          =>
                                                          %#letrec-syntax)
                                                        (cons '(define-values =>
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         %#define-values)
                      (cons '(define-runtime => %#define-runtime)
                            (cons '(define-syntax => %#define-syntax)
                                  (cons '(define-alias => %#define-alias)
                                        (cons (list 'extern
                                                    gx#macro-expand-extern)
                                              (cons (list 'lambda%
                                                          gx#macro-expand-lambda%)
                                                    (cons (list 'case-lambda
                                                                gx#macro-expand-case-lambda)
                                                          (cons (list 'let-values
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              gx#macro-expand-let-values)
                        (cons (list 'letrec-values
                                    gx#macro-expand-letrec-values)
                              (cons (list 'letrec*-values
                                          gx#macro-expand-letrec*-values)
                                    (cons (list 'if gx#macro-expand-if)
                                          '((%%app => %#call)
                                            (%%ref => %#ref)
                                            (%%begin-module => %#begin-module)
                                            (_)
                                            (...)
                                            (else)
                                            (=>)
                                            (unquote)
                                            (unquote-splicing)
                                            (unsyntax)
                                            (unsyntax-splicing)))))))))))))))))))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    (define gx#root-context:::init!__%
      (lambda (_%self200321%_ _%bind?200322%_)
        (let ((_%self200325%_ _%self200321%_))
          (if (##fx< '2 (##structure-length _%self200325%_))
              (begin
                (##unchecked-structure-set! _%self200325%_ 'root '1 '#f '#f)
                (##unchecked-structure-set!
                 _%self200325%_
                 (make-hash-table-eq)
                 '2
                 '#f
                 '#f)
                '#!void)
              (error '"struct-instance-init!: too many arguments for struct"
                     _%self200325%_
                     '2
                     (##structure-length _%self200325%_)))
          (if _%bind?200322%_
              (begin
                (let ((__method200389
                       (__method-ref
                        _%self200325%_
                        'bind-core-syntax-expanders!)))
                  (if __method200389
                      (__method200389 _%self200325%_)
                      (begin
                        (error '"Missing method"
                               _%self200325%_
                               'bind-core-syntax-expanders!)
                        '#!void)))
                (let ((__method200390
                       (__method-ref
                        _%self200325%_
                        'bind-core-macro-expanders!)))
                  (if __method200390
                      (__method200390 _%self200325%_)
                      (begin
                        (error '"Missing method"
                               _%self200325%_
                               'bind-core-macro-expanders!)
                        '#!void)))
                (let ((__method200391
                       (__method-ref _%self200325%_ 'bind-core-features!)))
                  (if __method200391
                      (__method200391 _%self200325%_)
                      (begin
                        (error '"Missing method"
                               _%self200325%_
                               'bind-core-features!)
                        '#!void))))
              '#!void))))
    (define gx#root-context:::init!__0
      (lambda (_%self200339%_)
        (let ((_%bind?200341%_ '#t))
          (gx#root-context:::init!__% _%self200339%_ _%bind?200341%_))))
    (define gx#root-context:::init!
      (lambda _g200395_
        (let ((_g200396_ (##length _g200395_)))
          (cond ((##fx= _g200396_ 1)
                 (apply gx#root-context:::init!__0 _g200395_))
                ((##fx= _g200396_ 2)
                 (apply gx#root-context:::init!__% _g200395_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#root-context:::init!
                  _g200395_))))))
    (define gx#root-context:::init!::specialize
      (lambda (__klass200345 __method-table200346)
        (let ((__bind-core-macro-expanders!200347
               (__make-promise
                (lambda ()
                  (let ((__method200350
                         (symbolic-table-ref
                          __method-table200346
                          'bind-core-macro-expanders!
                          '#f)))
                    (if __method200350
                        __method200350
                        (error '"Missing method"
                               'bind-core-macro-expanders!))))))
              (__bind-core-features!200348
               (__make-promise
                (lambda ()
                  (let ((__method200351
                         (symbolic-table-ref
                          __method-table200346
                          'bind-core-features!
                          '#f)))
                    (if __method200351
                        __method200351
                        (error '"Missing method" 'bind-core-features!))))))
              (__bind-core-syntax-expanders!200349
               (__make-promise
                (lambda ()
                  (let ((__method200352
                         (symbolic-table-ref
                          __method-table200346
                          'bind-core-syntax-expanders!
                          '#f)))
                    (if __method200352
                        __method200352
                        (error '"Missing method"
                               'bind-core-syntax-expanders!)))))))
          (let ((_%$%opt-lambda200319200336%_
                 (lambda (_%self200321%_ _%bind?200322%_)
                   (let ((_%self200325%_ _%self200321%_))
                     (if (##fx< '2 (##structure-length _%self200325%_))
                         (begin
                           (##unchecked-structure-set!
                            _%self200325%_
                            'root
                            '1
                            '#f
                            '#f)
                           (##unchecked-structure-set!
                            _%self200325%_
                            (make-hash-table-eq)
                            '2
                            '#f
                            '#f)
                           '#!void)
                         (error '"struct-instance-init!: too many arguments for struct"
                                _%self200325%_
                                '2
                                (##structure-length _%self200325%_)))
                     (if _%bind?200322%_
                         (begin
                           ((force __bind-core-syntax-expanders!200349)
                            _%self200325%_)
                           ((force __bind-core-macro-expanders!200347)
                            _%self200325%_)
                           ((force __bind-core-features!200348)
                            _%self200325%_))
                         '#!void)))))
            (lambda _g200397_
              (let ((_g200398_ (##length _g200397_)))
                (cond ((##fx= _g200398_ 1)
                       (apply (lambda (_%self200339%_)
                                (let ((_%bind?200341%_ '#t))
                                  (_%$%opt-lambda200319200336%_
                                   _%self200339%_
                                   _%bind?200341%_)))
                              _g200397_))
                      ((##fx= _g200398_ 2)
                       (apply _%$%opt-lambda200319200336%_ _g200397_))
                      (else
                       (##raise-wrong-number-of-arguments-exception
                        'case-lambda-dispatch
                        _g200397_)))))))))
    (bind-specializer!
     gx#root-context:::init!
     gx#root-context:::init!::specialize)
    (__bind-method!__% gx#root-context::t ':init! gx#root-context:::init! '#f)
    (define gx#top-context:::init!__%
      (lambda (_%self200166%_ _%super200167%_)
        (let* ((_%self200170%_ _%self200166%_)
               (_%super200186%_
                (let ((_%$e200180%_ _%super200167%_))
                  (if _%$e200180%_
                      _%$e200180%_
                      (let ((_%$e200183%_ (gx#core-context-root__0)))
                        (if _%$e200183%_
                            _%$e200183%_
                            (let ((__obj200392
                                   (##structure gx#root-context::t '#f '#f)))
                              (gx#root-context:::init!__0 __obj200392)
                              __obj200392)))))))
          (if (##fx< '5 (##structure-length _%self200170%_))
              (begin
                (##unchecked-structure-set! _%self200170%_ 'top '1 '#f '#f)
                (##unchecked-structure-set!
                 _%self200170%_
                 (make-hash-table-eq)
                 '2
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self200170%_
                 _%super200186%_
                 '3
                 '#f
                 '#f)
                (##unchecked-structure-set! _%self200170%_ '#f '4 '#f '#f)
                (##unchecked-structure-set! _%self200170%_ '#f '5 '#f '#f)
                '#!void)
              (error '"struct-instance-init!: too many arguments for struct"
                     _%self200170%_
                     '5
                     (##structure-length _%self200170%_))))))
    (define gx#top-context:::init!__0
      (lambda (_%self200191%_)
        (let ((_%super200193%_ '#f))
          (gx#top-context:::init!__% _%self200191%_ _%super200193%_))))
    (define gx#top-context:::init!
      (lambda _g200399_
        (let ((_g200400_ (##length _g200399_)))
          (cond ((##fx= _g200400_ 1)
                 (apply gx#top-context:::init!__0 _g200399_))
                ((##fx= _g200400_ 2)
                 (apply gx#top-context:::init!__% _g200399_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#top-context:::init!
                  _g200399_))))))
    (__bind-method!__% gx#top-context::t ':init! gx#top-context:::init! '#f)
    (define gx#expander-context::bind-core-syntax-expanders!__%
      (lambda (_%self199887%_ _%bindings199888%_)
        (let ((_%self199891%_ _%self199887%_))
          (for-each
           (lambda (_%bind199901%_)
             (let* ((_%$%bind199902199909%_ _%bind199901%_)
                    (_%$%E199904199912%_
                     (lambda ()
                       (error '"No clause matching"
                              _%$%bind199902199909%_
                              '([id . rest]))
                       '#!void))
                    (_%$%K199905200021%_
                     (lambda (_%rest199915%_ _%id199916%_)
                       (gx#core-context-put!
                        _%self199891%_
                        _%id199916%_
                        (let ((__obj200393
                               (##structure
                                gx#syntax-binding::t
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f)))
                          (gx#syntax-binding:::init!
                           __obj200393
                           _%id199916%_
                           _%id199916%_
                           '#f
                           (let* ((_%$%rest199917199928%_ _%rest199915%_)
                                  (_%$%E199919199932%_
                                   (lambda ()
                                     (error '"No clause matching"
                                            _%$%rest199917199928%_
                                            '([key expander compiler]))
                                     '#!void))
                                  (_%$%K199920199997%_
                                   (lambda (_%compiler199935%_
                                            _%expander199936%_
                                            _%key199937%_)
                                     ((let* ((_%$%key199938199951%_
                                              _%key199937%_)
                                             (_%$%E199944199955%_
                                              (lambda ()
                                                (error '"No clause matching"
                                                       _%$%key199938199951%_
                                                       '(top:)
                                                       '(module:)
                                                       '(define:)
                                                       '(special:)
                                                       '(expr:))
                                                '#!void)))
                                        (let ((_%$%K199949199991%_
                                               (lambda ()
                                                 gx#make-top-special-form))
                                              (_%$%K199948199984%_
                                               (lambda ()
                                                 gx#make-module-special-form))
                                              (_%$%K199947199976%_
                                               (lambda ()
                                                 gx#make-definition-form))
                                              (_%$%K199946199968%_
                                               (lambda ()
                                                 gx#make-special-form))
                                              (_%$%K199945199960%_
                                               (lambda ()
                                                 gx#make-expression-form)))
                                          (let* ((_%$%try-match199943199963%_
                                                  (lambda ()
                                                    (if (##eq? _%$%key199938199951%_
                                                               'expr:)
                                                        (_%$%K199945199960%_)
                                                        (_%$%E199944199955%_))))
                                                 (_%$%try-match199942199971%_
                                                  (lambda ()
                                                    (if (##eq? _%$%key199938199951%_
                                                               'special:)
                                                        (_%$%K199946199968%_)
                                                        (_%$%try-match199943199963%_))))
                                                 (_%$%try-match199941199979%_
                                                  (lambda ()
                                                    (if (##eq? _%$%key199938199951%_
                                                               'define:)
                                                        (_%$%K199947199976%_)
                                                        (_%$%try-match199942199971%_))))
                                                 (_%$%try-match199940199987%_
                                                  (lambda ()
                                                    (if (##eq? _%$%key199938199951%_
                                                               'module:)
                                                        (_%$%K199948199984%_)
                                                        (_%$%try-match199941199979%_)))))
                                            (if (##eq? _%$%key199938199951%_
                                                       'top:)
                                                (_%$%K199949199991%_)
                                                (_%$%try-match199940199987%_)))))
                                      _%expander199936%_
                                      _%id199916%_
                                      (let ((_%$e199994%_ _%compiler199935%_))
                                        (if _%$e199994%_
                                            _%$e199994%_
                                            gx#core-compile-top-error))))))
                             (if (pair? _%$%rest199917199928%_)
                                 (let ((_%$%hd199921200000%_
                                        (##car _%$%rest199917199928%_))
                                       (_%$%tl199922200002%_
                                        (##cdr _%$%rest199917199928%_)))
                                   (let ((_%key200005%_ _%$%hd199921200000%_))
                                     (if (pair? _%$%tl199922200002%_)
                                         (let ((_%$%hd199923200007%_
                                                (##car _%$%tl199922200002%_))
                                               (_%$%tl199924200009%_
                                                (##cdr _%$%tl199922200002%_)))
                                           (let ((_%expander200012%_
                                                  _%$%hd199923200007%_))
                                             (if (pair? _%$%tl199924200009%_)
                                                 (let ((_%$%hd199925200014%_
                                                        (##car _%$%tl199924200009%_))
                                                       (_%$%tl199926200016%_
                                                        (##cdr _%$%tl199924200009%_)))
                                                   (let ((_%compiler200019%_
                                                          _%$%hd199925200014%_))
                                                     (if (null? _%$%tl199926200016%_)
                                                         (_%$%K199920199997%_
                                                          _%compiler200019%_
                                                          _%expander200012%_
                                                          _%key200005%_)
                                                         (_%$%E199919199932%_))))
                                                 (_%$%E199919199932%_))))
                                         (_%$%E199919199932%_))))
                                 (_%$%E199919199932%_))))
                          __obj200393)))))
               (if (pair? _%$%bind199902199909%_)
                   (let ((_%$%hd199906200024%_ (##car _%$%bind199902199909%_))
                         (_%$%tl199907200026%_ (##cdr _%$%bind199902199909%_)))
                     (let* ((_%id200029%_ _%$%hd199906200024%_)
                            (_%rest200031%_ _%$%tl199907200026%_))
                       (_%$%K199905200021%_ _%rest200031%_ _%id200029%_)))
                   (_%$%E199904199912%_))))
           _%bindings199888%_))))
    (define gx#expander-context::bind-core-syntax-expanders!__0
      (lambda (_%self200036%_)
        (let ((_%bindings200038%_ gx#*core-syntax-expanders*))
          (gx#expander-context::bind-core-syntax-expanders!__%
           _%self200036%_
           _%bindings200038%_))))
    (define gx#expander-context::bind-core-syntax-expanders!
      (lambda _g200401_
        (let ((_g200402_ (##length _g200401_)))
          (cond ((##fx= _g200402_ 1)
                 (apply gx#expander-context::bind-core-syntax-expanders!__0
                        _g200401_))
                ((##fx= _g200402_ 2)
                 (apply gx#expander-context::bind-core-syntax-expanders!__%
                        _g200401_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#expander-context::bind-core-syntax-expanders!
                  _g200401_))))))
    (__bind-method!__%
     gx#expander-context::t
     'bind-core-syntax-expanders!
     gx#expander-context::bind-core-syntax-expanders!
     '#f)
    (define gx#expander-context::bind-core-macro-expanders!__%
      (lambda (_%self199649%_ _%bindings199650%_)
        (let ((_%self199653%_ _%self199649%_))
          (for-each
           (lambda (_%bind199663%_)
             (let* ((_%$%bind199664199671%_ _%bind199663%_)
                    (_%$%E199666199674%_
                     (lambda ()
                       (error '"No clause matching"
                              _%$%bind199664199671%_
                              '([id . rest]))
                       '#!void))
                    (_%$%K199667199742%_
                     (lambda (_%rest199677%_ _%id199678%_)
                       (gx#core-context-put!
                        _%self199653%_
                        _%id199678%_
                        (let ((__obj200394
                               (##structure
                                gx#syntax-binding::t
                                '#f
                                '#f
                                '#f
                                '#f
                                '#f)))
                          (gx#syntax-binding:::init!
                           __obj200394
                           _%id199678%_
                           _%id199678%_
                           '#f
                           (let* ((_%$%rest199679199694%_ _%rest199677%_)
                                  (_%$%E199683199698%_
                                   (lambda ()
                                     (error '"No clause matching"
                                            _%$%rest199679199694%_
                                            '(['=> core-id])
                                            '([proc])
                                            '([]))
                                     '#!void)))
                             (let ((_%$%K199688199727%_
                                    (lambda (_%core-id199725%_)
                                      (##structure
                                       gx#rename-macro-expander::t
                                       _%core-id199725%_)))
                                   (_%$%K199685199712%_
                                    (lambda (_%proc199710%_)
                                      (##structure
                                       gx#macro-expander::t
                                       _%proc199710%_)))
                                   (_%$%K199684199703%_
                                    (lambda ()
                                      (##structure
                                       gx#reserved-expander::t
                                       _%id199678%_))))
                               (let ((_%$%try-match199682199706%_
                                      (lambda ()
                                        (if (null? _%$%rest199679199694%_)
                                            (_%$%K199684199703%_)
                                            (_%$%E199683199698%_)))))
                                 (if (pair? _%$%rest199679199694%_)
                                     (let ((_%$%tl199690199732%_
                                            (##cdr _%$%rest199679199694%_))
                                           (_%$%hd199689199730%_
                                            (##car _%$%rest199679199694%_)))
                                       (if (##eq? _%$%hd199689199730%_ '=>)
                                           (if (pair? _%$%tl199690199732%_)
                                               (let ((_%$%tl199692199737%_
                                                      (##cdr _%$%tl199690199732%_))
                                                     (_%$%hd199691199735%_
                                                      (##car _%$%tl199690199732%_)))
                                                 (if (null? _%$%tl199692199737%_)
                                                     (let ((_%core-id199740%_
                                                            _%$%hd199691199735%_))
                                                       (##structure
                                                        gx#rename-macro-expander::t
                                                        _%core-id199740%_))
                                                     (_%$%E199683199698%_)))
                                               (if (null? _%$%tl199690199732%_)
                                                   (let ((_%proc199720%_
                                                          _%$%hd199689199730%_))
                                                     (##structure
                                                      gx#macro-expander::t
                                                      _%proc199720%_))
                                                   (_%$%E199683199698%_)))
                                           (if (null? _%$%tl199690199732%_)
                                               (let ((_%proc199720%_
                                                      _%$%hd199689199730%_))
                                                 (##structure
                                                  gx#macro-expander::t
                                                  _%proc199720%_))
                                               (_%$%E199683199698%_))))
                                     (_%$%try-match199682199706%_))))))
                          __obj200394)))))
               (if (pair? _%$%bind199664199671%_)
                   (let ((_%$%hd199668199745%_ (##car _%$%bind199664199671%_))
                         (_%$%tl199669199747%_ (##cdr _%$%bind199664199671%_)))
                     (let* ((_%id199750%_ _%$%hd199668199745%_)
                            (_%rest199752%_ _%$%tl199669199747%_))
                       (_%$%K199667199742%_ _%rest199752%_ _%id199750%_)))
                   (_%$%E199666199674%_))))
           _%bindings199650%_))))
    (define gx#expander-context::bind-core-macro-expanders!__0
      (lambda (_%self199757%_)
        (let ((_%bindings199759%_ gx#*core-macro-expanders*))
          (gx#expander-context::bind-core-macro-expanders!__%
           _%self199757%_
           _%bindings199759%_))))
    (define gx#expander-context::bind-core-macro-expanders!
      (lambda _g200403_
        (let ((_g200404_ (##length _g200403_)))
          (cond ((##fx= _g200404_ 1)
                 (apply gx#expander-context::bind-core-macro-expanders!__0
                        _g200403_))
                ((##fx= _g200404_ 2)
                 (apply gx#expander-context::bind-core-macro-expanders!__%
                        _g200403_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#expander-context::bind-core-macro-expanders!
                  _g200403_))))))
    (__bind-method!__%
     gx#expander-context::t
     'bind-core-macro-expanders!
     gx#expander-context::bind-core-macro-expanders!
     '#f)
    (define gx#expander-context::bind-core-features!
      (lambda (_%self199380%_)
        (let ((_%self199383%_ _%self199380%_))
          (letrec ((_%linux-variant?199394%_
                    (lambda (_%sys-type199494%_)
                      (let* ((_%$%g199495199503%_
                              (__string-split
                               (symbol->string _%sys-type199494%_)
                               '#\-))
                             (_%$%else199497199511%_ (lambda () '#f))
                             (_%$%K199499199516%_
                              (lambda (_%rest199514%_)
                                (not (null? _%rest199514%_)))))
                        (if (pair? _%$%g199495199503%_)
                            (let ((_%$%hd199500199519%_
                                   (##car _%$%g199495199503%_))
                                  (_%$%tl199501199521%_
                                   (##cdr _%$%g199495199503%_)))
                              (if (equal? _%$%hd199500199519%_ '"linux")
                                  (let ((_%rest199524%_ _%$%tl199501199521%_))
                                    (_%$%K199499199516%_ _%rest199524%_))
                                  (_%$%else199497199511%_)))
                            (_%$%else199497199511%_)))))
                   (_%bsd-variant199395%_
                    (lambda (_%sys-type199453%_)
                      (let ((_%sys-type-str199455%_
                             (symbol->string _%sys-type199453%_)))
                        (let _%lp199457%_ ((_%rest199459%_
                                            '("openbsd"
                                              "netbsd"
                                              "freebsd"
                                              "darwin")))
                          (let* ((_%$%rest199460199468%_ _%rest199459%_)
                                 (_%$%else199462199476%_ (lambda () '#f))
                                 (_%$%K199464199482%_
                                  (lambda (_%rest199479%_ _%sys199480%_)
                                    (if (string-prefix?
                                         _%sys199480%_
                                         _%sys-type-str199455%_)
                                        _%sys199480%_
                                        (_%lp199457%_ _%rest199479%_)))))
                            (if (pair? _%$%rest199460199468%_)
                                (let ((_%$%hd199465199485%_
                                       (##car _%$%rest199460199468%_))
                                      (_%$%tl199466199487%_
                                       (##cdr _%$%rest199460199468%_)))
                                  (let* ((_%sys199490%_ _%$%hd199465199485%_)
                                         (_%rest199492%_ _%$%tl199466199487%_))
                                    (_%$%K199464199482%_
                                     _%rest199492%_
                                     _%sys199490%_)))
                                (_%$%else199462199476%_))))))))
            (gx#core-bind-feature!__% 'gerbil '#f '0 _%self199383%_)
            (gx#core-bind-feature!__% (gerbil-system) '#f '0 _%self199383%_)
            (let* ((_%$%g199396199408%_ (system-type))
                   (_%$%else199398199416%_ (lambda () '#!void))
                   (_%$%K199400199429%_
                    (lambda (_%sys-type199419%_
                             _%sys-vendor199420%_
                             _%sys-cpu199421%_)
                      (gx#core-bind-feature!__%
                       _%sys-cpu199421%_
                       '#f
                       '0
                       _%self199383%_)
                      (gx#core-bind-feature!__%
                       _%sys-type199419%_
                       '#f
                       '0
                       _%self199383%_)
                      (if (_%linux-variant?199394%_ _%sys-type199419%_)
                          (gx#core-bind-feature!__%
                           (##string->symbol '"linux")
                           '#f
                           '0
                           _%self199383%_)
                          (let ((_%$e199424%_
                                 (_%bsd-variant199395%_ _%sys-type199419%_)))
                            (if _%$e199424%_
                                (let ()
                                  (gx#core-bind-feature!__%
                                   (##string->symbol '"bsd")
                                   '#f
                                   '0
                                   _%self199383%_)
                                  (gx#core-bind-feature!__%
                                   (string->symbol _%$e199424%_)
                                   '#f
                                   '0
                                   _%self199383%_))
                                '#!void))))))
              (if (pair? _%$%g199396199408%_)
                  (let ((_%$%hd199401199432%_ (##car _%$%g199396199408%_))
                        (_%$%tl199402199434%_ (##cdr _%$%g199396199408%_)))
                    (let ((_%sys-cpu199437%_ _%$%hd199401199432%_))
                      (if (pair? _%$%tl199402199434%_)
                          (let ((_%$%hd199403199439%_
                                 (##car _%$%tl199402199434%_))
                                (_%$%tl199404199441%_
                                 (##cdr _%$%tl199402199434%_)))
                            (let ((_%sys-vendor199444%_ _%$%hd199403199439%_))
                              (if (pair? _%$%tl199404199441%_)
                                  (let ((_%$%hd199405199446%_
                                         (##car _%$%tl199404199441%_))
                                        (_%$%tl199406199448%_
                                         (##cdr _%$%tl199404199441%_)))
                                    (let ((_%sys-type199451%_
                                           _%$%hd199405199446%_))
                                      (if (null? _%$%tl199406199448%_)
                                          (_%$%K199400199429%_
                                           _%sys-type199451%_
                                           _%sys-vendor199444%_
                                           _%sys-cpu199437%_)
                                          '#!void)))
                                  '#!void)))
                          '#!void)))
                  '#!void))
            (if (gerbil-runtime-smp?)
                (gx#core-bind-feature!__% 'gerbil-smp '#f '0 _%self199383%_)
                '#!void)))))
    (__bind-method!__%
     gx#expander-context::t
     'bind-core-features!
     gx#expander-context::bind-core-features!
     '#f)))
