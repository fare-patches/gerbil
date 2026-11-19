(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/compile::timestamp 1795039817)
  (begin
    (declare (not safe))
    (define gx#core-compile-top-syntax
      (lambda (_%stx199222%_)
        (let* ((_%$%e199223199230%_ _%stx199222%_)
               (_%$%E199225199234%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e199223199230%_)))
               (_%$%E199224199248%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e199223199230%_)
                      (let ((_%$%e199226199238%_
                             (gx#syntax-e _%$%e199223199230%_)))
                        (let ((_%$%hd199227199241%_
                               (##car _%$%e199226199238%_))
                              (_%$%tl199228199243%_
                               (##cdr _%$%e199226199238%_)))
                          (let* ((_%form199246%_ _%$%hd199227199241%_)
                                 (__self199251
                                  (gx#syntax-local-e__0 _%form199246%_))
                                 (__method199252
                                  (__method-ref
                                   __self199251
                                   'compile-top-syntax)))
                            (if __method199252
                                (__method199252 __self199251 _%stx199222%_)
                                (begin
                                  (error '"Missing method"
                                         __self199251
                                         'compile-top-syntax)
                                  '#!void)))))
                      (_%$%E199225199234%_)))))
          (_%$%E199224199248%_))))
    (define gx#core-expander::compile-top-syntax
      (lambda (_%self199171%_ _%stx199172%_)
        (let* ((_%self199175%_ _%self199171%_)
               (_%$%self199184199192%_ _%self199175%_)
               (_%$%E199186199195%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%self199184199192%_
                         '((core-expander _ _ K)))
                  '#!void))
               (_%$%K199187199208%_
                (lambda (_%K199198%_)
                  (let ((_%$e199200%_ (gx#stx-source _%stx199172%_)))
                    (if _%$e199200%_
                        (gx#stx-wrap-source
                         (_%K199198%_ _%stx199172%_)
                         _%$e199200%_)
                        (_%K199198%_ _%stx199172%_)))))
               (_%$%e199188199211%_
                (##unchecked-structure-ref _%$%self199184199192%_ '1 '#f '#f))
               (_%$%e199189199214%_
                (##unchecked-structure-ref _%$%self199184199192%_ '2 '#f '#f))
               (_%$%e199190199217%_
                (##unchecked-structure-ref _%$%self199184199192%_ '3 '#f '#f))
               (_%K199220%_ _%$%e199190199217%_))
          (_%$%K199187199208%_ _%K199220%_))))
    (__bind-method!__%
     gx#core-expander::t
     'compile-top-syntax
     gx#core-expander::compile-top-syntax
     '#f)
    (define gx#core-compile-top-error
      (lambda (_%stx199045%_)
        (gx#raise-syntax-error 'compile '"Cannot compile form" _%stx199045%_)))
    (define gx#core-compile-top-begin%
      (lambda (_%stx199015%_)
        (let* ((_%$%e199016199023%_ _%stx199015%_)
               (_%$%E199018199027%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e199016199023%_)))
               (_%$%E199017199041%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e199016199023%_)
                      (let ((_%$%e199019199031%_
                             (gx#syntax-e _%$%e199016199023%_)))
                        (let ((_%$%hd199020199034%_
                               (##car _%$%e199019199031%_))
                              (_%$%tl199021199036%_
                               (##cdr _%$%e199019199031%_)))
                          (let ((_%body199039%_ _%$%tl199021199036%_))
                            (cons '%#begin
                                  (gx#stx-map1
                                   gx#core-compile-top-syntax
                                   _%body199039%_)))))
                      (_%$%E199018199027%_)))))
          (_%$%E199017199041%_))))
    (define gx#core-compile-top-begin-syntax%
      (lambda (_%stx198984%_)
        (let* ((_%$%e198985198992%_ _%stx198984%_)
               (_%$%E198987198996%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198985198992%_)))
               (_%$%E198986199011%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198985198992%_)
                      (let ((_%$%e198988199000%_
                             (gx#syntax-e _%$%e198985198992%_)))
                        (let ((_%$%hd198989199003%_
                               (##car _%$%e198988199000%_))
                              (_%$%tl198990199005%_
                               (##cdr _%$%e198988199000%_)))
                          (let ((_%body199008%_ _%$%tl198990199005%_))
                            (cons '%#begin-syntax
                                  (call-with-parameters__1
                                   (lambda ()
                                     (gx#stx-map1
                                      gx#core-compile-top-syntax
                                      _%body199008%_))
                                   gx#current-expander-phi
                                   (##fx+ (gx#current-expander-phi) '1))))))
                      (_%$%E198987198996%_)))))
          (_%$%E198986199011%_))))
    (define gx#core-compile-top-begin-foreign%
      (lambda (_%stx198954%_)
        (let* ((_%$%e198955198962%_ _%stx198954%_)
               (_%$%E198957198966%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198955198962%_)))
               (_%$%E198956198980%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198955198962%_)
                      (let ((_%$%e198958198970%_
                             (gx#syntax-e _%$%e198955198962%_)))
                        (let ((_%$%hd198959198973%_
                               (##car _%$%e198958198970%_))
                              (_%$%tl198960198975%_
                               (##cdr _%$%e198958198970%_)))
                          (let ((_%body198978%_ _%$%tl198960198975%_))
                            (cons '%#begin-foreign _%body198978%_))))
                      (_%$%E198957198966%_)))))
          (_%$%E198956198980%_))))
    (define gx#core-compile-top-begin-annotation%
      (lambda (_%stx198900%_)
        (let* ((_%$%e198901198914%_ _%stx198900%_)
               (_%$%E198903198918%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198901198914%_)))
               (_%$%E198902198950%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198901198914%_)
                      (let ((_%$%e198904198922%_
                             (gx#syntax-e _%$%e198901198914%_)))
                        (let ((_%$%hd198905198925%_
                               (##car _%$%e198904198922%_))
                              (_%$%tl198906198927%_
                               (##cdr _%$%e198904198922%_)))
                          (if (gx#stx-pair? _%$%tl198906198927%_)
                              (let ((_%$%e198907198930%_
                                     (gx#syntax-e _%$%tl198906198927%_)))
                                (let ((_%$%hd198908198933%_
                                       (##car _%$%e198907198930%_))
                                      (_%$%tl198909198935%_
                                       (##cdr _%$%e198907198930%_)))
                                  (let ((_%ann198938%_ _%$%hd198908198933%_))
                                    (if (gx#stx-pair? _%$%tl198909198935%_)
                                        (let ((_%$%e198910198940%_
                                               (gx#syntax-e
                                                _%$%tl198909198935%_)))
                                          (let ((_%$%hd198911198943%_
                                                 (##car _%$%e198910198940%_))
                                                (_%$%tl198912198945%_
                                                 (##cdr _%$%e198910198940%_)))
                                            (let ((_%expr198948%_
                                                   _%$%hd198911198943%_))
                                              (if (gx#stx-null?
                                                   _%$%tl198912198945%_)
                                                  (gx#core-compile-top-syntax
                                                   _%expr198948%_)
                                                  (_%$%E198903198918%_)))))
                                        (_%$%E198903198918%_)))))
                              (_%$%E198903198918%_))))
                      (_%$%E198903198918%_)))))
          (_%$%E198902198950%_))))
    (define gx#core-compile-top-import%
      (lambda (_%stx198870%_)
        (let* ((_%$%e198871198878%_ _%stx198870%_)
               (_%$%E198873198882%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198871198878%_)))
               (_%$%E198872198896%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198871198878%_)
                      (let ((_%$%e198874198886%_
                             (gx#syntax-e _%$%e198871198878%_)))
                        (let ((_%$%hd198875198889%_
                               (##car _%$%e198874198886%_))
                              (_%$%tl198876198891%_
                               (##cdr _%$%e198874198886%_)))
                          (let ((_%body198894%_ _%$%tl198876198891%_))
                            (cons '%#import _%body198894%_))))
                      (_%$%E198873198882%_)))))
          (_%$%E198872198896%_))))
    (define gx#core-compile-top-module%
      (lambda (_%stx198827%_)
        (let* ((_%$%e198828198838%_ _%stx198827%_)
               (_%$%E198830198842%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198828198838%_)))
               (_%$%E198829198866%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198828198838%_)
                      (let ((_%$%e198831198846%_
                             (gx#syntax-e _%$%e198828198838%_)))
                        (let ((_%$%hd198832198849%_
                               (##car _%$%e198831198846%_))
                              (_%$%tl198833198851%_
                               (##cdr _%$%e198831198846%_)))
                          (if (gx#stx-pair? _%$%tl198833198851%_)
                              (let ((_%$%e198834198854%_
                                     (gx#syntax-e _%$%tl198833198851%_)))
                                (let ((_%$%hd198835198857%_
                                       (##car _%$%e198834198854%_))
                                      (_%$%tl198836198859%_
                                       (##cdr _%$%e198834198854%_)))
                                  (let* ((_%hd198862%_ _%$%hd198835198857%_)
                                         (_%body198864%_ _%$%tl198836198859%_))
                                    (cons '%#module
                                          (cons (##structure-ref
                                                 (gx#syntax-local-e__0
                                                  _%hd198862%_)
                                                 '1
                                                 gx#expander-context::t
                                                 '#f)
                                                (gx#stx-map1
                                                 gx#core-compile-top-syntax
                                                 _%body198864%_))))))
                              (_%$%E198830198842%_))))
                      (_%$%E198830198842%_)))))
          (_%$%E198829198866%_))))
    (define gx#core-compile-top-export%
      (lambda (_%stx198797%_)
        (let* ((_%$%e198798198805%_ _%stx198797%_)
               (_%$%E198800198809%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198798198805%_)))
               (_%$%E198799198823%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198798198805%_)
                      (let ((_%$%e198801198813%_
                             (gx#syntax-e _%$%e198798198805%_)))
                        (let ((_%$%hd198802198816%_
                               (##car _%$%e198801198813%_))
                              (_%$%tl198803198818%_
                               (##cdr _%$%e198801198813%_)))
                          (let ((_%body198821%_ _%$%tl198803198818%_))
                            (cons '%#export _%body198821%_))))
                      (_%$%E198800198809%_)))))
          (_%$%E198799198823%_))))
    (define gx#core-compile-top-provide%
      (lambda (_%stx198767%_)
        (let* ((_%$%e198768198775%_ _%stx198767%_)
               (_%$%E198770198779%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198768198775%_)))
               (_%$%E198769198793%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198768198775%_)
                      (let ((_%$%e198771198783%_
                             (gx#syntax-e _%$%e198768198775%_)))
                        (let ((_%$%hd198772198786%_
                               (##car _%$%e198771198783%_))
                              (_%$%tl198773198788%_
                               (##cdr _%$%e198771198783%_)))
                          (let ((_%body198791%_ _%$%tl198773198788%_))
                            (cons '%#provide _%body198791%_))))
                      (_%$%E198770198779%_)))))
          (_%$%E198769198793%_))))
    (define gx#core-compile-top-extern%
      (lambda (_%stx198737%_)
        (let* ((_%$%e198738198745%_ _%stx198737%_)
               (_%$%E198740198749%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198738198745%_)))
               (_%$%E198739198763%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198738198745%_)
                      (let ((_%$%e198741198753%_
                             (gx#syntax-e _%$%e198738198745%_)))
                        (let ((_%$%hd198742198756%_
                               (##car _%$%e198741198753%_))
                              (_%$%tl198743198758%_
                               (##cdr _%$%e198741198753%_)))
                          (let ((_%body198761%_ _%$%tl198743198758%_))
                            (cons '%#extern _%body198761%_))))
                      (_%$%E198740198749%_)))))
          (_%$%E198739198763%_))))
    (define gx#core-compile-top-define-values%
      (lambda (_%stx198683%_)
        (let* ((_%$%e198684198697%_ _%stx198683%_)
               (_%$%E198686198701%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198684198697%_)))
               (_%$%E198685198733%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198684198697%_)
                      (let ((_%$%e198687198705%_
                             (gx#syntax-e _%$%e198684198697%_)))
                        (let ((_%$%hd198688198708%_
                               (##car _%$%e198687198705%_))
                              (_%$%tl198689198710%_
                               (##cdr _%$%e198687198705%_)))
                          (if (gx#stx-pair? _%$%tl198689198710%_)
                              (let ((_%$%e198690198713%_
                                     (gx#syntax-e _%$%tl198689198710%_)))
                                (let ((_%$%hd198691198716%_
                                       (##car _%$%e198690198713%_))
                                      (_%$%tl198692198718%_
                                       (##cdr _%$%e198690198713%_)))
                                  (let ((_%hd198721%_ _%$%hd198691198716%_))
                                    (if (gx#stx-pair? _%$%tl198692198718%_)
                                        (let ((_%$%e198693198723%_
                                               (gx#syntax-e
                                                _%$%tl198692198718%_)))
                                          (let ((_%$%hd198694198726%_
                                                 (##car _%$%e198693198723%_))
                                                (_%$%tl198695198728%_
                                                 (##cdr _%$%e198693198723%_)))
                                            (let ((_%expr198731%_
                                                   _%$%hd198694198726%_))
                                              (if (gx#stx-null?
                                                   _%$%tl198695198728%_)
                                                  (cons '%#define-values
                                                        (cons (gx#stx-map1
                                                               gx#core-compile-top-runtime-bind
                                                               _%hd198721%_)
                                                              (cons (gx#core-compile-top-syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%expr198731%_)
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E198686198701%_)))))
                                        (_%$%E198686198701%_)))))
                              (_%$%E198686198701%_))))
                      (_%$%E198686198701%_)))))
          (_%$%E198685198733%_))))
    (define gx#core-compile-top-define-syntax%
      (lambda (_%stx198628%_)
        (let* ((_%$%e198629198642%_ _%stx198628%_)
               (_%$%E198631198646%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198629198642%_)))
               (_%$%E198630198679%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198629198642%_)
                      (let ((_%$%e198632198650%_
                             (gx#syntax-e _%$%e198629198642%_)))
                        (let ((_%$%hd198633198653%_
                               (##car _%$%e198632198650%_))
                              (_%$%tl198634198655%_
                               (##cdr _%$%e198632198650%_)))
                          (if (gx#stx-pair? _%$%tl198634198655%_)
                              (let ((_%$%e198635198658%_
                                     (gx#syntax-e _%$%tl198634198655%_)))
                                (let ((_%$%hd198636198661%_
                                       (##car _%$%e198635198658%_))
                                      (_%$%tl198637198663%_
                                       (##cdr _%$%e198635198658%_)))
                                  (let ((_%hd198666%_ _%$%hd198636198661%_))
                                    (if (gx#stx-pair? _%$%tl198637198663%_)
                                        (let ((_%$%e198638198668%_
                                               (gx#syntax-e
                                                _%$%tl198637198663%_)))
                                          (let ((_%$%hd198639198671%_
                                                 (##car _%$%e198638198668%_))
                                                (_%$%tl198640198673%_
                                                 (##cdr _%$%e198638198668%_)))
                                            (let ((_%expr198676%_
                                                   _%$%hd198639198671%_))
                                              (if (gx#stx-null?
                                                   _%$%tl198640198673%_)
                                                  (cons '%#define-syntax
                                                        (cons _%hd198666%_
                                                              (cons (call-with-parameters__1
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (lambda ()
                               (gx#core-compile-top-syntax _%expr198676%_))
                             gx#current-expander-phi
                             (##fx+ (gx#current-expander-phi) '1))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E198631198646%_)))))
                                        (_%$%E198631198646%_)))))
                              (_%$%E198631198646%_))))
                      (_%$%E198631198646%_)))))
          (_%$%E198630198679%_))))
    (define gx#core-compile-top-define-alias%
      (lambda (_%stx198598%_)
        (let* ((_%$%e198599198606%_ _%stx198598%_)
               (_%$%E198601198610%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198599198606%_)))
               (_%$%E198600198624%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198599198606%_)
                      (let ((_%$%e198602198614%_
                             (gx#syntax-e _%$%e198599198606%_)))
                        (let ((_%$%hd198603198617%_
                               (##car _%$%e198602198614%_))
                              (_%$%tl198604198619%_
                               (##cdr _%$%e198602198614%_)))
                          (let ((_%body198622%_ _%$%tl198604198619%_))
                            (cons '%#define-alias _%body198622%_))))
                      (_%$%E198601198610%_)))))
          (_%$%E198600198624%_))))
    (define gx#core-compile-top-define-runtime%
      (lambda (_%stx198568%_)
        (let* ((_%$%e198569198576%_ _%stx198568%_)
               (_%$%E198571198580%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198569198576%_)))
               (_%$%E198570198594%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198569198576%_)
                      (let ((_%$%e198572198584%_
                             (gx#syntax-e _%$%e198569198576%_)))
                        (let ((_%$%hd198573198587%_
                               (##car _%$%e198572198584%_))
                              (_%$%tl198574198589%_
                               (##cdr _%$%e198572198584%_)))
                          (let ((_%body198592%_ _%$%tl198574198589%_))
                            (cons '%#define-runtime _%body198592%_))))
                      (_%$%E198571198580%_)))))
          (_%$%E198570198594%_))))
    (define gx#core-compile-top-declare%
      (lambda (_%stx198538%_)
        (let* ((_%$%e198539198546%_ _%stx198538%_)
               (_%$%E198541198550%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198539198546%_)))
               (_%$%E198540198564%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198539198546%_)
                      (let ((_%$%e198542198554%_
                             (gx#syntax-e _%$%e198539198546%_)))
                        (let ((_%$%hd198543198557%_
                               (##car _%$%e198542198554%_))
                              (_%$%tl198544198559%_
                               (##cdr _%$%e198542198554%_)))
                          (let ((_%decls198562%_ _%$%tl198544198559%_))
                            (cons '%#declare _%decls198562%_))))
                      (_%$%E198541198550%_)))))
          (_%$%E198540198564%_))))
    (define gx#core-compile-top-lambda%
      (lambda (_%stx198508%_)
        (let* ((_%$%e198509198516%_ _%stx198508%_)
               (_%$%E198511198520%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198509198516%_)))
               (_%$%E198510198534%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198509198516%_)
                      (let ((_%$%e198512198524%_
                             (gx#syntax-e _%$%e198509198516%_)))
                        (let ((_%$%hd198513198527%_
                               (##car _%$%e198512198524%_))
                              (_%$%tl198514198529%_
                               (##cdr _%$%e198512198524%_)))
                          (let ((_%clause198532%_ _%$%tl198514198529%_))
                            (cons '%#lambda
                                  (gx#core-compile-top-lambda-clause
                                   _%clause198532%_)))))
                      (_%$%E198511198520%_)))))
          (_%$%E198510198534%_))))
    (define gx#core-compile-top-lambda-clause
      (lambda (_%stx198465%_)
        (let* ((_%$%e198466198476%_ _%stx198465%_)
               (_%$%E198468198480%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198466198476%_)))
               (_%$%E198467198504%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198466198476%_)
                      (let ((_%$%e198469198484%_
                             (gx#syntax-e _%$%e198466198476%_)))
                        (let ((_%$%hd198470198487%_
                               (##car _%$%e198469198484%_))
                              (_%$%tl198471198489%_
                               (##cdr _%$%e198469198484%_)))
                          (let ((_%hd198492%_ _%$%hd198470198487%_))
                            (if (gx#stx-pair? _%$%tl198471198489%_)
                                (let ((_%$%e198472198494%_
                                       (gx#syntax-e _%$%tl198471198489%_)))
                                  (let ((_%$%hd198473198497%_
                                         (##car _%$%e198472198494%_))
                                        (_%$%tl198474198499%_
                                         (##cdr _%$%e198472198494%_)))
                                    (let ((_%body198502%_
                                           _%$%hd198473198497%_))
                                      (if (gx#stx-null? _%$%tl198474198499%_)
                                          (cons (gx#stx-map1
                                                 gx#core-compile-top-runtime-bind
                                                 _%hd198492%_)
                                                (cons (gx#core-compile-top-syntax
                                                       _%body198502%_)
                                                      '()))
                                          (_%$%E198468198480%_)))))
                                (_%$%E198468198480%_)))))
                      (_%$%E198468198480%_)))))
          (_%$%E198467198504%_))))
    (define gx#core-compile-top-case-lambda%
      (lambda (_%stx198435%_)
        (let* ((_%$%e198436198443%_ _%stx198435%_)
               (_%$%E198438198447%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198436198443%_)))
               (_%$%E198437198461%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198436198443%_)
                      (let ((_%$%e198439198451%_
                             (gx#syntax-e _%$%e198436198443%_)))
                        (let ((_%$%hd198440198454%_
                               (##car _%$%e198439198451%_))
                              (_%$%tl198441198456%_
                               (##cdr _%$%e198439198451%_)))
                          (let ((_%clauses198459%_ _%$%tl198441198456%_))
                            (cons '%#case-lambda
                                  (gx#stx-map1
                                   gx#core-compile-top-lambda-clause
                                   _%clauses198459%_)))))
                      (_%$%E198438198447%_)))))
          (_%$%E198437198461%_))))
    (define gx#core-compile-top-let-values%__%
      (lambda (_%stx198370%_ _%form198371%_)
        (let* ((_%$%e198372198385%_ _%stx198370%_)
               (_%$%E198374198389%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198372198385%_)))
               (_%$%E198373198421%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198372198385%_)
                      (let ((_%$%e198375198393%_
                             (gx#syntax-e _%$%e198372198385%_)))
                        (let ((_%$%hd198376198396%_
                               (##car _%$%e198375198393%_))
                              (_%$%tl198377198398%_
                               (##cdr _%$%e198375198393%_)))
                          (if (gx#stx-pair? _%$%tl198377198398%_)
                              (let ((_%$%e198378198401%_
                                     (gx#syntax-e _%$%tl198377198398%_)))
                                (let ((_%$%hd198379198404%_
                                       (##car _%$%e198378198401%_))
                                      (_%$%tl198380198406%_
                                       (##cdr _%$%e198378198401%_)))
                                  (let ((_%hd198409%_ _%$%hd198379198404%_))
                                    (if (gx#stx-pair? _%$%tl198380198406%_)
                                        (let ((_%$%e198381198411%_
                                               (gx#syntax-e
                                                _%$%tl198380198406%_)))
                                          (let ((_%$%hd198382198414%_
                                                 (##car _%$%e198381198411%_))
                                                (_%$%tl198383198416%_
                                                 (##cdr _%$%e198381198411%_)))
                                            (let ((_%body198419%_
                                                   _%$%hd198382198414%_))
                                              (if (gx#stx-null?
                                                   _%$%tl198383198416%_)
                                                  (cons _%form198371%_
                                                        (cons (gx#stx-map1
                                                               gx#core-compile-top-lambda-clause
                                                               _%hd198409%_)
                                                              (cons (gx#core-compile-top-syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%body198419%_)
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E198374198389%_)))))
                                        (_%$%E198374198389%_)))))
                              (_%$%E198374198389%_))))
                      (_%$%E198374198389%_)))))
          (_%$%E198373198421%_))))
    (define gx#core-compile-top-let-values%__0
      (lambda (_%stx198428%_)
        (let ((_%form198430%_ '%#let-values))
          (gx#core-compile-top-let-values%__% _%stx198428%_ _%form198430%_))))
    (define gx#core-compile-top-let-values%
      (lambda _g199253_
        (let ((_g199254_ (##length _g199253_)))
          (cond ((##fx= _g199254_ 1)
                 (apply gx#core-compile-top-let-values%__0 _g199253_))
                ((##fx= _g199254_ 2)
                 (apply gx#core-compile-top-let-values%__% _g199253_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-compile-top-let-values%
                  _g199253_))))))
    (define gx#core-compile-top-letrec-values%
      (lambda (_%stx198367%_)
        (gx#core-compile-top-let-values%__% _%stx198367%_ '%#letrec-values)))
    (define gx#core-compile-top-letrec*-values%
      (lambda (_%stx198365%_)
        (gx#core-compile-top-let-values%__% _%stx198365%_ '%#letrec*-values)))
    (define gx#core-compile-top-quote%
      (lambda (_%stx198324%_)
        (let* ((_%$%e198325198335%_ _%stx198324%_)
               (_%$%E198327198339%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198325198335%_)))
               (_%$%E198326198361%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198325198335%_)
                      (let ((_%$%e198328198343%_
                             (gx#syntax-e _%$%e198325198335%_)))
                        (let ((_%$%hd198329198346%_
                               (##car _%$%e198328198343%_))
                              (_%$%tl198330198348%_
                               (##cdr _%$%e198328198343%_)))
                          (if (gx#stx-pair? _%$%tl198330198348%_)
                              (let ((_%$%e198331198351%_
                                     (gx#syntax-e _%$%tl198330198348%_)))
                                (let ((_%$%hd198332198354%_
                                       (##car _%$%e198331198351%_))
                                      (_%$%tl198333198356%_
                                       (##cdr _%$%e198331198351%_)))
                                  (let ((_%e198359%_ _%$%hd198332198354%_))
                                    (if (gx#stx-null? _%$%tl198333198356%_)
                                        (cons '%#quote
                                              (cons (gx#syntax->datum
                                                     _%e198359%_)
                                                    '()))
                                        (_%$%E198327198339%_)))))
                              (_%$%E198327198339%_))))
                      (_%$%E198327198339%_)))))
          (_%$%E198326198361%_))))
    (define gx#core-compile-top-quote-syntax%
      (lambda (_%stx198283%_)
        (let* ((_%$%e198284198294%_ _%stx198283%_)
               (_%$%E198286198298%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198284198294%_)))
               (_%$%E198285198320%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198284198294%_)
                      (let ((_%$%e198287198302%_
                             (gx#syntax-e _%$%e198284198294%_)))
                        (let ((_%$%hd198288198305%_
                               (##car _%$%e198287198302%_))
                              (_%$%tl198289198307%_
                               (##cdr _%$%e198287198302%_)))
                          (if (gx#stx-pair? _%$%tl198289198307%_)
                              (let ((_%$%e198290198310%_
                                     (gx#syntax-e _%$%tl198289198307%_)))
                                (let ((_%$%hd198291198313%_
                                       (##car _%$%e198290198310%_))
                                      (_%$%tl198292198315%_
                                       (##cdr _%$%e198290198310%_)))
                                  (let ((_%e198318%_ _%$%hd198291198313%_))
                                    (if (gx#stx-null? _%$%tl198292198315%_)
                                        (cons '%#quote-syntax
                                              (cons (gx#core-quote-syntax__0
                                                     _%e198318%_)
                                                    '()))
                                        (_%$%E198286198298%_)))))
                              (_%$%E198286198298%_))))
                      (_%$%E198286198298%_)))))
          (_%$%E198285198320%_))))
    (define gx#core-compile-top-call%
      (lambda (_%stx198240%_)
        (let* ((_%$%e198241198251%_ _%stx198240%_)
               (_%$%E198243198255%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198241198251%_)))
               (_%$%E198242198279%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198241198251%_)
                      (let ((_%$%e198244198259%_
                             (gx#syntax-e _%$%e198241198251%_)))
                        (let ((_%$%hd198245198262%_
                               (##car _%$%e198244198259%_))
                              (_%$%tl198246198264%_
                               (##cdr _%$%e198244198259%_)))
                          (if (gx#stx-pair? _%$%tl198246198264%_)
                              (let ((_%$%e198247198267%_
                                     (gx#syntax-e _%$%tl198246198264%_)))
                                (let ((_%$%hd198248198270%_
                                       (##car _%$%e198247198267%_))
                                      (_%$%tl198249198272%_
                                       (##cdr _%$%e198247198267%_)))
                                  (let* ((_%rator198275%_ _%$%hd198248198270%_)
                                         (_%args198277%_ _%$%tl198249198272%_))
                                    (cons '%#call
                                          (cons (gx#core-compile-top-syntax
                                                 _%rator198275%_)
                                                (gx#stx-map1
                                                 gx#core-compile-top-syntax
                                                 _%args198277%_))))))
                              (_%$%E198243198255%_))))
                      (_%$%E198243198255%_)))))
          (_%$%E198242198279%_))))
    (define gx#core-compile-top-if%
      (lambda (_%stx198173%_)
        (let* ((_%$%e198174198190%_ _%stx198173%_)
               (_%$%E198176198194%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198174198190%_)))
               (_%$%E198175198236%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198174198190%_)
                      (let ((_%$%e198177198198%_
                             (gx#syntax-e _%$%e198174198190%_)))
                        (let ((_%$%hd198178198201%_
                               (##car _%$%e198177198198%_))
                              (_%$%tl198179198203%_
                               (##cdr _%$%e198177198198%_)))
                          (if (gx#stx-pair? _%$%tl198179198203%_)
                              (let ((_%$%e198180198206%_
                                     (gx#syntax-e _%$%tl198179198203%_)))
                                (let ((_%$%hd198181198209%_
                                       (##car _%$%e198180198206%_))
                                      (_%$%tl198182198211%_
                                       (##cdr _%$%e198180198206%_)))
                                  (let ((_%test198214%_ _%$%hd198181198209%_))
                                    (if (gx#stx-pair? _%$%tl198182198211%_)
                                        (let ((_%$%e198183198216%_
                                               (gx#syntax-e
                                                _%$%tl198182198211%_)))
                                          (let ((_%$%hd198184198219%_
                                                 (##car _%$%e198183198216%_))
                                                (_%$%tl198185198221%_
                                                 (##cdr _%$%e198183198216%_)))
                                            (let ((_%K198224%_
                                                   _%$%hd198184198219%_))
                                              (if (gx#stx-pair?
                                                   _%$%tl198185198221%_)
                                                  (let ((_%$%e198186198226%_
                                                         (gx#syntax-e
                                                          _%$%tl198185198221%_)))
                                                    (let ((_%$%hd198187198229%_
                                                           (##car _%$%e198186198226%_))
                                                          (_%$%tl198188198231%_
                                                           (##cdr _%$%e198186198226%_)))
                                                      (let ((_%E198234%_
                                                             _%$%hd198187198229%_))
                                                        (if (gx#stx-null?
                                                             _%$%tl198188198231%_)
                                                            (cons '%#if
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons (gx#core-compile-top-syntax _%test198214%_)
                                (cons (gx#core-compile-top-syntax _%K198224%_)
                                      (cons (gx#core-compile-top-syntax
                                             _%E198234%_)
                                            '()))))
                    (_%$%E198176198194%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E198176198194%_)))))
                                        (_%$%E198176198194%_)))))
                              (_%$%E198176198194%_))))
                      (_%$%E198176198194%_)))))
          (_%$%E198175198236%_))))
    (define gx#core-compile-top-ref%
      (lambda (_%stx198132%_)
        (let* ((_%$%e198133198143%_ _%stx198132%_)
               (_%$%E198135198147%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198133198143%_)))
               (_%$%E198134198169%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198133198143%_)
                      (let ((_%$%e198136198151%_
                             (gx#syntax-e _%$%e198133198143%_)))
                        (let ((_%$%hd198137198154%_
                               (##car _%$%e198136198151%_))
                              (_%$%tl198138198156%_
                               (##cdr _%$%e198136198151%_)))
                          (if (gx#stx-pair? _%$%tl198138198156%_)
                              (let ((_%$%e198139198159%_
                                     (gx#syntax-e _%$%tl198138198156%_)))
                                (let ((_%$%hd198140198162%_
                                       (##car _%$%e198139198159%_))
                                      (_%$%tl198141198164%_
                                       (##cdr _%$%e198139198159%_)))
                                  (let ((_%id198167%_ _%$%hd198140198162%_))
                                    (if (gx#stx-null? _%$%tl198141198164%_)
                                        (if (gx#identifier? _%id198167%_)
                                            (cons '%#ref
                                                  (cons (gx#core-compile-top-runtime-ref
                                                         _%id198167%_)
                                                        '()))
                                            (_%$%E198135198147%_))
                                        (_%$%E198135198147%_)))))
                              (_%$%E198135198147%_))))
                      (_%$%E198135198147%_)))))
          (_%$%E198134198169%_))))
    (define gx#core-compile-top-setq%
      (lambda (_%stx198078%_)
        (let* ((_%$%e198079198092%_ _%stx198078%_)
               (_%$%E198081198096%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e198079198092%_)))
               (_%$%E198080198128%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e198079198092%_)
                      (let ((_%$%e198082198100%_
                             (gx#syntax-e _%$%e198079198092%_)))
                        (let ((_%$%hd198083198103%_
                               (##car _%$%e198082198100%_))
                              (_%$%tl198084198105%_
                               (##cdr _%$%e198082198100%_)))
                          (if (gx#stx-pair? _%$%tl198084198105%_)
                              (let ((_%$%e198085198108%_
                                     (gx#syntax-e _%$%tl198084198105%_)))
                                (let ((_%$%hd198086198111%_
                                       (##car _%$%e198085198108%_))
                                      (_%$%tl198087198113%_
                                       (##cdr _%$%e198085198108%_)))
                                  (let ((_%id198116%_ _%$%hd198086198111%_))
                                    (if (gx#stx-pair? _%$%tl198087198113%_)
                                        (let ((_%$%e198088198118%_
                                               (gx#syntax-e
                                                _%$%tl198087198113%_)))
                                          (let ((_%$%hd198089198121%_
                                                 (##car _%$%e198088198118%_))
                                                (_%$%tl198090198123%_
                                                 (##cdr _%$%e198088198118%_)))
                                            (let ((_%expr198126%_
                                                   _%$%hd198089198121%_))
                                              (if (gx#stx-null?
                                                   _%$%tl198090198123%_)
                                                  (if (gx#identifier?
                                                       _%id198116%_)
                                                      (cons '%#set!
                                                            (cons (gx#core-compile-top-runtime-ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%id198116%_)
                          (cons (gx#core-compile-top-syntax _%expr198126%_)
                                '())))
              (_%$%E198081198096%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%E198081198096%_)))))
                                        (_%$%E198081198096%_)))))
                              (_%$%E198081198096%_))))
                      (_%$%E198081198096%_)))))
          (_%$%E198080198128%_))))
    (define gx#core-compile-top-runtime-ref
      (lambda (_%id198072%_)
        (let ((_%$e198074%_ (gx#resolve-identifier__0 _%id198072%_)))
          (if _%$e198074%_
              (##unchecked-structure-ref _%$e198074%_ '1 '#f '#f)
              _%id198072%_))))
    (define gx#core-compile-top-runtime-bind
      (lambda (_%hd198070%_)
        (if (gx#identifier? _%hd198070%_)
            (gx#core-compile-top-runtime-ref _%hd198070%_)
            '#f)))))
