(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/core::timestamp 1795039816)
  (begin
    (declare (not safe))
    (define gx#current-expander-context (make-parameter '#f))
    (define gx#current-expander-marks (make-parameter '()))
    (define gx#current-expander-phi (make-parameter '0))
    (define gx#current-expander-path (make-parameter '()))
    (define gx#current-expander-eval (make-parameter '#f))
    (define gx#current-expander-compile (make-parameter '#f))
    (define gx#current-expander-module-eval (make-parameter '#f))
    (define gx#current-expander-module-import (make-parameter '#f))
    (define gx#current-expander-module-prelude (make-parameter '#f))
    (define gx#current-expander-allow-rebind? (make-parameter '#f))
    (define gx#current-expander-compiling? (make-parameter '#f))
    (define gx#current-compilation-target (make-parameter '#f))
    (define gx#expander-context::t
      (make-class-type
       'gx#expander-context::t
       'expander-context
       (list)
       '(id table)
       (cons (cons 'struct: '#t) '((print: id)))
       ':init!))
    (define gx#expander-context?
      (__make-class-predicate gx#expander-context::t))
    (define gx#make-expander-context
      (lambda _%$args189870%_
        (apply make-instance gx#expander-context::t _%$args189870%_)))
    (define gx#expander-context-id
      (__make-class-slot-accessor gx#expander-context::t 'id))
    (define gx#expander-context-table
      (__make-class-slot-accessor gx#expander-context::t 'table))
    (define gx#expander-context-id-set!
      (__make-class-slot-mutator gx#expander-context::t 'id))
    (define gx#expander-context-table-set!
      (__make-class-slot-mutator gx#expander-context::t 'table))
    (define gx#&expander-context-id
      (__make-class-slot-unchecked-accessor gx#expander-context::t 'id))
    (define gx#&expander-context-table
      (__make-class-slot-unchecked-accessor gx#expander-context::t 'table))
    (define gx#&expander-context-id-set!
      (__make-class-slot-unchecked-mutator gx#expander-context::t 'id))
    (define gx#&expander-context-table-set!
      (__make-class-slot-unchecked-mutator gx#expander-context::t 'table))
    (define gx#root-context::t
      (make-class-type
       'gx#root-context::t
       'root-context
       (list gx#expander-context::t)
       '()
       (cons (cons 'struct: '#t) '())
       ':init!))
    (define gx#root-context? (__make-class-predicate gx#root-context::t))
    (define gx#make-root-context
      (lambda _%$args189867%_
        (apply make-instance gx#root-context::t _%$args189867%_)))
    (define gx#root-context-id
      (__make-class-slot-accessor gx#root-context::t 'id))
    (define gx#root-context-table
      (__make-class-slot-accessor gx#root-context::t 'table))
    (define gx#root-context-id-set!
      (__make-class-slot-mutator gx#root-context::t 'id))
    (define gx#root-context-table-set!
      (__make-class-slot-mutator gx#root-context::t 'table))
    (define gx#&root-context-id
      (__make-class-slot-unchecked-accessor gx#root-context::t 'id))
    (define gx#&root-context-table
      (__make-class-slot-unchecked-accessor gx#root-context::t 'table))
    (define gx#&root-context-id-set!
      (__make-class-slot-unchecked-mutator gx#root-context::t 'id))
    (define gx#&root-context-table-set!
      (__make-class-slot-unchecked-mutator gx#root-context::t 'table))
    (define gx#phi-context::t
      (make-class-type
       'gx#phi-context::t
       'phi-context
       (list gx#expander-context::t)
       '(super up down)
       (cons (cons 'struct: '#t) '((print:)))
       ':init!))
    (define gx#phi-context? (__make-class-predicate gx#phi-context::t))
    (define gx#make-phi-context
      (lambda _%$args189864%_
        (apply make-instance gx#phi-context::t _%$args189864%_)))
    (define gx#phi-context-super
      (__make-class-slot-accessor gx#phi-context::t 'super))
    (define gx#phi-context-up
      (__make-class-slot-accessor gx#phi-context::t 'up))
    (define gx#phi-context-down
      (__make-class-slot-accessor gx#phi-context::t 'down))
    (define gx#phi-context-id
      (__make-class-slot-accessor gx#phi-context::t 'id))
    (define gx#phi-context-table
      (__make-class-slot-accessor gx#phi-context::t 'table))
    (define gx#phi-context-super-set!
      (__make-class-slot-mutator gx#phi-context::t 'super))
    (define gx#phi-context-up-set!
      (__make-class-slot-mutator gx#phi-context::t 'up))
    (define gx#phi-context-down-set!
      (__make-class-slot-mutator gx#phi-context::t 'down))
    (define gx#phi-context-id-set!
      (__make-class-slot-mutator gx#phi-context::t 'id))
    (define gx#phi-context-table-set!
      (__make-class-slot-mutator gx#phi-context::t 'table))
    (define gx#&phi-context-super
      (__make-class-slot-unchecked-accessor gx#phi-context::t 'super))
    (define gx#&phi-context-up
      (__make-class-slot-unchecked-accessor gx#phi-context::t 'up))
    (define gx#&phi-context-down
      (__make-class-slot-unchecked-accessor gx#phi-context::t 'down))
    (define gx#&phi-context-id
      (__make-class-slot-unchecked-accessor gx#phi-context::t 'id))
    (define gx#&phi-context-table
      (__make-class-slot-unchecked-accessor gx#phi-context::t 'table))
    (define gx#&phi-context-super-set!
      (__make-class-slot-unchecked-mutator gx#phi-context::t 'super))
    (define gx#&phi-context-up-set!
      (__make-class-slot-unchecked-mutator gx#phi-context::t 'up))
    (define gx#&phi-context-down-set!
      (__make-class-slot-unchecked-mutator gx#phi-context::t 'down))
    (define gx#&phi-context-id-set!
      (__make-class-slot-unchecked-mutator gx#phi-context::t 'id))
    (define gx#&phi-context-table-set!
      (__make-class-slot-unchecked-mutator gx#phi-context::t 'table))
    (define gx#top-context::t
      (make-class-type
       'gx#top-context::t
       'top-context
       (list gx#phi-context::t)
       '()
       (cons (cons 'struct: '#t) '())
       ':init!))
    (define gx#top-context? (__make-class-predicate gx#top-context::t))
    (define gx#make-top-context
      (lambda _%$args189861%_
        (apply make-instance gx#top-context::t _%$args189861%_)))
    (define gx#top-context-super
      (__make-class-slot-accessor gx#top-context::t 'super))
    (define gx#top-context-up
      (__make-class-slot-accessor gx#top-context::t 'up))
    (define gx#top-context-down
      (__make-class-slot-accessor gx#top-context::t 'down))
    (define gx#top-context-id
      (__make-class-slot-accessor gx#top-context::t 'id))
    (define gx#top-context-table
      (__make-class-slot-accessor gx#top-context::t 'table))
    (define gx#top-context-super-set!
      (__make-class-slot-mutator gx#top-context::t 'super))
    (define gx#top-context-up-set!
      (__make-class-slot-mutator gx#top-context::t 'up))
    (define gx#top-context-down-set!
      (__make-class-slot-mutator gx#top-context::t 'down))
    (define gx#top-context-id-set!
      (__make-class-slot-mutator gx#top-context::t 'id))
    (define gx#top-context-table-set!
      (__make-class-slot-mutator gx#top-context::t 'table))
    (define gx#&top-context-super
      (__make-class-slot-unchecked-accessor gx#top-context::t 'super))
    (define gx#&top-context-up
      (__make-class-slot-unchecked-accessor gx#top-context::t 'up))
    (define gx#&top-context-down
      (__make-class-slot-unchecked-accessor gx#top-context::t 'down))
    (define gx#&top-context-id
      (__make-class-slot-unchecked-accessor gx#top-context::t 'id))
    (define gx#&top-context-table
      (__make-class-slot-unchecked-accessor gx#top-context::t 'table))
    (define gx#&top-context-super-set!
      (__make-class-slot-unchecked-mutator gx#top-context::t 'super))
    (define gx#&top-context-up-set!
      (__make-class-slot-unchecked-mutator gx#top-context::t 'up))
    (define gx#&top-context-down-set!
      (__make-class-slot-unchecked-mutator gx#top-context::t 'down))
    (define gx#&top-context-id-set!
      (__make-class-slot-unchecked-mutator gx#top-context::t 'id))
    (define gx#&top-context-table-set!
      (__make-class-slot-unchecked-mutator gx#top-context::t 'table))
    (define gx#module-context::t
      (make-class-type
       'gx#module-context::t
       'module-context
       (list gx#top-context::t)
       '(ns path import export e code)
       (cons (cons 'struct: '#t) '((print:)))
       ':init!))
    (define gx#module-context? (__make-class-predicate gx#module-context::t))
    (define gx#make-module-context
      (lambda _%$args189858%_
        (apply make-instance gx#module-context::t _%$args189858%_)))
    (define gx#module-context-ns
      (__make-class-slot-accessor gx#module-context::t 'ns))
    (define gx#module-context-path
      (__make-class-slot-accessor gx#module-context::t 'path))
    (define gx#module-context-import
      (__make-class-slot-accessor gx#module-context::t 'import))
    (define gx#module-context-export
      (__make-class-slot-accessor gx#module-context::t 'export))
    (define gx#module-context-e
      (__make-class-slot-accessor gx#module-context::t 'e))
    (define gx#module-context-code
      (__make-class-slot-accessor gx#module-context::t 'code))
    (define gx#module-context-super
      (__make-class-slot-accessor gx#module-context::t 'super))
    (define gx#module-context-up
      (__make-class-slot-accessor gx#module-context::t 'up))
    (define gx#module-context-down
      (__make-class-slot-accessor gx#module-context::t 'down))
    (define gx#module-context-id
      (__make-class-slot-accessor gx#module-context::t 'id))
    (define gx#module-context-table
      (__make-class-slot-accessor gx#module-context::t 'table))
    (define gx#module-context-ns-set!
      (__make-class-slot-mutator gx#module-context::t 'ns))
    (define gx#module-context-path-set!
      (__make-class-slot-mutator gx#module-context::t 'path))
    (define gx#module-context-import-set!
      (__make-class-slot-mutator gx#module-context::t 'import))
    (define gx#module-context-export-set!
      (__make-class-slot-mutator gx#module-context::t 'export))
    (define gx#module-context-e-set!
      (__make-class-slot-mutator gx#module-context::t 'e))
    (define gx#module-context-code-set!
      (__make-class-slot-mutator gx#module-context::t 'code))
    (define gx#module-context-super-set!
      (__make-class-slot-mutator gx#module-context::t 'super))
    (define gx#module-context-up-set!
      (__make-class-slot-mutator gx#module-context::t 'up))
    (define gx#module-context-down-set!
      (__make-class-slot-mutator gx#module-context::t 'down))
    (define gx#module-context-id-set!
      (__make-class-slot-mutator gx#module-context::t 'id))
    (define gx#module-context-table-set!
      (__make-class-slot-mutator gx#module-context::t 'table))
    (define gx#&module-context-ns
      (__make-class-slot-unchecked-accessor gx#module-context::t 'ns))
    (define gx#&module-context-path
      (__make-class-slot-unchecked-accessor gx#module-context::t 'path))
    (define gx#&module-context-import
      (__make-class-slot-unchecked-accessor gx#module-context::t 'import))
    (define gx#&module-context-export
      (__make-class-slot-unchecked-accessor gx#module-context::t 'export))
    (define gx#&module-context-e
      (__make-class-slot-unchecked-accessor gx#module-context::t 'e))
    (define gx#&module-context-code
      (__make-class-slot-unchecked-accessor gx#module-context::t 'code))
    (define gx#&module-context-super
      (__make-class-slot-unchecked-accessor gx#module-context::t 'super))
    (define gx#&module-context-up
      (__make-class-slot-unchecked-accessor gx#module-context::t 'up))
    (define gx#&module-context-down
      (__make-class-slot-unchecked-accessor gx#module-context::t 'down))
    (define gx#&module-context-id
      (__make-class-slot-unchecked-accessor gx#module-context::t 'id))
    (define gx#&module-context-table
      (__make-class-slot-unchecked-accessor gx#module-context::t 'table))
    (define gx#&module-context-ns-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'ns))
    (define gx#&module-context-path-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'path))
    (define gx#&module-context-import-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'import))
    (define gx#&module-context-export-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'export))
    (define gx#&module-context-e-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'e))
    (define gx#&module-context-code-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'code))
    (define gx#&module-context-super-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'super))
    (define gx#&module-context-up-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'up))
    (define gx#&module-context-down-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'down))
    (define gx#&module-context-id-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'id))
    (define gx#&module-context-table-set!
      (__make-class-slot-unchecked-mutator gx#module-context::t 'table))
    (define gx#prelude-context::t
      (make-class-type
       'gx#prelude-context::t
       'prelude-context
       (list gx#top-context::t)
       '(path import e)
       (cons (cons 'struct: '#t) '((print:)))
       ':init!))
    (define gx#prelude-context? (__make-class-predicate gx#prelude-context::t))
    (define gx#make-prelude-context
      (lambda _%$args189855%_
        (apply make-instance gx#prelude-context::t _%$args189855%_)))
    (define gx#prelude-context-path
      (__make-class-slot-accessor gx#prelude-context::t 'path))
    (define gx#prelude-context-import
      (__make-class-slot-accessor gx#prelude-context::t 'import))
    (define gx#prelude-context-e
      (__make-class-slot-accessor gx#prelude-context::t 'e))
    (define gx#prelude-context-super
      (__make-class-slot-accessor gx#prelude-context::t 'super))
    (define gx#prelude-context-up
      (__make-class-slot-accessor gx#prelude-context::t 'up))
    (define gx#prelude-context-down
      (__make-class-slot-accessor gx#prelude-context::t 'down))
    (define gx#prelude-context-id
      (__make-class-slot-accessor gx#prelude-context::t 'id))
    (define gx#prelude-context-table
      (__make-class-slot-accessor gx#prelude-context::t 'table))
    (define gx#prelude-context-path-set!
      (__make-class-slot-mutator gx#prelude-context::t 'path))
    (define gx#prelude-context-import-set!
      (__make-class-slot-mutator gx#prelude-context::t 'import))
    (define gx#prelude-context-e-set!
      (__make-class-slot-mutator gx#prelude-context::t 'e))
    (define gx#prelude-context-super-set!
      (__make-class-slot-mutator gx#prelude-context::t 'super))
    (define gx#prelude-context-up-set!
      (__make-class-slot-mutator gx#prelude-context::t 'up))
    (define gx#prelude-context-down-set!
      (__make-class-slot-mutator gx#prelude-context::t 'down))
    (define gx#prelude-context-id-set!
      (__make-class-slot-mutator gx#prelude-context::t 'id))
    (define gx#prelude-context-table-set!
      (__make-class-slot-mutator gx#prelude-context::t 'table))
    (define gx#&prelude-context-path
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'path))
    (define gx#&prelude-context-import
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'import))
    (define gx#&prelude-context-e
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'e))
    (define gx#&prelude-context-super
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'super))
    (define gx#&prelude-context-up
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'up))
    (define gx#&prelude-context-down
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'down))
    (define gx#&prelude-context-id
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'id))
    (define gx#&prelude-context-table
      (__make-class-slot-unchecked-accessor gx#prelude-context::t 'table))
    (define gx#&prelude-context-path-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'path))
    (define gx#&prelude-context-import-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'import))
    (define gx#&prelude-context-e-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'e))
    (define gx#&prelude-context-super-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'super))
    (define gx#&prelude-context-up-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'up))
    (define gx#&prelude-context-down-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'down))
    (define gx#&prelude-context-id-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'id))
    (define gx#&prelude-context-table-set!
      (__make-class-slot-unchecked-mutator gx#prelude-context::t 'table))
    (define gx#local-context::t
      (make-class-type
       'gx#local-context::t
       'local-context
       (list gx#phi-context::t)
       '()
       (cons (cons 'struct: '#t) '())
       ':init!))
    (define gx#local-context? (__make-class-predicate gx#local-context::t))
    (define gx#make-local-context
      (lambda _%$args189852%_
        (apply make-instance gx#local-context::t _%$args189852%_)))
    (define gx#local-context-super
      (__make-class-slot-accessor gx#local-context::t 'super))
    (define gx#local-context-up
      (__make-class-slot-accessor gx#local-context::t 'up))
    (define gx#local-context-down
      (__make-class-slot-accessor gx#local-context::t 'down))
    (define gx#local-context-id
      (__make-class-slot-accessor gx#local-context::t 'id))
    (define gx#local-context-table
      (__make-class-slot-accessor gx#local-context::t 'table))
    (define gx#local-context-super-set!
      (__make-class-slot-mutator gx#local-context::t 'super))
    (define gx#local-context-up-set!
      (__make-class-slot-mutator gx#local-context::t 'up))
    (define gx#local-context-down-set!
      (__make-class-slot-mutator gx#local-context::t 'down))
    (define gx#local-context-id-set!
      (__make-class-slot-mutator gx#local-context::t 'id))
    (define gx#local-context-table-set!
      (__make-class-slot-mutator gx#local-context::t 'table))
    (define gx#&local-context-super
      (__make-class-slot-unchecked-accessor gx#local-context::t 'super))
    (define gx#&local-context-up
      (__make-class-slot-unchecked-accessor gx#local-context::t 'up))
    (define gx#&local-context-down
      (__make-class-slot-unchecked-accessor gx#local-context::t 'down))
    (define gx#&local-context-id
      (__make-class-slot-unchecked-accessor gx#local-context::t 'id))
    (define gx#&local-context-table
      (__make-class-slot-unchecked-accessor gx#local-context::t 'table))
    (define gx#&local-context-super-set!
      (__make-class-slot-unchecked-mutator gx#local-context::t 'super))
    (define gx#&local-context-up-set!
      (__make-class-slot-unchecked-mutator gx#local-context::t 'up))
    (define gx#&local-context-down-set!
      (__make-class-slot-unchecked-mutator gx#local-context::t 'down))
    (define gx#&local-context-id-set!
      (__make-class-slot-unchecked-mutator gx#local-context::t 'id))
    (define gx#&local-context-table-set!
      (__make-class-slot-unchecked-mutator gx#local-context::t 'table))
    (define gx#phi-context:::init!__%
      (lambda (_%self189825%_ _%id189826%_ _%super189827%_)
        (let ((_%self189830%_ _%self189825%_))
          (if (##fx< '3 (##structure-length _%self189830%_))
              (begin
                (##unchecked-structure-set!
                 _%self189830%_
                 _%id189826%_
                 '1
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self189830%_
                 (make-hash-table-eq)
                 '2
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self189830%_
                 _%super189827%_
                 '3
                 '#f
                 '#f)
                '#!void)
              (error '"struct-instance-init!: too many arguments for struct"
                     _%self189830%_
                     '3
                     (##structure-length _%self189830%_))))))
    (define gx#phi-context:::init!__0
      (lambda (_%self189843%_ _%id189844%_)
        (let ((_%super189846%_ (gx#current-expander-context)))
          (gx#phi-context:::init!__%
           _%self189843%_
           _%id189844%_
           _%super189846%_))))
    (define gx#phi-context:::init!
      (lambda _g189912_
        (let ((_g189913_ (##length _g189912_)))
          (cond ((##fx= _g189913_ 2)
                 (apply gx#phi-context:::init!__0 _g189912_))
                ((##fx= _g189913_ 3)
                 (apply gx#phi-context:::init!__% _g189912_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#phi-context:::init!
                  _g189912_))))))
    (__bind-method!__% gx#phi-context::t ':init! gx#phi-context:::init! '#f)
    (define gx#local-context:::init!__%
      (lambda (_%self189678%_ _%super189679%_)
        (let ((_%self189682%_ _%self189678%_))
          (if (##fx< '3 (##structure-length _%self189682%_))
              (begin
                (##unchecked-structure-set!
                 _%self189682%_
                 (##gensym 'L)
                 '1
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self189682%_
                 (make-hash-table-eq)
                 '2
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self189682%_
                 _%super189679%_
                 '3
                 '#f
                 '#f)
                '#!void)
              (error '"struct-instance-init!: too many arguments for struct"
                     _%self189682%_
                     '3
                     (##structure-length _%self189682%_))))))
    (define gx#local-context:::init!__0
      (lambda (_%self189695%_)
        (let ((_%super189697%_ (gx#current-expander-context)))
          (gx#local-context:::init!__% _%self189695%_ _%super189697%_))))
    (define gx#local-context:::init!
      (lambda _g189914_
        (let ((_g189915_ (##length _g189914_)))
          (cond ((##fx= _g189915_ 1)
                 (apply gx#local-context:::init!__0 _g189914_))
                ((##fx= _g189915_ 2)
                 (apply gx#local-context:::init!__% _g189914_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#local-context:::init!
                  _g189914_))))))
    (__bind-method!__%
     gx#local-context::t
     ':init!
     gx#local-context:::init!
     '#f)
    (define gx#binding::t
      (make-class-type
       'gx#binding::t
       'binding
       (list)
       '(id key phi properties)
       (cons (cons 'struct: '#t) '((print: id)))
       ':init!))
    (define gx#binding? (__make-class-predicate gx#binding::t))
    (define gx#make-binding
      (lambda _%$args189552%_
        (apply make-instance gx#binding::t _%$args189552%_)))
    (define gx#binding-id (__make-class-slot-accessor gx#binding::t 'id))
    (define gx#binding-key (__make-class-slot-accessor gx#binding::t 'key))
    (define gx#binding-phi (__make-class-slot-accessor gx#binding::t 'phi))
    (define gx#binding-properties
      (__make-class-slot-accessor gx#binding::t 'properties))
    (define gx#binding-id-set! (__make-class-slot-mutator gx#binding::t 'id))
    (define gx#binding-key-set! (__make-class-slot-mutator gx#binding::t 'key))
    (define gx#binding-phi-set! (__make-class-slot-mutator gx#binding::t 'phi))
    (define gx#binding-properties-set!
      (__make-class-slot-mutator gx#binding::t 'properties))
    (define gx#&binding-id
      (__make-class-slot-unchecked-accessor gx#binding::t 'id))
    (define gx#&binding-key
      (__make-class-slot-unchecked-accessor gx#binding::t 'key))
    (define gx#&binding-phi
      (__make-class-slot-unchecked-accessor gx#binding::t 'phi))
    (define gx#&binding-properties
      (__make-class-slot-unchecked-accessor gx#binding::t 'properties))
    (define gx#&binding-id-set!
      (__make-class-slot-unchecked-mutator gx#binding::t 'id))
    (define gx#&binding-key-set!
      (__make-class-slot-unchecked-mutator gx#binding::t 'key))
    (define gx#&binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#binding::t 'phi))
    (define gx#&binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#binding::t 'properties))
    (define gx#binding:::init!
      (lambda (_%self189535%_ _%id189536%_ _%key189537%_ _%phi189538%_)
        (let ((_%self189541%_ _%self189535%_))
          (##unchecked-structure-set! _%self189541%_ _%id189536%_ '1 '#f '#f)
          (##unchecked-structure-set! _%self189541%_ _%key189537%_ '2 '#f '#f)
          (##unchecked-structure-set!
           _%self189541%_
           _%phi189538%_
           '3
           '#f
           '#f))))
    (__bind-method!__% gx#binding::t ':init! gx#binding:::init! '#f)
    (define gx#runtime-binding::t
      (make-class-type
       'gx#runtime-binding::t
       'runtime-binding
       (list gx#binding::t)
       '(type macro)
       (cons (cons 'struct: '#t) '((print:)))
       ':init!))
    (define gx#runtime-binding? (__make-class-predicate gx#runtime-binding::t))
    (define gx#make-runtime-binding
      (lambda _%$args189410%_
        (apply make-instance gx#runtime-binding::t _%$args189410%_)))
    (define gx#runtime-binding-type
      (__make-class-slot-accessor gx#runtime-binding::t 'type))
    (define gx#runtime-binding-macro
      (__make-class-slot-accessor gx#runtime-binding::t 'macro))
    (define gx#runtime-binding-id
      (__make-class-slot-accessor gx#runtime-binding::t 'id))
    (define gx#runtime-binding-key
      (__make-class-slot-accessor gx#runtime-binding::t 'key))
    (define gx#runtime-binding-phi
      (__make-class-slot-accessor gx#runtime-binding::t 'phi))
    (define gx#runtime-binding-properties
      (__make-class-slot-accessor gx#runtime-binding::t 'properties))
    (define gx#runtime-binding-type-set!
      (__make-class-slot-mutator gx#runtime-binding::t 'type))
    (define gx#runtime-binding-macro-set!
      (__make-class-slot-mutator gx#runtime-binding::t 'macro))
    (define gx#runtime-binding-id-set!
      (__make-class-slot-mutator gx#runtime-binding::t 'id))
    (define gx#runtime-binding-key-set!
      (__make-class-slot-mutator gx#runtime-binding::t 'key))
    (define gx#runtime-binding-phi-set!
      (__make-class-slot-mutator gx#runtime-binding::t 'phi))
    (define gx#runtime-binding-properties-set!
      (__make-class-slot-mutator gx#runtime-binding::t 'properties))
    (define gx#&runtime-binding-type
      (__make-class-slot-unchecked-accessor gx#runtime-binding::t 'type))
    (define gx#&runtime-binding-macro
      (__make-class-slot-unchecked-accessor gx#runtime-binding::t 'macro))
    (define gx#&runtime-binding-id
      (__make-class-slot-unchecked-accessor gx#runtime-binding::t 'id))
    (define gx#&runtime-binding-key
      (__make-class-slot-unchecked-accessor gx#runtime-binding::t 'key))
    (define gx#&runtime-binding-phi
      (__make-class-slot-unchecked-accessor gx#runtime-binding::t 'phi))
    (define gx#&runtime-binding-properties
      (__make-class-slot-unchecked-accessor gx#runtime-binding::t 'properties))
    (define gx#&runtime-binding-type-set!
      (__make-class-slot-unchecked-mutator gx#runtime-binding::t 'type))
    (define gx#&runtime-binding-macro-set!
      (__make-class-slot-unchecked-mutator gx#runtime-binding::t 'macro))
    (define gx#&runtime-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#runtime-binding::t 'id))
    (define gx#&runtime-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#runtime-binding::t 'key))
    (define gx#&runtime-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#runtime-binding::t 'phi))
    (define gx#&runtime-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#runtime-binding::t 'properties))
    (define gx#local-binding::t
      (make-class-type
       'gx#local-binding::t
       'local-binding
       (list gx#runtime-binding::t)
       '()
       (cons (cons 'struct: '#t) '())
       ':init!))
    (define gx#local-binding? (__make-class-predicate gx#local-binding::t))
    (define gx#make-local-binding
      (lambda _%$args189407%_
        (apply make-instance gx#local-binding::t _%$args189407%_)))
    (define gx#local-binding-type
      (__make-class-slot-accessor gx#local-binding::t 'type))
    (define gx#local-binding-macro
      (__make-class-slot-accessor gx#local-binding::t 'macro))
    (define gx#local-binding-id
      (__make-class-slot-accessor gx#local-binding::t 'id))
    (define gx#local-binding-key
      (__make-class-slot-accessor gx#local-binding::t 'key))
    (define gx#local-binding-phi
      (__make-class-slot-accessor gx#local-binding::t 'phi))
    (define gx#local-binding-properties
      (__make-class-slot-accessor gx#local-binding::t 'properties))
    (define gx#local-binding-type-set!
      (__make-class-slot-mutator gx#local-binding::t 'type))
    (define gx#local-binding-macro-set!
      (__make-class-slot-mutator gx#local-binding::t 'macro))
    (define gx#local-binding-id-set!
      (__make-class-slot-mutator gx#local-binding::t 'id))
    (define gx#local-binding-key-set!
      (__make-class-slot-mutator gx#local-binding::t 'key))
    (define gx#local-binding-phi-set!
      (__make-class-slot-mutator gx#local-binding::t 'phi))
    (define gx#local-binding-properties-set!
      (__make-class-slot-mutator gx#local-binding::t 'properties))
    (define gx#&local-binding-type
      (__make-class-slot-unchecked-accessor gx#local-binding::t 'type))
    (define gx#&local-binding-macro
      (__make-class-slot-unchecked-accessor gx#local-binding::t 'macro))
    (define gx#&local-binding-id
      (__make-class-slot-unchecked-accessor gx#local-binding::t 'id))
    (define gx#&local-binding-key
      (__make-class-slot-unchecked-accessor gx#local-binding::t 'key))
    (define gx#&local-binding-phi
      (__make-class-slot-unchecked-accessor gx#local-binding::t 'phi))
    (define gx#&local-binding-properties
      (__make-class-slot-unchecked-accessor gx#local-binding::t 'properties))
    (define gx#&local-binding-type-set!
      (__make-class-slot-unchecked-mutator gx#local-binding::t 'type))
    (define gx#&local-binding-macro-set!
      (__make-class-slot-unchecked-mutator gx#local-binding::t 'macro))
    (define gx#&local-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#local-binding::t 'id))
    (define gx#&local-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#local-binding::t 'key))
    (define gx#&local-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#local-binding::t 'phi))
    (define gx#&local-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#local-binding::t 'properties))
    (define gx#top-binding::t
      (make-class-type
       'gx#top-binding::t
       'top-binding
       (list gx#runtime-binding::t)
       '()
       (cons (cons 'struct: '#t) '())
       ':init!))
    (define gx#top-binding? (__make-class-predicate gx#top-binding::t))
    (define gx#make-top-binding
      (lambda _%$args189404%_
        (apply make-instance gx#top-binding::t _%$args189404%_)))
    (define gx#top-binding-type
      (__make-class-slot-accessor gx#top-binding::t 'type))
    (define gx#top-binding-macro
      (__make-class-slot-accessor gx#top-binding::t 'macro))
    (define gx#top-binding-id
      (__make-class-slot-accessor gx#top-binding::t 'id))
    (define gx#top-binding-key
      (__make-class-slot-accessor gx#top-binding::t 'key))
    (define gx#top-binding-phi
      (__make-class-slot-accessor gx#top-binding::t 'phi))
    (define gx#top-binding-properties
      (__make-class-slot-accessor gx#top-binding::t 'properties))
    (define gx#top-binding-type-set!
      (__make-class-slot-mutator gx#top-binding::t 'type))
    (define gx#top-binding-macro-set!
      (__make-class-slot-mutator gx#top-binding::t 'macro))
    (define gx#top-binding-id-set!
      (__make-class-slot-mutator gx#top-binding::t 'id))
    (define gx#top-binding-key-set!
      (__make-class-slot-mutator gx#top-binding::t 'key))
    (define gx#top-binding-phi-set!
      (__make-class-slot-mutator gx#top-binding::t 'phi))
    (define gx#top-binding-properties-set!
      (__make-class-slot-mutator gx#top-binding::t 'properties))
    (define gx#&top-binding-type
      (__make-class-slot-unchecked-accessor gx#top-binding::t 'type))
    (define gx#&top-binding-macro
      (__make-class-slot-unchecked-accessor gx#top-binding::t 'macro))
    (define gx#&top-binding-id
      (__make-class-slot-unchecked-accessor gx#top-binding::t 'id))
    (define gx#&top-binding-key
      (__make-class-slot-unchecked-accessor gx#top-binding::t 'key))
    (define gx#&top-binding-phi
      (__make-class-slot-unchecked-accessor gx#top-binding::t 'phi))
    (define gx#&top-binding-properties
      (__make-class-slot-unchecked-accessor gx#top-binding::t 'properties))
    (define gx#&top-binding-type-set!
      (__make-class-slot-unchecked-mutator gx#top-binding::t 'type))
    (define gx#&top-binding-macro-set!
      (__make-class-slot-unchecked-mutator gx#top-binding::t 'macro))
    (define gx#&top-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#top-binding::t 'id))
    (define gx#&top-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#top-binding::t 'key))
    (define gx#&top-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#top-binding::t 'phi))
    (define gx#&top-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#top-binding::t 'properties))
    (define gx#module-binding::t
      (make-class-type
       'gx#module-binding::t
       'module-binding
       (list gx#top-binding::t)
       '(context)
       (cons (cons 'struct: '#t) '((print:)))
       ':init!))
    (define gx#module-binding? (__make-class-predicate gx#module-binding::t))
    (define gx#make-module-binding
      (lambda _%$args189401%_
        (apply make-instance gx#module-binding::t _%$args189401%_)))
    (define gx#module-binding-context
      (__make-class-slot-accessor gx#module-binding::t 'context))
    (define gx#module-binding-type
      (__make-class-slot-accessor gx#module-binding::t 'type))
    (define gx#module-binding-macro
      (__make-class-slot-accessor gx#module-binding::t 'macro))
    (define gx#module-binding-id
      (__make-class-slot-accessor gx#module-binding::t 'id))
    (define gx#module-binding-key
      (__make-class-slot-accessor gx#module-binding::t 'key))
    (define gx#module-binding-phi
      (__make-class-slot-accessor gx#module-binding::t 'phi))
    (define gx#module-binding-properties
      (__make-class-slot-accessor gx#module-binding::t 'properties))
    (define gx#module-binding-context-set!
      (__make-class-slot-mutator gx#module-binding::t 'context))
    (define gx#module-binding-type-set!
      (__make-class-slot-mutator gx#module-binding::t 'type))
    (define gx#module-binding-macro-set!
      (__make-class-slot-mutator gx#module-binding::t 'macro))
    (define gx#module-binding-id-set!
      (__make-class-slot-mutator gx#module-binding::t 'id))
    (define gx#module-binding-key-set!
      (__make-class-slot-mutator gx#module-binding::t 'key))
    (define gx#module-binding-phi-set!
      (__make-class-slot-mutator gx#module-binding::t 'phi))
    (define gx#module-binding-properties-set!
      (__make-class-slot-mutator gx#module-binding::t 'properties))
    (define gx#&module-binding-context
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'context))
    (define gx#&module-binding-type
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'type))
    (define gx#&module-binding-macro
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'macro))
    (define gx#&module-binding-id
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'id))
    (define gx#&module-binding-key
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'key))
    (define gx#&module-binding-phi
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'phi))
    (define gx#&module-binding-properties
      (__make-class-slot-unchecked-accessor gx#module-binding::t 'properties))
    (define gx#&module-binding-context-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'context))
    (define gx#&module-binding-type-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'type))
    (define gx#&module-binding-macro-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'macro))
    (define gx#&module-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'id))
    (define gx#&module-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'key))
    (define gx#&module-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'phi))
    (define gx#&module-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#module-binding::t 'properties))
    (define gx#extern-binding::t
      (make-class-type
       'gx#extern-binding::t
       'extern-binding
       (list gx#top-binding::t)
       '()
       (cons (cons 'struct: '#t) '())
       ':init!))
    (define gx#extern-binding? (__make-class-predicate gx#extern-binding::t))
    (define gx#make-extern-binding
      (lambda _%$args189398%_
        (apply make-instance gx#extern-binding::t _%$args189398%_)))
    (define gx#extern-binding-type
      (__make-class-slot-accessor gx#extern-binding::t 'type))
    (define gx#extern-binding-macro
      (__make-class-slot-accessor gx#extern-binding::t 'macro))
    (define gx#extern-binding-id
      (__make-class-slot-accessor gx#extern-binding::t 'id))
    (define gx#extern-binding-key
      (__make-class-slot-accessor gx#extern-binding::t 'key))
    (define gx#extern-binding-phi
      (__make-class-slot-accessor gx#extern-binding::t 'phi))
    (define gx#extern-binding-properties
      (__make-class-slot-accessor gx#extern-binding::t 'properties))
    (define gx#extern-binding-type-set!
      (__make-class-slot-mutator gx#extern-binding::t 'type))
    (define gx#extern-binding-macro-set!
      (__make-class-slot-mutator gx#extern-binding::t 'macro))
    (define gx#extern-binding-id-set!
      (__make-class-slot-mutator gx#extern-binding::t 'id))
    (define gx#extern-binding-key-set!
      (__make-class-slot-mutator gx#extern-binding::t 'key))
    (define gx#extern-binding-phi-set!
      (__make-class-slot-mutator gx#extern-binding::t 'phi))
    (define gx#extern-binding-properties-set!
      (__make-class-slot-mutator gx#extern-binding::t 'properties))
    (define gx#&extern-binding-type
      (__make-class-slot-unchecked-accessor gx#extern-binding::t 'type))
    (define gx#&extern-binding-macro
      (__make-class-slot-unchecked-accessor gx#extern-binding::t 'macro))
    (define gx#&extern-binding-id
      (__make-class-slot-unchecked-accessor gx#extern-binding::t 'id))
    (define gx#&extern-binding-key
      (__make-class-slot-unchecked-accessor gx#extern-binding::t 'key))
    (define gx#&extern-binding-phi
      (__make-class-slot-unchecked-accessor gx#extern-binding::t 'phi))
    (define gx#&extern-binding-properties
      (__make-class-slot-unchecked-accessor gx#extern-binding::t 'properties))
    (define gx#&extern-binding-type-set!
      (__make-class-slot-unchecked-mutator gx#extern-binding::t 'type))
    (define gx#&extern-binding-macro-set!
      (__make-class-slot-unchecked-mutator gx#extern-binding::t 'macro))
    (define gx#&extern-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#extern-binding::t 'id))
    (define gx#&extern-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#extern-binding::t 'key))
    (define gx#&extern-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#extern-binding::t 'phi))
    (define gx#&extern-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#extern-binding::t 'properties))
    (define gx#runtime-binding:::init! gx#binding:::init!)
    (__bind-method!__%
     gx#runtime-binding::t
     ':init!
     gx#runtime-binding:::init!
     '#f)
    (define gx#local-binding:::init! gx#binding:::init!)
    (__bind-method!__%
     gx#local-binding::t
     ':init!
     gx#local-binding:::init!
     '#f)
    (define gx#top-binding:::init! gx#binding:::init!)
    (__bind-method!__% gx#top-binding::t ':init! gx#top-binding:::init! '#f)
    (define gx#module-binding:::init!
      (lambda (_%self189014%_
               _%id189015%_
               _%key189016%_
               _%phi189017%_
               _%ctx189018%_)
        (let ((_%self189021%_ _%self189014%_))
          (gx#binding:::init!
           _%self189021%_
           _%id189015%_
           _%key189016%_
           _%phi189017%_)
          (##unchecked-structure-set!
           _%self189021%_
           _%ctx189018%_
           '7
           '#f
           '#f))))
    (__bind-method!__%
     gx#module-binding::t
     ':init!
     gx#module-binding:::init!
     '#f)
    (define gx#extern-binding:::init! gx#binding:::init!)
    (__bind-method!__%
     gx#extern-binding::t
     ':init!
     gx#extern-binding:::init!
     '#f)
    (define gx#syntax-binding::t
      (make-class-type
       'gx#syntax-binding::t
       'syntax-binding
       (list gx#binding::t)
       '(e)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print:))))
       ':init!))
    (define gx#syntax-binding? (__make-class-predicate gx#syntax-binding::t))
    (define gx#make-syntax-binding
      (lambda _%$args188767%_
        (apply make-instance gx#syntax-binding::t _%$args188767%_)))
    (define gx#syntax-binding-e
      (__make-class-slot-accessor gx#syntax-binding::t 'e))
    (define gx#syntax-binding-id
      (__make-class-slot-accessor gx#syntax-binding::t 'id))
    (define gx#syntax-binding-key
      (__make-class-slot-accessor gx#syntax-binding::t 'key))
    (define gx#syntax-binding-phi
      (__make-class-slot-accessor gx#syntax-binding::t 'phi))
    (define gx#syntax-binding-properties
      (__make-class-slot-accessor gx#syntax-binding::t 'properties))
    (define gx#syntax-binding-e-set!
      (__make-class-slot-mutator gx#syntax-binding::t 'e))
    (define gx#syntax-binding-id-set!
      (__make-class-slot-mutator gx#syntax-binding::t 'id))
    (define gx#syntax-binding-key-set!
      (__make-class-slot-mutator gx#syntax-binding::t 'key))
    (define gx#syntax-binding-phi-set!
      (__make-class-slot-mutator gx#syntax-binding::t 'phi))
    (define gx#syntax-binding-properties-set!
      (__make-class-slot-mutator gx#syntax-binding::t 'properties))
    (define gx#&syntax-binding-e
      (__make-class-slot-unchecked-accessor gx#syntax-binding::t 'e))
    (define gx#&syntax-binding-id
      (__make-class-slot-unchecked-accessor gx#syntax-binding::t 'id))
    (define gx#&syntax-binding-key
      (__make-class-slot-unchecked-accessor gx#syntax-binding::t 'key))
    (define gx#&syntax-binding-phi
      (__make-class-slot-unchecked-accessor gx#syntax-binding::t 'phi))
    (define gx#&syntax-binding-properties
      (__make-class-slot-unchecked-accessor gx#syntax-binding::t 'properties))
    (define gx#&syntax-binding-e-set!
      (__make-class-slot-unchecked-mutator gx#syntax-binding::t 'e))
    (define gx#&syntax-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#syntax-binding::t 'id))
    (define gx#&syntax-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#syntax-binding::t 'key))
    (define gx#&syntax-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#syntax-binding::t 'phi))
    (define gx#&syntax-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#syntax-binding::t 'properties))
    (define gx#import-binding::t
      (make-class-type
       'gx#import-binding::t
       'import-binding
       (list gx#binding::t)
       '(e context weak?)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print:))))
       ':init!))
    (define gx#import-binding? (__make-class-predicate gx#import-binding::t))
    (define gx#make-import-binding
      (lambda _%$args188764%_
        (apply make-instance gx#import-binding::t _%$args188764%_)))
    (define gx#import-binding-e
      (__make-class-slot-accessor gx#import-binding::t 'e))
    (define gx#import-binding-context
      (__make-class-slot-accessor gx#import-binding::t 'context))
    (define gx#import-binding-weak?
      (__make-class-slot-accessor gx#import-binding::t 'weak?))
    (define gx#import-binding-id
      (__make-class-slot-accessor gx#import-binding::t 'id))
    (define gx#import-binding-key
      (__make-class-slot-accessor gx#import-binding::t 'key))
    (define gx#import-binding-phi
      (__make-class-slot-accessor gx#import-binding::t 'phi))
    (define gx#import-binding-properties
      (__make-class-slot-accessor gx#import-binding::t 'properties))
    (define gx#import-binding-e-set!
      (__make-class-slot-mutator gx#import-binding::t 'e))
    (define gx#import-binding-context-set!
      (__make-class-slot-mutator gx#import-binding::t 'context))
    (define gx#import-binding-weak?-set!
      (__make-class-slot-mutator gx#import-binding::t 'weak?))
    (define gx#import-binding-id-set!
      (__make-class-slot-mutator gx#import-binding::t 'id))
    (define gx#import-binding-key-set!
      (__make-class-slot-mutator gx#import-binding::t 'key))
    (define gx#import-binding-phi-set!
      (__make-class-slot-mutator gx#import-binding::t 'phi))
    (define gx#import-binding-properties-set!
      (__make-class-slot-mutator gx#import-binding::t 'properties))
    (define gx#&import-binding-e
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'e))
    (define gx#&import-binding-context
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'context))
    (define gx#&import-binding-weak?
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'weak?))
    (define gx#&import-binding-id
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'id))
    (define gx#&import-binding-key
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'key))
    (define gx#&import-binding-phi
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'phi))
    (define gx#&import-binding-properties
      (__make-class-slot-unchecked-accessor gx#import-binding::t 'properties))
    (define gx#&import-binding-e-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'e))
    (define gx#&import-binding-context-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'context))
    (define gx#&import-binding-weak?-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'weak?))
    (define gx#&import-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'id))
    (define gx#&import-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'key))
    (define gx#&import-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'phi))
    (define gx#&import-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#import-binding::t 'properties))
    (define gx#alias-binding::t
      (make-class-type
       'gx#alias-binding::t
       'alias-binding
       (list gx#binding::t)
       '(e)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print: e))))
       ':init!))
    (define gx#alias-binding? (__make-class-predicate gx#alias-binding::t))
    (define gx#make-alias-binding
      (lambda _%$args188761%_
        (apply make-instance gx#alias-binding::t _%$args188761%_)))
    (define gx#alias-binding-e
      (__make-class-slot-accessor gx#alias-binding::t 'e))
    (define gx#alias-binding-id
      (__make-class-slot-accessor gx#alias-binding::t 'id))
    (define gx#alias-binding-key
      (__make-class-slot-accessor gx#alias-binding::t 'key))
    (define gx#alias-binding-phi
      (__make-class-slot-accessor gx#alias-binding::t 'phi))
    (define gx#alias-binding-properties
      (__make-class-slot-accessor gx#alias-binding::t 'properties))
    (define gx#alias-binding-e-set!
      (__make-class-slot-mutator gx#alias-binding::t 'e))
    (define gx#alias-binding-id-set!
      (__make-class-slot-mutator gx#alias-binding::t 'id))
    (define gx#alias-binding-key-set!
      (__make-class-slot-mutator gx#alias-binding::t 'key))
    (define gx#alias-binding-phi-set!
      (__make-class-slot-mutator gx#alias-binding::t 'phi))
    (define gx#alias-binding-properties-set!
      (__make-class-slot-mutator gx#alias-binding::t 'properties))
    (define gx#&alias-binding-e
      (__make-class-slot-unchecked-accessor gx#alias-binding::t 'e))
    (define gx#&alias-binding-id
      (__make-class-slot-unchecked-accessor gx#alias-binding::t 'id))
    (define gx#&alias-binding-key
      (__make-class-slot-unchecked-accessor gx#alias-binding::t 'key))
    (define gx#&alias-binding-phi
      (__make-class-slot-unchecked-accessor gx#alias-binding::t 'phi))
    (define gx#&alias-binding-properties
      (__make-class-slot-unchecked-accessor gx#alias-binding::t 'properties))
    (define gx#&alias-binding-e-set!
      (__make-class-slot-unchecked-mutator gx#alias-binding::t 'e))
    (define gx#&alias-binding-id-set!
      (__make-class-slot-unchecked-mutator gx#alias-binding::t 'id))
    (define gx#&alias-binding-key-set!
      (__make-class-slot-unchecked-mutator gx#alias-binding::t 'key))
    (define gx#&alias-binding-phi-set!
      (__make-class-slot-unchecked-mutator gx#alias-binding::t 'phi))
    (define gx#&alias-binding-properties-set!
      (__make-class-slot-unchecked-mutator gx#alias-binding::t 'properties))
    (define gx#syntax-binding:::init!
      (lambda (_%self188743%_
               _%id188744%_
               _%key188745%_
               _%phi188746%_
               _%e188747%_)
        (let ((_%self188750%_ _%self188743%_))
          (gx#binding:::init!
           _%self188750%_
           _%id188744%_
           _%key188745%_
           _%phi188746%_)
          (##unchecked-structure-set! _%self188750%_ _%e188747%_ '5 '#f '#f))))
    (__bind-method!__%
     gx#syntax-binding::t
     ':init!
     gx#syntax-binding:::init!
     '#f)
    (define gx#import-binding:::init!
      (lambda (_%self188601%_
               _%id188602%_
               _%key188603%_
               _%phi188604%_
               _%e188605%_
               _%ctx188606%_
               _%weak?188607%_)
        (let ((_%self188610%_ _%self188601%_))
          (gx#binding:::init!
           _%self188610%_
           _%id188602%_
           _%key188603%_
           _%phi188604%_)
          (##unchecked-structure-set! _%self188610%_ _%e188605%_ '5 '#f '#f)
          (##unchecked-structure-set! _%self188610%_ _%ctx188606%_ '6 '#f '#f)
          (##unchecked-structure-set!
           _%self188610%_
           _%weak?188607%_
           '7
           '#f
           '#f))))
    (__bind-method!__%
     gx#import-binding::t
     ':init!
     gx#import-binding:::init!
     '#f)
    (define gx#alias-binding:::init!
      (lambda (_%self188461%_
               _%id188462%_
               _%key188463%_
               _%phi188464%_
               _%e188465%_)
        (let ((_%self188468%_ _%self188461%_))
          (gx#binding:::init!
           _%self188468%_
           _%id188462%_
           _%key188463%_
           _%phi188464%_)
          (##unchecked-structure-set! _%self188468%_ _%e188465%_ '5 '#f '#f))))
    (__bind-method!__%
     gx#alias-binding::t
     ':init!
     gx#alias-binding:::init!
     '#f)
    (define gx#expander::t
      (make-class-type
       'gx#expander::t
       'expander
       (list)
       '(e)
       (cons (cons 'struct: '#t) '((print:)))
       '#f))
    (define gx#expander? (__make-class-predicate gx#expander::t))
    (define gx#make-expander
      (lambda _%$args188336%_
        (apply make-instance gx#expander::t _%$args188336%_)))
    (define gx#expander-e (__make-class-slot-accessor gx#expander::t 'e))
    (define gx#expander-e-set! (__make-class-slot-mutator gx#expander::t 'e))
    (define gx#&expander-e
      (__make-class-slot-unchecked-accessor gx#expander::t 'e))
    (define gx#&expander-e-set!
      (__make-class-slot-unchecked-mutator gx#expander::t 'e))
    (define gx#core-expander::t
      (make-class-type
       'gx#core-expander::t
       'core-expander
       (list gx#expander::t)
       '(id compile-top)
       (cons (cons 'struct: '#t) '((print: id)))
       '#f))
    (define gx#core-expander? (__make-class-predicate gx#core-expander::t))
    (define gx#make-core-expander
      (lambda _%$args188333%_
        (apply make-instance gx#core-expander::t _%$args188333%_)))
    (define gx#core-expander-id
      (__make-class-slot-accessor gx#core-expander::t 'id))
    (define gx#core-expander-compile-top
      (__make-class-slot-accessor gx#core-expander::t 'compile-top))
    (define gx#core-expander-e
      (__make-class-slot-accessor gx#core-expander::t 'e))
    (define gx#core-expander-id-set!
      (__make-class-slot-mutator gx#core-expander::t 'id))
    (define gx#core-expander-compile-top-set!
      (__make-class-slot-mutator gx#core-expander::t 'compile-top))
    (define gx#core-expander-e-set!
      (__make-class-slot-mutator gx#core-expander::t 'e))
    (define gx#&core-expander-id
      (__make-class-slot-unchecked-accessor gx#core-expander::t 'id))
    (define gx#&core-expander-compile-top
      (__make-class-slot-unchecked-accessor gx#core-expander::t 'compile-top))
    (define gx#&core-expander-e
      (__make-class-slot-unchecked-accessor gx#core-expander::t 'e))
    (define gx#&core-expander-id-set!
      (__make-class-slot-unchecked-mutator gx#core-expander::t 'id))
    (define gx#&core-expander-compile-top-set!
      (__make-class-slot-unchecked-mutator gx#core-expander::t 'compile-top))
    (define gx#&core-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#core-expander::t 'e))
    (define gx#expression-form::t
      (make-class-type
       'gx#expression-form::t
       'expression-form
       (list gx#core-expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#expression-form? (__make-class-predicate gx#expression-form::t))
    (define gx#make-expression-form
      (lambda _%$args188330%_
        (apply make-instance gx#expression-form::t _%$args188330%_)))
    (define gx#expression-form-id
      (__make-class-slot-accessor gx#expression-form::t 'id))
    (define gx#expression-form-compile-top
      (__make-class-slot-accessor gx#expression-form::t 'compile-top))
    (define gx#expression-form-e
      (__make-class-slot-accessor gx#expression-form::t 'e))
    (define gx#expression-form-id-set!
      (__make-class-slot-mutator gx#expression-form::t 'id))
    (define gx#expression-form-compile-top-set!
      (__make-class-slot-mutator gx#expression-form::t 'compile-top))
    (define gx#expression-form-e-set!
      (__make-class-slot-mutator gx#expression-form::t 'e))
    (define gx#&expression-form-id
      (__make-class-slot-unchecked-accessor gx#expression-form::t 'id))
    (define gx#&expression-form-compile-top
      (__make-class-slot-unchecked-accessor
       gx#expression-form::t
       'compile-top))
    (define gx#&expression-form-e
      (__make-class-slot-unchecked-accessor gx#expression-form::t 'e))
    (define gx#&expression-form-id-set!
      (__make-class-slot-unchecked-mutator gx#expression-form::t 'id))
    (define gx#&expression-form-compile-top-set!
      (__make-class-slot-unchecked-mutator gx#expression-form::t 'compile-top))
    (define gx#&expression-form-e-set!
      (__make-class-slot-unchecked-mutator gx#expression-form::t 'e))
    (define gx#special-form::t
      (make-class-type
       'gx#special-form::t
       'special-form
       (list gx#core-expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#special-form? (__make-class-predicate gx#special-form::t))
    (define gx#make-special-form
      (lambda _%$args188327%_
        (apply make-instance gx#special-form::t _%$args188327%_)))
    (define gx#special-form-id
      (__make-class-slot-accessor gx#special-form::t 'id))
    (define gx#special-form-compile-top
      (__make-class-slot-accessor gx#special-form::t 'compile-top))
    (define gx#special-form-e
      (__make-class-slot-accessor gx#special-form::t 'e))
    (define gx#special-form-id-set!
      (__make-class-slot-mutator gx#special-form::t 'id))
    (define gx#special-form-compile-top-set!
      (__make-class-slot-mutator gx#special-form::t 'compile-top))
    (define gx#special-form-e-set!
      (__make-class-slot-mutator gx#special-form::t 'e))
    (define gx#&special-form-id
      (__make-class-slot-unchecked-accessor gx#special-form::t 'id))
    (define gx#&special-form-compile-top
      (__make-class-slot-unchecked-accessor gx#special-form::t 'compile-top))
    (define gx#&special-form-e
      (__make-class-slot-unchecked-accessor gx#special-form::t 'e))
    (define gx#&special-form-id-set!
      (__make-class-slot-unchecked-mutator gx#special-form::t 'id))
    (define gx#&special-form-compile-top-set!
      (__make-class-slot-unchecked-mutator gx#special-form::t 'compile-top))
    (define gx#&special-form-e-set!
      (__make-class-slot-unchecked-mutator gx#special-form::t 'e))
    (define gx#definition-form::t
      (make-class-type
       'gx#definition-form::t
       'definition-form
       (list gx#special-form::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#definition-form? (__make-class-predicate gx#definition-form::t))
    (define gx#make-definition-form
      (lambda _%$args188324%_
        (apply make-instance gx#definition-form::t _%$args188324%_)))
    (define gx#definition-form-id
      (__make-class-slot-accessor gx#definition-form::t 'id))
    (define gx#definition-form-compile-top
      (__make-class-slot-accessor gx#definition-form::t 'compile-top))
    (define gx#definition-form-e
      (__make-class-slot-accessor gx#definition-form::t 'e))
    (define gx#definition-form-id-set!
      (__make-class-slot-mutator gx#definition-form::t 'id))
    (define gx#definition-form-compile-top-set!
      (__make-class-slot-mutator gx#definition-form::t 'compile-top))
    (define gx#definition-form-e-set!
      (__make-class-slot-mutator gx#definition-form::t 'e))
    (define gx#&definition-form-id
      (__make-class-slot-unchecked-accessor gx#definition-form::t 'id))
    (define gx#&definition-form-compile-top
      (__make-class-slot-unchecked-accessor
       gx#definition-form::t
       'compile-top))
    (define gx#&definition-form-e
      (__make-class-slot-unchecked-accessor gx#definition-form::t 'e))
    (define gx#&definition-form-id-set!
      (__make-class-slot-unchecked-mutator gx#definition-form::t 'id))
    (define gx#&definition-form-compile-top-set!
      (__make-class-slot-unchecked-mutator gx#definition-form::t 'compile-top))
    (define gx#&definition-form-e-set!
      (__make-class-slot-unchecked-mutator gx#definition-form::t 'e))
    (define gx#top-special-form::t
      (make-class-type
       'gx#top-special-form::t
       'top-special-form
       (list gx#special-form::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#top-special-form?
      (__make-class-predicate gx#top-special-form::t))
    (define gx#make-top-special-form
      (lambda _%$args188321%_
        (apply make-instance gx#top-special-form::t _%$args188321%_)))
    (define gx#top-special-form-id
      (__make-class-slot-accessor gx#top-special-form::t 'id))
    (define gx#top-special-form-compile-top
      (__make-class-slot-accessor gx#top-special-form::t 'compile-top))
    (define gx#top-special-form-e
      (__make-class-slot-accessor gx#top-special-form::t 'e))
    (define gx#top-special-form-id-set!
      (__make-class-slot-mutator gx#top-special-form::t 'id))
    (define gx#top-special-form-compile-top-set!
      (__make-class-slot-mutator gx#top-special-form::t 'compile-top))
    (define gx#top-special-form-e-set!
      (__make-class-slot-mutator gx#top-special-form::t 'e))
    (define gx#&top-special-form-id
      (__make-class-slot-unchecked-accessor gx#top-special-form::t 'id))
    (define gx#&top-special-form-compile-top
      (__make-class-slot-unchecked-accessor
       gx#top-special-form::t
       'compile-top))
    (define gx#&top-special-form-e
      (__make-class-slot-unchecked-accessor gx#top-special-form::t 'e))
    (define gx#&top-special-form-id-set!
      (__make-class-slot-unchecked-mutator gx#top-special-form::t 'id))
    (define gx#&top-special-form-compile-top-set!
      (__make-class-slot-unchecked-mutator
       gx#top-special-form::t
       'compile-top))
    (define gx#&top-special-form-e-set!
      (__make-class-slot-unchecked-mutator gx#top-special-form::t 'e))
    (define gx#module-special-form::t
      (make-class-type
       'gx#module-special-form::t
       'module-special-form
       (list gx#top-special-form::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#module-special-form?
      (__make-class-predicate gx#module-special-form::t))
    (define gx#make-module-special-form
      (lambda _%$args188318%_
        (apply make-instance gx#module-special-form::t _%$args188318%_)))
    (define gx#module-special-form-id
      (__make-class-slot-accessor gx#module-special-form::t 'id))
    (define gx#module-special-form-compile-top
      (__make-class-slot-accessor gx#module-special-form::t 'compile-top))
    (define gx#module-special-form-e
      (__make-class-slot-accessor gx#module-special-form::t 'e))
    (define gx#module-special-form-id-set!
      (__make-class-slot-mutator gx#module-special-form::t 'id))
    (define gx#module-special-form-compile-top-set!
      (__make-class-slot-mutator gx#module-special-form::t 'compile-top))
    (define gx#module-special-form-e-set!
      (__make-class-slot-mutator gx#module-special-form::t 'e))
    (define gx#&module-special-form-id
      (__make-class-slot-unchecked-accessor gx#module-special-form::t 'id))
    (define gx#&module-special-form-compile-top
      (__make-class-slot-unchecked-accessor
       gx#module-special-form::t
       'compile-top))
    (define gx#&module-special-form-e
      (__make-class-slot-unchecked-accessor gx#module-special-form::t 'e))
    (define gx#&module-special-form-id-set!
      (__make-class-slot-unchecked-mutator gx#module-special-form::t 'id))
    (define gx#&module-special-form-compile-top-set!
      (__make-class-slot-unchecked-mutator
       gx#module-special-form::t
       'compile-top))
    (define gx#&module-special-form-e-set!
      (__make-class-slot-unchecked-mutator gx#module-special-form::t 'e))
    (define gx#feature-expander::t
      (make-class-type
       'gx#feature-expander::t
       'feature-expander
       (list gx#expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#feature-expander?
      (__make-class-predicate gx#feature-expander::t))
    (define gx#make-feature-expander
      (lambda _%$args188315%_
        (apply make-instance gx#feature-expander::t _%$args188315%_)))
    (define gx#feature-expander-e
      (__make-class-slot-accessor gx#feature-expander::t 'e))
    (define gx#feature-expander-e-set!
      (__make-class-slot-mutator gx#feature-expander::t 'e))
    (define gx#&feature-expander-e
      (__make-class-slot-unchecked-accessor gx#feature-expander::t 'e))
    (define gx#&feature-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#feature-expander::t 'e))
    (define gx#private-feature-expander::t
      (make-class-type
       'gx#private-feature-expander::t
       'private-feature-expander
       (list gx#feature-expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#private-feature-expander?
      (__make-class-predicate gx#private-feature-expander::t))
    (define gx#make-private-feature-expander
      (lambda _%$args188312%_
        (apply make-instance gx#private-feature-expander::t _%$args188312%_)))
    (define gx#private-feature-expander-e
      (__make-class-slot-accessor gx#private-feature-expander::t 'e))
    (define gx#private-feature-expander-e-set!
      (__make-class-slot-mutator gx#private-feature-expander::t 'e))
    (define gx#&private-feature-expander-e
      (__make-class-slot-unchecked-accessor gx#private-feature-expander::t 'e))
    (define gx#&private-feature-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#private-feature-expander::t 'e))
    (define gx#reserved-expander::t
      (make-class-type
       'gx#reserved-expander::t
       'reserved-expander
       (list gx#expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#reserved-expander?
      (__make-class-predicate gx#reserved-expander::t))
    (define gx#make-reserved-expander
      (lambda _%$args188309%_
        (apply make-instance gx#reserved-expander::t _%$args188309%_)))
    (define gx#reserved-expander-e
      (__make-class-slot-accessor gx#reserved-expander::t 'e))
    (define gx#reserved-expander-e-set!
      (__make-class-slot-mutator gx#reserved-expander::t 'e))
    (define gx#&reserved-expander-e
      (__make-class-slot-unchecked-accessor gx#reserved-expander::t 'e))
    (define gx#&reserved-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#reserved-expander::t 'e))
    (define gx#macro-expander::t
      (make-class-type
       'gx#macro-expander::t
       'macro-expander
       (list gx#expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#macro-expander? (__make-class-predicate gx#macro-expander::t))
    (define gx#make-macro-expander
      (lambda _%$args188306%_
        (apply make-instance gx#macro-expander::t _%$args188306%_)))
    (define gx#macro-expander-e
      (__make-class-slot-accessor gx#macro-expander::t 'e))
    (define gx#macro-expander-e-set!
      (__make-class-slot-mutator gx#macro-expander::t 'e))
    (define gx#&macro-expander-e
      (__make-class-slot-unchecked-accessor gx#macro-expander::t 'e))
    (define gx#&macro-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#macro-expander::t 'e))
    (define gx#rename-macro-expander::t
      (make-class-type
       'gx#rename-macro-expander::t
       'rename-macro-expander
       (list gx#macro-expander::t)
       '()
       (cons (cons 'struct: '#t) '())
       '#f))
    (define gx#rename-macro-expander?
      (__make-class-predicate gx#rename-macro-expander::t))
    (define gx#make-rename-macro-expander
      (lambda _%$args188303%_
        (apply make-instance gx#rename-macro-expander::t _%$args188303%_)))
    (define gx#rename-macro-expander-e
      (__make-class-slot-accessor gx#rename-macro-expander::t 'e))
    (define gx#rename-macro-expander-e-set!
      (__make-class-slot-mutator gx#rename-macro-expander::t 'e))
    (define gx#&rename-macro-expander-e
      (__make-class-slot-unchecked-accessor gx#rename-macro-expander::t 'e))
    (define gx#&rename-macro-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#rename-macro-expander::t 'e))
    (define gx#user-expander::t
      (make-class-type
       'gx#user-expander::t
       'user-expander
       (list gx#macro-expander::t)
       '(context phi)
       (cons (cons 'struct: '#t) '((print:)))
       '#f))
    (define gx#user-expander? (__make-class-predicate gx#user-expander::t))
    (define gx#make-user-expander
      (lambda _%$args188300%_
        (apply make-instance gx#user-expander::t _%$args188300%_)))
    (define gx#user-expander-context
      (__make-class-slot-accessor gx#user-expander::t 'context))
    (define gx#user-expander-phi
      (__make-class-slot-accessor gx#user-expander::t 'phi))
    (define gx#user-expander-e
      (__make-class-slot-accessor gx#user-expander::t 'e))
    (define gx#user-expander-context-set!
      (__make-class-slot-mutator gx#user-expander::t 'context))
    (define gx#user-expander-phi-set!
      (__make-class-slot-mutator gx#user-expander::t 'phi))
    (define gx#user-expander-e-set!
      (__make-class-slot-mutator gx#user-expander::t 'e))
    (define gx#&user-expander-context
      (__make-class-slot-unchecked-accessor gx#user-expander::t 'context))
    (define gx#&user-expander-phi
      (__make-class-slot-unchecked-accessor gx#user-expander::t 'phi))
    (define gx#&user-expander-e
      (__make-class-slot-unchecked-accessor gx#user-expander::t 'e))
    (define gx#&user-expander-context-set!
      (__make-class-slot-unchecked-mutator gx#user-expander::t 'context))
    (define gx#&user-expander-phi-set!
      (__make-class-slot-unchecked-mutator gx#user-expander::t 'phi))
    (define gx#&user-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#user-expander::t 'e))
    (define gx#expander-mark::t
      (make-class-type
       'gx#expander-mark::t
       'expander-mark
       (list)
       '(subst context phi trace)
       (cons (cons 'struct: '#t) '((print:)))
       '#f))
    (define gx#expander-mark? (__make-class-predicate gx#expander-mark::t))
    (define gx#make-expander-mark
      (lambda _%$args188297%_
        (apply make-instance gx#expander-mark::t _%$args188297%_)))
    (define gx#expander-mark-subst
      (__make-class-slot-accessor gx#expander-mark::t 'subst))
    (define gx#expander-mark-context
      (__make-class-slot-accessor gx#expander-mark::t 'context))
    (define gx#expander-mark-phi
      (__make-class-slot-accessor gx#expander-mark::t 'phi))
    (define gx#expander-mark-trace
      (__make-class-slot-accessor gx#expander-mark::t 'trace))
    (define gx#expander-mark-subst-set!
      (__make-class-slot-mutator gx#expander-mark::t 'subst))
    (define gx#expander-mark-context-set!
      (__make-class-slot-mutator gx#expander-mark::t 'context))
    (define gx#expander-mark-phi-set!
      (__make-class-slot-mutator gx#expander-mark::t 'phi))
    (define gx#expander-mark-trace-set!
      (__make-class-slot-mutator gx#expander-mark::t 'trace))
    (define gx#&expander-mark-subst
      (__make-class-slot-unchecked-accessor gx#expander-mark::t 'subst))
    (define gx#&expander-mark-context
      (__make-class-slot-unchecked-accessor gx#expander-mark::t 'context))
    (define gx#&expander-mark-phi
      (__make-class-slot-unchecked-accessor gx#expander-mark::t 'phi))
    (define gx#&expander-mark-trace
      (__make-class-slot-unchecked-accessor gx#expander-mark::t 'trace))
    (define gx#&expander-mark-subst-set!
      (__make-class-slot-unchecked-mutator gx#expander-mark::t 'subst))
    (define gx#&expander-mark-context-set!
      (__make-class-slot-unchecked-mutator gx#expander-mark::t 'context))
    (define gx#&expander-mark-phi-set!
      (__make-class-slot-unchecked-mutator gx#expander-mark::t 'phi))
    (define gx#&expander-mark-trace-set!
      (__make-class-slot-unchecked-mutator gx#expander-mark::t 'trace))
    (define gx#raise-syntax-error
      (lambda (_%ctx188281%_
               _%message188282%_
               _%stx188283%_
               .
               _%details188284%_)
        (let ((_%ctx188295%_
               (let ((_%$e188286%_ _%ctx188281%_))
                 (if _%$e188286%_
                     _%$e188286%_
                     (let ((_%$e188289%_ (gx#core-context-top__0)))
                       (if _%$e188289%_
                           (list 'expand
                                 (##structure-ref
                                  _%$e188289%_
                                  '1
                                  gx#expander-context::t
                                  '#f))
                           '#f))))))
          (raise (make-syntax-error
                  _%message188282%_
                  (cons _%stx188283%_ _%details188284%_)
                  _%ctx188295%_
                  (gx#current-expander-context)
                  (gx#current-expander-marks)
                  (gx#current-expander-phi))))))
    (define gx#eval-syntax__%
      (lambda (_%stx188268%_ _%expression?188269%_)
        (gx#eval-syntax*
         (gx#core-expand__% _%stx188268%_ _%expression?188269%_))))
    (define gx#eval-syntax__0
      (lambda (_%stx188274%_)
        (let ((_%expression?188276%_ '#f))
          (gx#eval-syntax__% _%stx188274%_ _%expression?188276%_))))
    (define gx#eval-syntax
      (lambda _g189916_
        (let ((_g189917_ (##length _g189916_)))
          (cond ((##fx= _g189917_ 1) (apply gx#eval-syntax__0 _g189916_))
                ((##fx= _g189917_ 2) (apply gx#eval-syntax__% _g189916_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#eval-syntax
                  _g189916_))))))
    (define gx#eval-syntax+1__%
      (lambda (_%stx188253%_ _%expression?188254%_)
        (call-with-parameters__1
         (lambda () (gx#eval-syntax__% _%stx188253%_ _%expression?188254%_))
         gx#current-expander-phi
         (##fx+ (gx#current-expander-phi) '1))))
    (define gx#eval-syntax+1__0
      (lambda (_%stx188260%_)
        (let ((_%expression?188262%_ '#f))
          (gx#eval-syntax+1__% _%stx188260%_ _%expression?188262%_))))
    (define gx#eval-syntax+1
      (lambda _g189918_
        (let ((_g189919_ (##length _g189918_)))
          (cond ((##fx= _g189919_ 1) (apply gx#eval-syntax+1__0 _g189918_))
                ((##fx= _g189919_ 2) (apply gx#eval-syntax+1__% _g189918_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#eval-syntax+1
                  _g189918_))))))
    (define gx#eval-expression+1
      (lambda (_%stx188250%_) (gx#eval-syntax+1__% _%stx188250%_ '#t)))
    (define gx#eval-syntax*
      (lambda (_%stx188248%_)
        ((gx#current-expander-eval)
         ((gx#current-expander-compile) _%stx188248%_))))
    (define gx#core-expand__%
      (lambda (_%stx188235%_ _%expression?188236%_)
        (if _%expression?188236%_
            (gx#core-expand-expression _%stx188235%_)
            (gx#core-expand-top _%stx188235%_))))
    (define gx#core-expand__0
      (lambda (_%stx188241%_)
        (let ((_%expression?188243%_ '#f))
          (gx#core-expand__% _%stx188241%_ _%expression?188243%_))))
    (define gx#core-expand
      (lambda _g189920_
        (let ((_g189921_ (##length _g189920_)))
          (cond ((##fx= _g189921_ 1) (apply gx#core-expand__0 _g189920_))
                ((##fx= _g189921_ 2) (apply gx#core-expand__% _g189920_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand
                  _g189920_))))))
    (define gx#core-expand-top
      (lambda (_%stx188202%_)
        (let* ((_%stx188204%_ (gx#core-expand*__0 _%stx188202%_))
               (_%$%e188205188212%_ _%stx188204%_)
               (_%$%E188207188216%_
                (lambda () (gx#core-expand-expression _%stx188204%_)))
               (_%$%E188206188230%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e188205188212%_)
                      (let ((_%$%e188208188220%_
                             (gx#syntax-e _%$%e188205188212%_)))
                        (let ((_%$%hd188209188223%_
                               (##car _%$%e188208188220%_))
                              (_%$%tl188210188225%_
                               (##cdr _%$%e188208188220%_)))
                          (let ((_%form188228%_ _%$%hd188209188223%_))
                            (if (gx#core-bound-identifier?__0 _%form188228%_)
                                _%stx188204%_
                                (_%$%E188207188216%_)))))
                      (_%$%E188207188216%_)))))
          (_%$%E188206188230%_))))
    (define gx#core-expand-expression
      (lambda (_%stx188134%_)
        (letrec ((_%sealed-expression?188136%_
                  (lambda (_%hd188172%_)
                    (if (gx#sealed-syntax? _%hd188172%_)
                        (let* ((_%$%e188173188180%_ _%hd188172%_)
                               (_%$%E188175188184%_ (lambda () '#f))
                               (_%$%E188174188198%_
                                (lambda ()
                                  (if (gx#stx-pair? _%$%e188173188180%_)
                                      (let ((_%$%e188176188188%_
                                             (gx#syntax-e
                                              _%$%e188173188180%_)))
                                        (let ((_%$%hd188177188191%_
                                               (##car _%$%e188176188188%_))
                                              (_%$%tl188178188193%_
                                               (##cdr _%$%e188176188188%_)))
                                          (let ((_%form188196%_
                                                 _%$%hd188177188191%_))
                                            (gx#core-bound-identifier?__%
                                             _%form188196%_
                                             gx#expression-form-binding?))))
                                      (_%$%E188175188184%_)))))
                          (_%$%E188174188198%_))
                        '#f)))
                 (_%illegal-expression188137%_
                  (lambda (_%hd188169%_ . _%_188170%_)
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; illegal expression"
                     _%stx188134%_
                     _%hd188169%_)))
                 (_%expand-e188138%_
                  (lambda (_%form188161%_ _%hd188162%_)
                    (let ((_%bind188164%_
                           (if (##structure-instance-of?
                                _%form188161%_
                                'gx#binding::t)
                               _%form188161%_
                               (gx#resolve-identifier__0 _%form188161%_))))
                      (if (gx#core-expander-binding? _%bind188164%_)
                          (gx#core-apply-expander__0
                           (##unchecked-structure-ref
                            _%bind188164%_
                            '5
                            '#f
                            '#f)
                           (gx#stx-wrap-source
                            _%hd188162%_
                            (gx#stx-source _%stx188134%_)))
                          (if (##structure-direct-instance-of?
                               _%bind188164%_
                               'gx#syntax-binding::t)
                              (gx#core-expand-expression
                               (gx#core-apply-expander__0
                                (##unchecked-structure-ref
                                 _%bind188164%_
                                 '5
                                 '#f
                                 '#f)
                                (gx#stx-wrap-source
                                 _%hd188162%_
                                 (gx#stx-source _%stx188134%_))))
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; missing expander"
                               _%stx188134%_
                               _%form188161%_)))))))
          (let ((_%hd188140%_ (gx#core-expand-head _%stx188134%_)))
            (if (_%sealed-expression?188136%_ _%hd188140%_)
                _%hd188140%_
                (if (gx#stx-pair? _%hd188140%_)
                    (let* ((_%form188144%_ (gx#stx-car _%hd188140%_))
                           (_%bind188146%_
                            (if (gx#identifier? _%form188144%_)
                                (gx#resolve-identifier__0 _%form188144%_)
                                '#f)))
                      (if (or (not _%bind188146%_)
                              (not (gx#core-expander-binding? _%bind188146%_)))
                          (_%expand-e188138%_
                           '%%app
                           (cons '%%app _%hd188140%_))
                          (if (eq? (##unchecked-structure-ref
                                    _%bind188146%_
                                    '1
                                    '#f
                                    '#f)
                                   '%#begin)
                              (gx#core-expand-block*
                               _%hd188140%_
                               _%illegal-expression188137%_)
                              (if (gx#expression-form-binding? _%bind188146%_)
                                  (_%expand-e188138%_
                                   _%bind188146%_
                                   _%hd188140%_)
                                  (if (gx#direct-special-form-binding?
                                       _%bind188146%_)
                                      (gx#core-expand-expression
                                       (_%expand-e188138%_
                                        _%bind188146%_
                                        _%hd188140%_))
                                      (_%illegal-expression188137%_
                                       _%hd188140%_))))))
                    (if (gx#core-bound-identifier?__0 _%hd188140%_)
                        (_%illegal-expression188137%_ _%hd188140%_)
                        (if (gx#identifier? _%hd188140%_)
                            (_%expand-e188138%_
                             '%%ref
                             (cons '%%ref (cons _%hd188140%_ '())))
                            (if (gx#stx-datum? _%hd188140%_)
                                (_%expand-e188138%_
                                 '%#quote
                                 (cons '%#quote (cons _%hd188140%_ '())))
                                (_%illegal-expression188137%_
                                 _%hd188140%_))))))))))
    (define gx#core-expand-expression+1
      (lambda (_%stx188129%_)
        (call-with-parameters__1
         (lambda ()
           (let ((_%stx188132%_ (gx#core-expand-expression _%stx188129%_)))
             (values _%stx188132%_ (gx#eval-syntax* _%stx188132%_))))
         gx#current-expander-phi
         (##fx+ (gx#current-expander-phi) '1))))
    (define gx#core-expand*__%
      (lambda (_%stx188110%_ _%stop?188111%_)
        (let _%lp188113%_ ((_%stx188115%_ _%stx188110%_))
          (if (_%stop?188111%_ _%stx188115%_)
              _%stx188115%_
              (let ((_%rstx188117%_ (gx#core-expand1 _%stx188115%_)))
                (if (eq? _%stx188115%_ _%rstx188117%_)
                    _%stx188115%_
                    (_%lp188113%_ _%rstx188117%_)))))))
    (define gx#core-expand*__0
      (lambda (_%stx188122%_)
        (let ((_%stop?188124%_ false))
          (gx#core-expand*__% _%stx188122%_ _%stop?188124%_))))
    (define gx#core-expand*
      (lambda _g189922_
        (let ((_g189923_ (##length _g189922_)))
          (cond ((##fx= _g189923_ 1) (apply gx#core-expand*__0 _g189922_))
                ((##fx= _g189923_ 2) (apply gx#core-expand*__% _g189922_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand*
                  _g189922_))))))
    (define gx#core-expand1
      (lambda (_%stx188062%_)
        (letrec ((_%step188064%_
                  (lambda (_%hd188101%_)
                    (let ((_%bind188103%_
                           (gx#resolve-identifier__0 _%hd188101%_)))
                      (if (##structure-instance-of?
                           _%bind188103%_
                           'gx#runtime-binding::t)
                          _%stx188062%_
                          (if (##structure-direct-instance-of?
                               _%bind188103%_
                               'gx#syntax-binding::t)
                              (gx#core-apply-expander__0
                               (##unchecked-structure-ref
                                _%bind188103%_
                                '5
                                '#f
                                '#f)
                               _%stx188062%_)
                              (if _%bind188103%_
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; no binding for head"
                                   _%stx188062%_)
                                  _%stx188062%_)))))))
          (let* ((_%$%e188065188073%_ _%stx188062%_)
                 (_%$%E188071188077%_ (lambda () _%stx188062%_))
                 (_%$%E188067188083%_
                  (lambda ()
                    (let ((_%hd188081%_ _%$%e188065188073%_))
                      (if (gx#identifier? _%hd188081%_)
                          (_%step188064%_ _%hd188081%_)
                          (_%$%E188071188077%_)))))
                 (_%$%E188066188097%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e188065188073%_)
                        (let ((_%$%e188068188087%_
                               (gx#syntax-e _%$%e188065188073%_)))
                          (let ((_%$%hd188069188090%_
                                 (##car _%$%e188068188087%_))
                                (_%$%tl188070188092%_
                                 (##cdr _%$%e188068188087%_)))
                            (let ((_%hd188095%_ _%$%hd188069188090%_))
                              (if (gx#identifier? _%hd188095%_)
                                  (_%step188064%_ _%hd188095%_)
                                  (_%$%E188067188083%_)))))
                        (_%$%E188067188083%_)))))
            (_%$%E188066188097%_)))))
    (define gx#core-expand-head
      (lambda (_%stx188028%_)
        (letrec ((_%stop?188030%_
                  (lambda (_%stx188032%_)
                    (let* ((_%$%e188033188040%_ _%stx188032%_)
                           (_%$%E188035188044%_ (lambda () '#f))
                           (_%$%E188034188058%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e188033188040%_)
                                  (let ((_%$%e188036188048%_
                                         (gx#syntax-e _%$%e188033188040%_)))
                                    (let ((_%$%hd188037188051%_
                                           (##car _%$%e188036188048%_))
                                          (_%$%tl188038188053%_
                                           (##cdr _%$%e188036188048%_)))
                                      (let ((_%hd188056%_
                                             _%$%hd188037188051%_))
                                        (gx#core-bound-identifier?__0
                                         _%hd188056%_))))
                                  (_%$%E188035188044%_)))))
                      (_%$%E188034188058%_)))))
          (gx#core-expand*__% _%stx188028%_ _%stop?188030%_))))
    (define gx#core-expand-block__%
      (lambda (_%stx187834%_
               _%expand-special187835%_
               _%begin-form187836%_
               _%expand-e187837%_)
        (letrec ((_%expand-splice187839%_
                  (lambda (_%hd188002%_
                           _%body188003%_
                           _%rest188004%_
                           _%r188005%_)
                    (if (gx#stx-list? _%body188003%_)
                        (_%K187843%_
                         (gx#stx-foldr cons _%rest188004%_ _%body188003%_)
                         _%r188005%_)
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; splice body isn't a list"
                         _%stx187834%_
                         _%hd188002%_))))
                 (_%expand-cond-expand187840%_
                  (lambda (_%hd187998%_ _%rest187999%_ _%r188000%_)
                    (_%K187843%_
                     (cons (gx#core-expand-cond-expand% _%hd187998%_)
                           _%rest187999%_)
                     _%r188000%_)))
                 (_%expand-include187841%_
                  (lambda (_%hd187947%_ _%rest187948%_ _%r187949%_)
                    (let* ((_%$%e187950187960%_ _%hd187947%_)
                           (_%$%E187952187964%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e187950187960%_)))
                           (_%$%E187951187994%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e187950187960%_)
                                  (let ((_%$%e187953187968%_
                                         (gx#syntax-e _%$%e187950187960%_)))
                                    (let ((_%$%hd187954187971%_
                                           (##car _%$%e187953187968%_))
                                          (_%$%tl187955187973%_
                                           (##cdr _%$%e187953187968%_)))
                                      (if (gx#stx-pair? _%$%tl187955187973%_)
                                          (let ((_%$%e187956187976%_
                                                 (gx#syntax-e
                                                  _%$%tl187955187973%_)))
                                            (let ((_%$%hd187957187979%_
                                                   (##car _%$%e187956187976%_))
                                                  (_%$%tl187958187981%_
                                                   (##cdr _%$%e187956187976%_)))
                                              (let ((_%path187984%_
                                                     _%$%hd187957187979%_))
                                                (if (gx#stx-null?
                                                     _%$%tl187958187981%_)
                                                    (if (gx#stx-string?
                                                         _%path187984%_)
                                                        (let* ((_%rpath187986%_
                                                                (gx#core-resolve-path__%
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%path187984%_
                         (gx#stx-source _%hd187947%_)))
                       (_%block187988%_
                        (gx#core-expand-include%__%
                         _%hd187947%_
                         _%rpath187986%_))
                       (_%rbody187991%_
                        (call-with-parameters__1
                         (lambda ()
                           (gx#core-expand-block__%
                            _%block187988%_
                            _%expand-special187835%_
                            '#f
                            _%expand-e187837%_))
                         gx#current-expander-path
                         (cons _%rpath187986%_ (gx#current-expander-path)))))
                  (_%K187843%_
                   _%rest187948%_
                   (append _%rbody187991%_ _%r187949%_)))
                (_%$%E187952187964%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%E187952187964%_)))))
                                          (_%$%E187952187964%_))))
                                  (_%$%E187952187964%_)))))
                      (_%$%E187951187994%_))))
                 (_%expand-expression187842%_
                  (lambda (_%hd187943%_ _%rest187944%_ _%r187945%_)
                    (_%K187843%_
                     _%rest187944%_
                     (cons (_%expand-e187837%_ _%hd187943%_) _%r187945%_))))
                 (_%K187843%_
                  (lambda (_%rest187873%_ _%r187874%_)
                    (let* ((_%$%e187875187882%_ _%rest187873%_)
                           (_%$%E187877187886%_
                            (lambda ()
                              (if _%begin-form187836%_
                                  (gx#core-quote-syntax__1
                                   (gx#core-cons
                                    _%begin-form187836%_
                                    (reverse _%r187874%_))
                                   (gx#stx-source _%stx187834%_))
                                  _%r187874%_)))
                           (_%$%E187876187939%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e187875187882%_)
                                  (let ((_%$%e187878187890%_
                                         (gx#syntax-e _%$%e187875187882%_)))
                                    (let ((_%$%hd187879187893%_
                                           (##car _%$%e187878187890%_))
                                          (_%$%tl187880187895%_
                                           (##cdr _%$%e187878187890%_)))
                                      (let* ((_%hd187898%_
                                              _%$%hd187879187893%_)
                                             (_%rest187900%_
                                              _%$%tl187880187895%_)
                                             (_%hd187902%_
                                              (gx#core-expand-head
                                               _%hd187898%_))
                                             (_%$%e187903187910%_ _%hd187902%_)
                                             (_%$%E187905187914%_
                                              (lambda ()
                                                (_%expand-expression187842%_
                                                 _%hd187902%_
                                                 _%rest187900%_
                                                 _%r187874%_)))
                                             (_%$%E187904187935%_
                                              (lambda ()
                                                (if (gx#stx-pair?
                                                     _%$%e187903187910%_)
                                                    (let ((_%$%e187906187918%_
                                                           (gx#syntax-e
                                                            _%$%e187903187910%_)))
                                                      (let ((_%$%hd187907187921%_
                                                             (##car _%$%e187906187918%_))
                                                            (_%$%tl187908187923%_
                                                             (##cdr _%$%e187906187918%_)))
                                                        (let* ((_%form187926%_
                                                                _%$%hd187907187921%_)
                                                               (_%body187928%_
                                                                _%$%tl187908187923%_)
                                                               (_%bind187930%_
                                                                (if (gx#identifier?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%form187926%_)
                            (gx#resolve-identifier__0 _%form187926%_)
                            '#f)))
                  (if (gx#special-form-binding? _%bind187930%_)
                      (let ((_%$e187932%_
                             (##unchecked-structure-ref
                              _%bind187930%_
                              '1
                              '#f
                              '#f)))
                        (if (eq? '%#begin _%$e187932%_)
                            (_%expand-splice187839%_
                             _%hd187902%_
                             _%body187928%_
                             _%rest187900%_
                             _%r187874%_)
                            (if (eq? '%#cond-expand _%$e187932%_)
                                (_%expand-cond-expand187840%_
                                 _%hd187902%_
                                 _%rest187900%_
                                 _%r187874%_)
                                (if (eq? '%#include _%$e187932%_)
                                    (_%expand-include187841%_
                                     _%hd187902%_
                                     _%rest187900%_
                                     _%r187874%_)
                                    (_%expand-special187835%_
                                     _%hd187902%_
                                     _%K187843%_
                                     _%rest187900%_
                                     _%r187874%_)))))
                      (_%expand-expression187842%_
                       _%hd187902%_
                       _%rest187900%_
                       _%r187874%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%E187905187914%_)))))
                                        (_%$%E187904187935%_))))
                                  (_%$%E187877187886%_)))))
                      (_%$%E187876187939%_)))))
          (let* ((_%$%e187844187851%_ _%stx187834%_)
                 (_%$%E187846187855%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e187844187851%_)))
                 (_%$%E187845187869%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e187844187851%_)
                        (let ((_%$%e187847187859%_
                               (gx#syntax-e _%$%e187844187851%_)))
                          (let ((_%$%hd187848187862%_
                                 (##car _%$%e187847187859%_))
                                (_%$%tl187849187864%_
                                 (##cdr _%$%e187847187859%_)))
                            (let ((_%body187867%_ _%$%tl187849187864%_))
                              (if (gx#stx-list? _%body187867%_)
                                  (_%K187843%_ _%body187867%_ '())
                                  (_%$%E187846187855%_)))))
                        (_%$%E187846187855%_)))))
            (_%$%E187845187869%_)))))
    (define gx#core-expand-block__0
      (lambda (_%stx188010%_ _%expand-special188011%_)
        (let* ((_%begin-form188013%_ '%#begin)
               (_%expand-e188015%_ gx#core-expand-expression))
          (gx#core-expand-block__%
           _%stx188010%_
           _%expand-special188011%_
           _%begin-form188013%_
           _%expand-e188015%_))))
    (define gx#core-expand-block__1
      (lambda (_%stx188017%_ _%expand-special188018%_ _%begin-form188019%_)
        (let ((_%expand-e188021%_ gx#core-expand-expression))
          (gx#core-expand-block__%
           _%stx188017%_
           _%expand-special188018%_
           _%begin-form188019%_
           _%expand-e188021%_))))
    (define gx#core-expand-block
      (lambda _g189924_
        (let ((_g189925_ (##length _g189924_)))
          (cond ((##fx= _g189925_ 2) (apply gx#core-expand-block__0 _g189924_))
                ((##fx= _g189925_ 3) (apply gx#core-expand-block__1 _g189924_))
                ((##fx= _g189925_ 4) (apply gx#core-expand-block__% _g189924_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-block
                  _g189924_))))))
    (define gx#core-expand-block*
      (lambda (_%stx187782%_ _%expand-special187783%_)
        (let* ((_%$%g187784187795%_
                (gx#core-expand-block__1
                 _%stx187782%_
                 _%expand-special187783%_
                 '#f))
               (_%$%E187788187799%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%g187784187795%_
                         '([])
                         '([expr])
                         '(body))
                  '#!void)))
          (let ((_%$%K187793187830%_
                 (lambda ()
                   (gx#raise-syntax-error
                    '#f
                    '"Bad syntax; empty block"
                    _%stx187782%_)))
                (_%$%K187790187816%_ (lambda (_%expr187814%_) _%expr187814%_))
                (_%$%K187789187805%_
                 (lambda (_%body187803%_)
                   (gx#core-quote-syntax__1
                    (gx#core-cons '%#begin (reverse _%body187803%_))
                    (gx#stx-source _%stx187782%_)))))
            (let ((_%$%try-match187786187826%_
                   (lambda ()
                     (if (pair? _%$%g187784187795%_)
                         (let ((_%$%tl187792187821%_
                                (##cdr _%$%g187784187795%_))
                               (_%$%hd187791187819%_
                                (##car _%$%g187784187795%_)))
                           (if (null? _%$%tl187792187821%_)
                               (let ((_%expr187824%_ _%$%hd187791187819%_))
                                 (_%$%K187790187816%_ _%expr187824%_))
                               (let ((_%body187808%_ _%$%g187784187795%_))
                                 (_%$%K187789187805%_ _%body187808%_))))
                         (let ((_%body187808%_ _%$%g187784187795%_))
                           (_%$%K187789187805%_ _%body187808%_))))))
              (if (null? _%$%g187784187795%_)
                  (_%$%K187793187830%_)
                  (_%$%try-match187786187826%_)))))))
    (define gx#core-expand-cond-expand%
      (lambda (_%stx187608%_)
        (letrec ((_%satisfied?187610%_
                  (lambda (_%condition187711%_)
                    (let* ((_%$%e187712187727%_ _%condition187711%_)
                           (_%$%E187722187731%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e187712187727%_)))
                           (_%$%E187715187750%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e187712187727%_)
                                  (let ((_%$%e187723187735%_
                                         (gx#syntax-e _%$%e187712187727%_)))
                                    (let ((_%$%hd187724187738%_
                                           (##car _%$%e187723187735%_))
                                          (_%$%tl187725187740%_
                                           (##cdr _%$%e187723187735%_)))
                                      (let* ((_%combinator187743%_
                                              _%$%hd187724187738%_)
                                             (_%body187745%_
                                              _%$%tl187725187740%_))
                                        (if (gx#stx-list? _%body187745%_)
                                            (let ((_%$e187747%_
                                                   (gx#stx-e
                                                    _%combinator187743%_)))
                                              (if (eq? 'not _%$e187747%_)
                                                  (not (gx#stx-ormap
                                                        _%satisfied?187610%_
                                                        _%body187745%_))
                                                  (if (eq? 'and _%$e187747%_)
                                                      (gx#stx-andmap
                                                       _%satisfied?187610%_
                                                       _%body187745%_)
                                                      (if (eq? 'or
                                                               _%$e187747%_)
                                                          (gx#stx-ormap
                                                           _%satisfied?187610%_
                                                           _%body187745%_)
                                                          (if (eq? 'defined
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$e187747%_)
                      (gx#stx-andmap gx#core-resolve-identifier _%body187745%_)
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; bad cond-expannd combinator"
                       _%stx187608%_
                       _%combinator187743%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%E187722187731%_)))))
                                  (_%$%E187722187731%_))))
                           (_%$%E187714187772%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e187712187727%_)
                                  (let ((_%$%e187716187754%_
                                         (gx#syntax-e _%$%e187712187727%_)))
                                    (let ((_%$%hd187717187757%_
                                           (##car _%$%e187716187754%_))
                                          (_%$%tl187718187759%_
                                           (##cdr _%$%e187716187754%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd187717187757%_)
                                               (gx#core-identifier=?
                                                _%$%hd187717187757%_
                                                'unquote))
                                          (if (gx#stx-pair?
                                               _%$%tl187718187759%_)
                                              (let ((_%$%e187719187762%_
                                                     (gx#syntax-e
                                                      _%$%tl187718187759%_)))
                                                (let ((_%$%hd187720187765%_
                                                       (##car _%$%e187719187762%_))
                                                      (_%$%tl187721187767%_
                                                       (##cdr _%$%e187719187762%_)))
                                                  (let ((_%expr187770%_
                                                         _%$%hd187720187765%_))
                                                    (if (gx#stx-null?
                                                         _%$%tl187721187767%_)
                                                        (gx#eval-syntax+1__0
                                                         _%expr187770%_)
                                                        (_%$%E187715187750%_)))))
                                              (_%$%E187715187750%_))
                                          (_%$%E187715187750%_))))
                                  (_%$%E187715187750%_))))
                           (_%$%E187713187778%_
                            (lambda ()
                              (let ((_%id187776%_ _%$%e187712187727%_))
                                (if (gx#identifier? _%id187776%_)
                                    (gx#core-bound-identifier?__%
                                     _%id187776%_
                                     gx#feature-binding?)
                                    (_%$%E187714187772%_))))))
                      (_%$%E187713187778%_))))
                 (_%loop187611%_
                  (lambda (_%rest187641%_)
                    (let* ((_%$%e187642187650%_ _%rest187641%_)
                           (_%$%E187648187654%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e187642187650%_)))
                           (_%$%E187644187658%_
                            (lambda ()
                              (if (gx#stx-null? _%$%e187642187650%_)
                                  '()
                                  (_%$%E187648187654%_))))
                           (_%$%E187643187707%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e187642187650%_)
                                  (let ((_%$%e187645187662%_
                                         (gx#syntax-e _%$%e187642187650%_)))
                                    (let ((_%$%hd187646187665%_
                                           (##car _%$%e187645187662%_))
                                          (_%$%tl187647187667%_
                                           (##cdr _%$%e187645187662%_)))
                                      (let* ((_%hd187670%_
                                              _%$%hd187646187665%_)
                                             (_%rest187672%_
                                              _%$%tl187647187667%_)
                                             (_%$%e187673187680%_ _%hd187670%_)
                                             (_%$%E187675187684%_
                                              (lambda ()
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Bad syntax; invalid syntax-case clause"
                                                 _%$%e187673187680%_)))
                                             (_%$%E187674187703%_
                                              (lambda ()
                                                (if (gx#stx-pair?
                                                     _%$%e187673187680%_)
                                                    (let ((_%$%e187676187688%_
                                                           (gx#syntax-e
                                                            _%$%e187673187680%_)))
                                                      (let ((_%$%hd187677187691%_
                                                             (##car _%$%e187676187688%_))
                                                            (_%$%tl187678187693%_
                                                             (##cdr _%$%e187676187688%_)))
                                                        (let* ((_%condition187696%_
                                                                _%$%hd187677187691%_)
                                                               (_%body187698%_
                                                                _%$%tl187678187693%_))
                                                          (if (gx#stx-eq?
                                                               _%condition187696%_
                                                               'else)
                                                              (if (gx#stx-null?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%rest187672%_)
                          _%body187698%_
                          (gx#raise-syntax-error
                           '#f
                           '"Bad syntax; clauses after else"
                           _%stx187608%_
                           _%hd187670%_))
                      (if (_%satisfied?187610%_ _%condition187696%_)
                          _%body187698%_
                          (_%loop187611%_ _%rest187672%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%E187675187684%_)))))
                                        (_%$%E187674187703%_))))
                                  (_%$%E187644187658%_)))))
                      (_%$%E187643187707%_)))))
          (let* ((_%$%e187612187619%_ _%stx187608%_)
                 (_%$%E187614187623%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e187612187619%_)))
                 (_%$%E187613187637%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e187612187619%_)
                        (let ((_%$%e187615187627%_
                               (gx#syntax-e _%$%e187612187619%_)))
                          (let ((_%$%hd187616187630%_
                                 (##car _%$%e187615187627%_))
                                (_%$%tl187617187632%_
                                 (##cdr _%$%e187615187627%_)))
                            (let ((_%clauses187635%_ _%$%tl187617187632%_))
                              (if (gx#stx-list? _%clauses187635%_)
                                  (gx#core-cons
                                   'begin
                                   (_%loop187611%_ _%clauses187635%_))
                                  (_%$%E187614187623%_)))))
                        (_%$%E187614187623%_)))))
            (_%$%E187613187637%_)))))
    (define gx#core-expand-include%__%
      (lambda (_%stx187551%_ _%rpath187552%_)
        (let* ((_%$%e187553187563%_ _%stx187551%_)
               (_%$%E187555187567%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e187553187563%_)))
               (_%$%E187554187594%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e187553187563%_)
                      (let ((_%$%e187556187571%_
                             (gx#syntax-e _%$%e187553187563%_)))
                        (let ((_%$%hd187557187574%_
                               (##car _%$%e187556187571%_))
                              (_%$%tl187558187576%_
                               (##cdr _%$%e187556187571%_)))
                          (if (gx#stx-pair? _%$%tl187558187576%_)
                              (let ((_%$%e187559187579%_
                                     (gx#syntax-e _%$%tl187558187576%_)))
                                (let ((_%$%hd187560187582%_
                                       (##car _%$%e187559187579%_))
                                      (_%$%tl187561187584%_
                                       (##cdr _%$%e187559187579%_)))
                                  (let ((_%path187587%_ _%$%hd187560187582%_))
                                    (if (gx#stx-null? _%$%tl187561187584%_)
                                        (if (gx#stx-string? _%path187587%_)
                                            (let ((_%rpath187592%_
                                                   (let ((_%$e187589%_
                                                          _%rpath187552%_))
                                                     (if _%$e187589%_
                                                         _%$e187589%_
                                                         (gx#core-resolve-path__%
                                                          _%path187587%_
                                                          (gx#stx-source
                                                           _%stx187551%_))))))
                                              (if (member _%rpath187592%_
                                                          (gx#current-expander-path))
                                                  (gx#raise-syntax-error
                                                   '#f
                                                   '"Bad syntax; cyclic expansion"
                                                   _%stx187551%_
                                                   (##append
                                                    (##member
                                                     _%rpath187592%_
                                                     (reverse (gx#current-expander-path)))
                                                    (cons _%rpath187592%_
                                                          '())))
                                                  (gx#syntax-local-rewrap
                                                   (gx#stx-wrap-source
                                                    (gx#core-cons
                                                     'begin
                                                     (read-syntax-from-file
                                                      _%rpath187592%_))
                                                    (gx#stx-source
                                                     _%stx187551%_)))))
                                            (_%$%E187555187567%_))
                                        (_%$%E187555187567%_)))))
                              (_%$%E187555187567%_))))
                      (_%$%E187555187567%_)))))
          (_%$%E187554187594%_))))
    (define gx#core-expand-include%__0
      (lambda (_%stx187601%_)
        (let ((_%rpath187603%_ '#f))
          (gx#core-expand-include%__% _%stx187601%_ _%rpath187603%_))))
    (define gx#core-expand-include%
      (lambda _g189926_
        (let ((_g189927_ (##length _g189926_)))
          (cond ((##fx= _g189927_ 1)
                 (apply gx#core-expand-include%__0 _g189926_))
                ((##fx= _g189927_ 2)
                 (apply gx#core-expand-include%__% _g189926_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-include%
                  _g189926_))))))
    (define gx#core-apply-expander__%
      (lambda (_%K187517%_ _%stx187518%_ _%method187519%_)
        (if (procedure? _%K187517%_)
            (let ((_%$e187522%_ (gx#stx-source _%stx187518%_)))
              (if _%$e187522%_
                  (gx#stx-wrap-source (_%K187517%_ _%stx187518%_) _%$e187522%_)
                  (_%K187517%_ _%stx187518%_)))
            (let ((_%$e187530%_
                   (bound-method-ref _%K187517%_ _%method187519%_)))
              (if _%$e187530%_
                  (gx#core-apply-expander__%
                   _%$e187530%_
                   _%stx187518%_
                   _%method187519%_)
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; no expander method"
                   _%stx187518%_
                   _%method187519%_))))))
    (define gx#core-apply-expander__0
      (lambda (_%K187541%_ _%stx187542%_)
        (let ((_%method187544%_ 'apply-macro-expander))
          (gx#core-apply-expander__%
           _%K187541%_
           _%stx187542%_
           _%method187544%_))))
    (define gx#core-apply-expander
      (lambda _g189928_
        (let ((_g189929_ (##length _g189928_)))
          (cond ((##fx= _g189929_ 2)
                 (apply gx#core-apply-expander__0 _g189928_))
                ((##fx= _g189929_ 3)
                 (apply gx#core-apply-expander__% _g189928_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-apply-expander
                  _g189928_))))))
    (define gx#expander::apply-macro-expander
      (lambda (_%self187502%_ _%stx187503%_)
        (let ((_%self187506%_ _%self187502%_))
          (gx#raise-syntax-error
           '#f
           '"Bad syntax; no applicable expander"
           _%stx187503%_))))
    (__bind-method!__%
     gx#expander::t
     'apply-macro-expander
     gx#expander::apply-macro-expander
     '#f)
    (define gx#macro-expander::apply-macro-expander
      (lambda (_%self187345%_ _%stx187346%_)
        (let* ((_%self187349%_ _%self187345%_)
               (_%$%self187358187364%_ _%self187349%_)
               (_%$%E187360187367%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%self187358187364%_
                         '((macro-expander K)))
                  '#!void))
               (_%$%K187361187372%_
                (lambda (_%K187370%_)
                  (gx#core-apply-expander__0 _%K187370%_ _%stx187346%_)))
               (_%$%e187362187375%_
                (##unchecked-structure-ref _%$%self187358187364%_ '1 '#f '#f))
               (_%K187378%_ _%$%e187362187375%_))
          (_%$%K187361187372%_ _%K187378%_))))
    (__bind-method!__%
     gx#macro-expander::t
     'apply-macro-expander
     gx#macro-expander::apply-macro-expander
     '#f)
    (define gx#core-expander::apply-macro-expander
      (lambda (_%self187188%_ _%stx187189%_)
        (let ((_%self187192%_ _%self187188%_))
          (if (gx#sealed-syntax? _%stx187189%_)
              _%stx187189%_
              (let* ((_%$%self187201187207%_ _%self187192%_)
                     (_%$%E187203187210%_
                      (lambda ()
                        (error '"No clause matching"
                               _%$%self187201187207%_
                               '((core-expander K)))
                        '#!void))
                     (_%$%K187204187215%_
                      (lambda (_%K187213%_)
                        (gx#core-apply-expander__0 _%K187213%_ _%stx187189%_)))
                     (_%$%e187205187218%_
                      (##unchecked-structure-ref
                       _%$%self187201187207%_
                       '1
                       '#f
                       '#f))
                     (_%K187221%_ _%$%e187205187218%_))
                (_%$%K187204187215%_ _%K187221%_))))))
    (__bind-method!__%
     gx#core-expander::t
     'apply-macro-expander
     gx#core-expander::apply-macro-expander
     '#f)
    (define gx#top-special-form::apply-macro-expander__%
      (lambda (_%self187038%_ _%stx187039%_ _%top?187040%_)
        (let ((_%self187043%_ _%self187038%_))
          (if (and gx#__DEBUG-EXPANDER gx#__DEBUG-VERBOSE)
              (begin
                (displayln '"@expand " (gx#syntax->datum _%stx187039%_))
                (force-output))
              '#!void)
          (if (_%top?187040%_ (gx#current-expander-context))
              (gx#core-expander::apply-macro-expander
               _%self187043%_
               _%stx187039%_)
              (gx#raise-syntax-error
               '#f
               '"Bad syntax; illegal context"
               _%stx187039%_)))))
    (define gx#top-special-form::apply-macro-expander__0
      (lambda (_%self187057%_ _%stx187058%_)
        (let ((_%top?187060%_ gx#top-context?))
          (gx#top-special-form::apply-macro-expander__%
           _%self187057%_
           _%stx187058%_
           _%top?187060%_))))
    (define gx#top-special-form::apply-macro-expander
      (lambda _g189930_
        (let ((_g189931_ (##length _g189930_)))
          (cond ((##fx= _g189931_ 2)
                 (apply gx#top-special-form::apply-macro-expander__0
                        _g189930_))
                ((##fx= _g189931_ 3)
                 (apply gx#top-special-form::apply-macro-expander__%
                        _g189930_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#top-special-form::apply-macro-expander
                  _g189930_))))))
    (__bind-method!__%
     gx#top-special-form::t
     'apply-macro-expander
     gx#top-special-form::apply-macro-expander
     '#f)
    (define gx#module-special-form::apply-macro-expander
      (lambda (_%self186901%_ _%stx186902%_)
        (let ((_%self186905%_ _%self186901%_))
          (gx#top-special-form::apply-macro-expander__%
           _%self186905%_
           _%stx186902%_
           gx#module-context?))))
    (__bind-method!__%
     gx#module-special-form::t
     'apply-macro-expander
     gx#module-special-form::apply-macro-expander
     '#f)
    (define gx#rename-macro-expander::apply-macro-expander
      (lambda (_%self186716%_ _%stx186717%_)
        (let* ((_%self186720%_ _%self186716%_)
               (_%$%self186729186735%_ _%self186720%_)
               (_%$%E186731186738%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%self186729186735%_
                         '((rename-macro-expander id)))
                  '#!void))
               (_%$%K186732186771%_
                (lambda (_%id186741%_)
                  (let* ((_%$%e186742186749%_ _%stx186717%_)
                         (_%$%E186744186753%_
                          (lambda ()
                            (gx#raise-syntax-error
                             '#f
                             '"Bad syntax; invalid syntax-case clause"
                             _%$%e186742186749%_)))
                         (_%$%E186743186767%_
                          (lambda ()
                            (if (gx#stx-pair? _%$%e186742186749%_)
                                (let ((_%$%e186745186757%_
                                       (gx#syntax-e _%$%e186742186749%_)))
                                  (let ((_%$%hd186746186760%_
                                         (##car _%$%e186745186757%_))
                                        (_%$%tl186747186762%_
                                         (##cdr _%$%e186745186757%_)))
                                    (let ((_%body186765%_
                                           _%$%tl186747186762%_))
                                      (gx#core-cons
                                       _%id186741%_
                                       _%body186765%_))))
                                (_%$%E186744186753%_)))))
                    (_%$%E186743186767%_))))
               (_%$%e186733186774%_
                (##unchecked-structure-ref _%$%self186729186735%_ '1 '#f '#f))
               (_%id186777%_ _%$%e186733186774%_))
          (_%$%K186732186771%_ _%id186777%_))))
    (__bind-method!__%
     gx#rename-macro-expander::t
     'apply-macro-expander
     gx#rename-macro-expander::apply-macro-expander
     '#f)
    (define gx#core-apply-user-expander__%
      (lambda (_%self186543%_ _%stx186544%_ _%method186545%_)
        (if gx#__DEBUG-EXPANDER
            (begin
              (displayln '"@expand " (gx#syntax->datum _%stx186544%_))
              (force-output))
            '#!void)
        (let* ((_%$%self186546186554%_ _%self186543%_)
               (_%$%E186548186557%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%self186546186554%_
                         '((user-expander K ctx phi)))
                  '#!void))
               (_%$%K186549186564%_
                (lambda (_%phi186560%_ _%ctx186561%_ _%K186562%_)
                  (gx#core-apply-user-macro
                   _%K186562%_
                   _%stx186544%_
                   _%ctx186561%_
                   _%phi186560%_
                   _%method186545%_))))
          (if (##structure-instance-of?
               _%$%self186546186554%_
               'gx#user-expander::t)
              (let* ((_%$%e186550186567%_
                      (##unchecked-structure-ref
                       _%$%self186546186554%_
                       '1
                       '#f
                       '#f))
                     (_%K186570%_ _%$%e186550186567%_)
                     (_%$%e186551186572%_
                      (##unchecked-structure-ref
                       _%$%self186546186554%_
                       '2
                       '#f
                       '#f))
                     (_%ctx186575%_ _%$%e186551186572%_)
                     (_%$%e186552186577%_
                      (##unchecked-structure-ref
                       _%$%self186546186554%_
                       '3
                       '#f
                       '#f))
                     (_%phi186580%_ _%$%e186552186577%_))
                (_%$%K186549186564%_ _%phi186580%_ _%ctx186575%_ _%K186570%_))
              (_%$%E186548186557%_)))))
    (define gx#core-apply-user-expander__0
      (lambda (_%self186585%_ _%stx186586%_)
        (let ((_%method186588%_ 'apply-macro-expander))
          (gx#core-apply-user-expander__%
           _%self186585%_
           _%stx186586%_
           _%method186588%_))))
    (define gx#core-apply-user-expander
      (lambda _g189932_
        (let ((_g189933_ (##length _g189932_)))
          (cond ((##fx= _g189933_ 2)
                 (apply gx#core-apply-user-expander__0 _g189932_))
                ((##fx= _g189933_ 3)
                 (apply gx#core-apply-user-expander__% _g189932_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-apply-user-expander
                  _g189932_))))))
    (define gx#core-apply-user-macro
      (lambda (_%K186533%_
               _%stx186534%_
               _%ctx186535%_
               _%phi186536%_
               _%method186537%_)
        (let ((_%mark186539%_
               (##structure
                gx#expander-mark::t
                '#f
                _%ctx186535%_
                _%phi186536%_
                _%stx186534%_)))
          (call-with-parameters__1
           (lambda ()
             (gx#stx-apply-mark
              (gx#core-apply-expander__%
               _%K186533%_
               (gx#stx-apply-mark _%stx186534%_ _%mark186539%_)
               _%method186537%_)
              _%mark186539%_))
           gx#current-expander-marks
           (cons _%mark186539%_ (gx#current-expander-marks))))))
    (define gx#user-expander::apply-macro-expander gx#core-apply-user-expander)
    (__bind-method!__%
     gx#user-expander::t
     'apply-macro-expander
     gx#user-expander::apply-macro-expander
     '#f)
    (define gx#resolve-identifier__%
      (lambda (_%stx186381%_ _%phi186382%_ _%ctx186383%_)
        (let _%lp186385%_ ((_%bind186387%_
                            (gx#core-resolve-identifier__%
                             _%stx186381%_
                             _%phi186382%_
                             _%ctx186383%_)))
          (if (##structure-direct-instance-of?
               _%bind186387%_
               'gx#import-binding::t)
              (_%lp186385%_
               (##unchecked-structure-ref _%bind186387%_ '5 '#f '#f))
              (if (##structure-direct-instance-of?
                   _%bind186387%_
                   'gx#alias-binding::t)
                  (_%lp186385%_
                   (gx#core-resolve-identifier__%
                    (##unchecked-structure-ref _%bind186387%_ '5 '#f '#f)
                    _%phi186382%_
                    _%ctx186383%_))
                  _%bind186387%_)))))
    (define gx#resolve-identifier__0
      (lambda (_%stx186395%_)
        (let* ((_%phi186397%_ (gx#current-expander-phi))
               (_%ctx186399%_ (gx#current-expander-context)))
          (gx#resolve-identifier__%
           _%stx186395%_
           _%phi186397%_
           _%ctx186399%_))))
    (define gx#resolve-identifier__1
      (lambda (_%stx186401%_ _%phi186402%_)
        (let ((_%ctx186404%_ (gx#current-expander-context)))
          (gx#resolve-identifier__%
           _%stx186401%_
           _%phi186402%_
           _%ctx186404%_))))
    (define gx#resolve-identifier
      (lambda _g189934_
        (let ((_g189935_ (##length _g189934_)))
          (cond ((##fx= _g189935_ 1)
                 (apply gx#resolve-identifier__0 _g189934_))
                ((##fx= _g189935_ 2)
                 (apply gx#resolve-identifier__1 _g189934_))
                ((##fx= _g189935_ 3)
                 (apply gx#resolve-identifier__% _g189934_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#resolve-identifier
                  _g189934_))))))
    (define gx#bind-identifier!__%
      (lambda (_%stx186336%_
               _%val186337%_
               _%rebind?186338%_
               _%phi186339%_
               _%ctx186340%_)
        (let ((_%rebind?186345%_
               (if _%rebind?186338%_
                   (if (procedure? _%rebind?186338%_) _%rebind?186338%_ true)
                   gx#core-context-rebind?)))
          (gx#core-bind!__%
           (gx#core-identifier-key _%stx186336%_)
           _%val186337%_
           _%rebind?186345%_
           _%phi186339%_
           _%ctx186340%_))))
    (define gx#bind-identifier!__0
      (lambda (_%stx186350%_ _%val186351%_)
        (let* ((_%rebind?186353%_ '#f)
               (_%phi186355%_ (gx#current-expander-phi))
               (_%ctx186357%_ (gx#current-expander-context)))
          (gx#bind-identifier!__%
           _%stx186350%_
           _%val186351%_
           _%rebind?186353%_
           _%phi186355%_
           _%ctx186357%_))))
    (define gx#bind-identifier!__1
      (lambda (_%stx186359%_ _%val186360%_ _%rebind?186361%_)
        (let* ((_%phi186363%_ (gx#current-expander-phi))
               (_%ctx186365%_ (gx#current-expander-context)))
          (gx#bind-identifier!__%
           _%stx186359%_
           _%val186360%_
           _%rebind?186361%_
           _%phi186363%_
           _%ctx186365%_))))
    (define gx#bind-identifier!__2
      (lambda (_%stx186367%_ _%val186368%_ _%rebind?186369%_ _%phi186370%_)
        (let ((_%ctx186372%_ (gx#current-expander-context)))
          (gx#bind-identifier!__%
           _%stx186367%_
           _%val186368%_
           _%rebind?186369%_
           _%phi186370%_
           _%ctx186372%_))))
    (define gx#bind-identifier!
      (lambda _g189936_
        (let ((_g189937_ (##length _g189936_)))
          (cond ((##fx= _g189937_ 2) (apply gx#bind-identifier!__0 _g189936_))
                ((##fx= _g189937_ 3) (apply gx#bind-identifier!__1 _g189936_))
                ((##fx= _g189937_ 4) (apply gx#bind-identifier!__2 _g189936_))
                ((##fx= _g189937_ 5) (apply gx#bind-identifier!__% _g189936_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#bind-identifier!
                  _g189936_))))))
    (define gx#core-resolve-identifier__%
      (lambda (_%stx186302%_ _%phi186303%_ _%ctx186304%_)
        (let _%lp186306%_ ((_%e186308%_ _%stx186302%_)
                           (_%marks186309%_ (gx#current-expander-marks)))
          (if (symbol? _%e186308%_)
              (gx#core-resolve-binding
               _%e186308%_
               _%phi186303%_
               _%phi186303%_
               _%ctx186304%_
               (reverse _%marks186309%_))
              (if (gx#identifier-quote? _%e186308%_)
                  (gx#core-resolve-binding
                   (##unchecked-structure-ref _%e186308%_ '1 '#f '#f)
                   _%phi186303%_
                   '0
                   (##unchecked-structure-ref _%e186308%_ '3 '#f '#f)
                   (##unchecked-structure-ref _%e186308%_ '4 '#f '#f))
                  (if (##structure-direct-instance-of?
                       _%e186308%_
                       'gx#identifier-wrap::t)
                      (gx#core-resolve-binding
                       (##unchecked-structure-ref _%e186308%_ '1 '#f '#f)
                       _%phi186303%_
                       _%phi186303%_
                       _%ctx186304%_
                       (foldl__0
                        gx#apply-mark
                        (##unchecked-structure-ref _%e186308%_ '3 '#f '#f)
                        _%marks186309%_))
                      (if (##structure-direct-instance-of?
                           _%e186308%_
                           'gx#syntax-wrap::t)
                          (_%lp186306%_
                           (##unchecked-structure-ref _%e186308%_ '1 '#f '#f)
                           (gx#apply-mark
                            (##unchecked-structure-ref _%e186308%_ '3 '#f '#f)
                            _%marks186309%_))
                          (if (##structure-instance-of?
                               _%e186308%_
                               'gerbil#AST::t)
                              (_%lp186306%_
                               (##unchecked-structure-ref
                                _%e186308%_
                                '1
                                '#f
                                '#f)
                               _%marks186309%_)
                              (gx#raise-syntax-error
                               '#f
                               '"Bad identifier"
                               _%stx186302%_)))))))))
    (define gx#core-resolve-identifier__0
      (lambda (_%stx186320%_)
        (let* ((_%phi186322%_ (gx#current-expander-phi))
               (_%ctx186324%_ (gx#current-expander-context)))
          (gx#core-resolve-identifier__%
           _%stx186320%_
           _%phi186322%_
           _%ctx186324%_))))
    (define gx#core-resolve-identifier__1
      (lambda (_%stx186326%_ _%phi186327%_)
        (let ((_%ctx186329%_ (gx#current-expander-context)))
          (gx#core-resolve-identifier__%
           _%stx186326%_
           _%phi186327%_
           _%ctx186329%_))))
    (define gx#core-resolve-identifier
      (lambda _g189938_
        (let ((_g189939_ (##length _g189938_)))
          (cond ((##fx= _g189939_ 1)
                 (apply gx#core-resolve-identifier__0 _g189938_))
                ((##fx= _g189939_ 2)
                 (apply gx#core-resolve-identifier__1 _g189938_))
                ((##fx= _g189939_ 3)
                 (apply gx#core-resolve-identifier__% _g189938_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-resolve-identifier
                  _g189938_))))))
    (define gx#core-resolve-binding
      (lambda (_%id186213%_
               _%phi186214%_
               _%src-phi186215%_
               _%ctx186216%_
               _%marks186217%_)
        (letrec ((_%resolve186219%_
                  (lambda (_%ctx186286%_ _%src-phi186287%_ _%key186288%_)
                    (let _%lp186290%_ ((_%ctx186292%_
                                        (gx#core-context-shift
                                         _%ctx186286%_
                                         _%phi186214%_))
                                       (_%dphi186293%_
                                        (fx- _%phi186214%_ _%src-phi186287%_)))
                      (let ((_%$e186295%_
                             (gx#core-context-resolve
                              _%ctx186292%_
                              _%key186288%_)))
                        (if _%$e186295%_
                            _%$e186295%_
                            (if (fxzero? _%dphi186293%_)
                                '#f
                                (if (fxpositive? _%dphi186293%_)
                                    (_%lp186290%_
                                     (gx#core-context-shift _%ctx186292%_ '-1)
                                     (##fx- _%dphi186293%_ '1))
                                    (_%lp186290%_
                                     (gx#core-context-shift _%ctx186292%_ '1)
                                     (##fx+ _%dphi186293%_ '1))))))))))
          (let _%lp186221%_ ((_%ctx186223%_ _%ctx186216%_)
                             (_%src-phi186224%_ _%src-phi186215%_)
                             (_%rest186225%_ _%marks186217%_))
            (let* ((_%$%rest186226186234%_ _%rest186225%_)
                   (_%$%else186228186242%_
                    (lambda ()
                      (_%resolve186219%_
                       _%ctx186223%_
                       _%src-phi186224%_
                       _%id186213%_)))
                   (_%$%K186230186274%_
                    (lambda (_%rest186245%_ _%hd186246%_)
                      (let* ((_%$%hd186247186253%_ _%hd186246%_)
                             (_%$%E186249186256%_
                              (lambda ()
                                (error '"No clause matching"
                                       _%$%hd186247186253%_
                                       '((expander-mark subst)))
                                '#!void))
                             (_%$%K186250186266%_
                              (lambda (_%subst186259%_)
                                (let ((_%$e186263%_
                                       (let ((_%key186261%_
                                              (if _%subst186259%_
                                                  (hash-get
                                                   _%subst186259%_
                                                   _%id186213%_)
                                                  '#f)))
                                         (if _%key186261%_
                                             (_%resolve186219%_
                                              _%ctx186223%_
                                              _%src-phi186224%_
                                              _%key186261%_)
                                             '#f))))
                                  (if _%$e186263%_
                                      _%$e186263%_
                                      (_%lp186221%_
                                       (##unchecked-structure-ref
                                        _%hd186246%_
                                        '2
                                        '#f
                                        '#f)
                                       (##unchecked-structure-ref
                                        _%hd186246%_
                                        '3
                                        '#f
                                        '#f)
                                       _%rest186245%_))))))
                        (if (##structure-instance-of?
                             _%$%hd186247186253%_
                             'gx#expander-mark::t)
                            (let* ((_%$%e186251186269%_
                                    (##unchecked-structure-ref
                                     _%$%hd186247186253%_
                                     '1
                                     '#f
                                     '#f))
                                   (_%subst186272%_ _%$%e186251186269%_))
                              (_%$%K186250186266%_ _%subst186272%_))
                            (_%$%E186249186256%_))))))
              (if (pair? _%$%rest186226186234%_)
                  (let ((_%$%hd186231186277%_ (##car _%$%rest186226186234%_))
                        (_%$%tl186232186279%_ (##cdr _%$%rest186226186234%_)))
                    (let* ((_%hd186282%_ _%$%hd186231186277%_)
                           (_%rest186284%_ _%$%tl186232186279%_))
                      (_%$%K186230186274%_ _%rest186284%_ _%hd186282%_)))
                  (_%$%else186228186242%_)))))))
    (define gx#core-bind!__%
      (lambda (_%key186084%_
               _%val186085%_
               _%rebind?186086%_
               _%phi186087%_
               _%ctx186088%_)
        (letrec ((_%update-binding186090%_
                  (lambda (_%xval186162%_)
                    (if (or (_%rebind?186086%_
                             _%ctx186088%_
                             _%xval186162%_
                             _%val186085%_)
                            (and (##structure-direct-instance-of?
                                  _%xval186162%_
                                  'gx#import-binding::t)
                                 (or (##unchecked-structure-ref
                                      _%xval186162%_
                                      '7
                                      '#f
                                      '#f)
                                     (and (##structure-instance-of?
                                           _%val186085%_
                                           'gx#binding::t)
                                          (not (##structure-direct-instance-of?
                                                _%val186085%_
                                                'gx#import-binding::t)))))
                            (and (##structure-instance-of?
                                  _%xval186162%_
                                  'gx#extern-binding::t)
                                 (##structure-instance-of?
                                  _%val186085%_
                                  'gx#runtime-binding::t)
                                 (eq? (##unchecked-structure-ref
                                       _%val186085%_
                                       '1
                                       '#f
                                       '#f)
                                      (##unchecked-structure-ref
                                       _%xval186162%_
                                       '1
                                       '#f
                                       '#f))))
                        _%val186085%_
                        (if (and (##structure-direct-instance-of?
                                  _%val186085%_
                                  'gx#import-binding::t)
                                 (or (##unchecked-structure-ref
                                      _%val186085%_
                                      '7
                                      '#f
                                      '#f)
                                     (and (##structure-instance-of?
                                           _%xval186162%_
                                           'gx#binding::t)
                                          (eq? (##unchecked-structure-ref
                                                _%val186085%_
                                                '1
                                                '#f
                                                '#f)
                                               (##unchecked-structure-ref
                                                _%xval186162%_
                                                '1
                                                '#f
                                                '#f)))))
                            _%xval186162%_
                            (if (and (##structure-direct-instance-of?
                                      _%val186085%_
                                      'gx#import-binding::t)
                                     (##structure-instance-of?
                                      _%xval186162%_
                                      'gx#binding::t))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad binding; import conflict"
                                 _%key186084%_
                                 (cons (##unchecked-structure-ref
                                        _%val186085%_
                                        '1
                                        '#f
                                        '#f)
                                       (cons (##structure-ref
                                              (##unchecked-structure-ref
                                               _%val186085%_
                                               '6
                                               '#f
                                               '#f)
                                              '1
                                              gx#expander-context::t
                                              '#f)
                                             '()))
                                 (cons (##unchecked-structure-ref
                                        _%xval186162%_
                                        '1
                                        '#f
                                        '#f)
                                       (cons (if (##structure-direct-instance-of?
                                                  _%xval186162%_
                                                  'gx#import-binding::t)
                                                 (##structure-ref
                                                  (##unchecked-structure-ref
                                                   _%xval186162%_
                                                   '6
                                                   '#f
                                                   '#f)
                                                  '1
                                                  gx#expander-context::t
                                                  '#f)
                                                 _%xval186162%_)
                                             '())))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad binding; rebind conflict"
                                 _%key186084%_
                                 _%val186085%_
                                 _%xval186162%_))))))
                 (_%gensubst186091%_
                  (lambda (_%subst186157%_ _%id186158%_)
                    (let ((_%eid186160%_
                           (gensym (if (uninterned-symbol? _%id186158%_)
                                       '%
                                       _%id186158%_))))
                      (hash-put! _%subst186157%_ _%id186158%_ _%eid186160%_)
                      _%eid186160%_)))
                 (_%subst!186092%_
                  (lambda (_%key186094%_)
                    (let* ((_%$%key186095186103%_ _%key186094%_)
                           (_%$%else186097186111%_ (lambda () _%key186094%_))
                           (_%$%K186099186145%_
                            (lambda (_%mark186114%_ _%id186115%_)
                              (let* ((_%$%mark186116186122%_ _%mark186114%_)
                                     (_%$%E186118186125%_
                                      (lambda ()
                                        (error '"No clause matching"
                                               _%$%mark186116186122%_
                                               '((expander-mark subst)))
                                        '#!void))
                                     (_%$%K186119186137%_
                                      (lambda (_%subst186128%_)
                                        (if _%subst186128%_
                                            (let ((_%$e186133%_
                                                   (hash-get
                                                    _%subst186128%_
                                                    _%id186115%_)))
                                              (if _%$e186133%_
                                                  _%$e186133%_
                                                  (_%gensubst186091%_
                                                   _%subst186128%_
                                                   _%id186115%_)))
                                            (let ((_%subst186131%_
                                                   (make-hash-table-eq)))
                                              (##unchecked-structure-set!
                                               _%mark186114%_
                                               _%subst186131%_
                                               '1
                                               '#f
                                               '#f)
                                              (_%gensubst186091%_
                                               _%subst186131%_
                                               _%id186115%_))))))
                                (if (##structure-instance-of?
                                     _%$%mark186116186122%_
                                     'gx#expander-mark::t)
                                    (let* ((_%$%e186120186140%_
                                            (##unchecked-structure-ref
                                             _%$%mark186116186122%_
                                             '1
                                             '#f
                                             '#f))
                                           (_%subst186143%_
                                            _%$%e186120186140%_))
                                      (_%$%K186119186137%_ _%subst186143%_))
                                    (_%$%E186118186125%_))))))
                      (if (pair? _%$%key186095186103%_)
                          (let ((_%$%hd186100186148%_
                                 (##car _%$%key186095186103%_))
                                (_%$%tl186101186150%_
                                 (##cdr _%$%key186095186103%_)))
                            (let* ((_%id186153%_ _%$%hd186100186148%_)
                                   (_%mark186155%_ _%$%tl186101186150%_))
                              (_%$%K186099186145%_
                               _%mark186155%_
                               _%id186153%_)))
                          (_%$%else186097186111%_))))))
          (if (and gx#__DEBUG-EXPANDER gx#__DEBUG-VERBOSE)
              (begin (displayln '"@bind " _%key186084%_) (force-output))
              '#!void)
          (gx#core-context-bind!
           (gx#core-context-shift _%ctx186088%_ _%phi186087%_)
           (_%subst!186092%_ _%key186084%_)
           _%val186085%_
           _%update-binding186090%_))))
    (define gx#core-bind!__0
      (lambda (_%key186183%_ _%val186184%_)
        (let* ((_%rebind?186186%_ false)
               (_%phi186188%_ (gx#current-expander-phi))
               (_%ctx186190%_ (gx#current-expander-context)))
          (gx#core-bind!__%
           _%key186183%_
           _%val186184%_
           _%rebind?186186%_
           _%phi186188%_
           _%ctx186190%_))))
    (define gx#core-bind!__1
      (lambda (_%key186192%_ _%val186193%_ _%rebind?186194%_)
        (let* ((_%phi186196%_ (gx#current-expander-phi))
               (_%ctx186198%_ (gx#current-expander-context)))
          (gx#core-bind!__%
           _%key186192%_
           _%val186193%_
           _%rebind?186194%_
           _%phi186196%_
           _%ctx186198%_))))
    (define gx#core-bind!__2
      (lambda (_%key186200%_ _%val186201%_ _%rebind?186202%_ _%phi186203%_)
        (let ((_%ctx186205%_ (gx#current-expander-context)))
          (gx#core-bind!__%
           _%key186200%_
           _%val186201%_
           _%rebind?186202%_
           _%phi186203%_
           _%ctx186205%_))))
    (define gx#core-bind!
      (lambda _g189940_
        (let ((_g189941_ (##length _g189940_)))
          (cond ((##fx= _g189941_ 2) (apply gx#core-bind!__0 _g189940_))
                ((##fx= _g189941_ 3) (apply gx#core-bind!__1 _g189940_))
                ((##fx= _g189941_ 4) (apply gx#core-bind!__2 _g189940_))
                ((##fx= _g189941_ 5) (apply gx#core-bind!__% _g189940_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind!
                  _g189940_))))))
    (define gx#core-identifier-key
      (lambda (_%stx186015%_)
        (if (symbol? _%stx186015%_)
            (let* ((_%$%g186017186025%_ (gx#current-expander-marks))
                   (_%$%else186019186033%_ (lambda () _%stx186015%_))
                   (_%$%K186021186038%_
                    (lambda (_%hd186036%_) (cons _%stx186015%_ _%hd186036%_))))
              (if (pair? _%$%g186017186025%_)
                  (let* ((_%$%hd186022186041%_ (##car _%$%g186017186025%_))
                         (_%hd186044%_ _%$%hd186022186041%_))
                    (_%$%K186021186038%_ _%hd186044%_))
                  (_%$%else186019186033%_)))
            (if (gx#identifier? _%stx186015%_)
                (let* ((_%id186047%_ (gx#syntax-local-unwrap _%stx186015%_))
                       (_%eid186049%_ (gx#stx-e _%id186047%_))
                       (_%marks186051%_
                        (gx#stx-identifier-marks* _%id186047%_))
                       (_%$%marks186053186061%_ _%marks186051%_)
                       (_%$%else186055186069%_ (lambda () _%eid186049%_))
                       (_%$%K186057186074%_
                        (lambda (_%hd186072%_)
                          (cons _%eid186049%_ _%hd186072%_))))
                  (if (pair? _%$%marks186053186061%_)
                      (let* ((_%$%hd186058186077%_
                              (##car _%$%marks186053186061%_))
                             (_%hd186080%_ _%$%hd186058186077%_))
                        (_%$%K186057186074%_ _%hd186080%_))
                      (_%$%else186055186069%_)))
                (gx#raise-syntax-error '#f '"Bad identifier" _%stx186015%_)))))
    (define gx#&phi-context? gx#phi-context?)
    (define gx#core-context-shift
      (lambda (_%ctx185954%_ _%phi185955%_)
        (letrec ((_%make-phi185957%_
                  (lambda (_%super186013%_)
                    (let ((__obj189911
                           (##structure
                            gx#phi-context::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f)))
                      (gx#phi-context:::init!__%
                       __obj189911
                       (##gensym 'phi)
                       _%super186013%_)
                      __obj189911)))
                 (_%make-phi/up185958%_
                  (lambda (_%ctx186008%_ _%super186009%_)
                    (let ((_%ctx+1186011%_
                           (_%make-phi185957%_ _%super186009%_)))
                      (##unchecked-structure-set!
                       _%ctx186008%_
                       _%ctx+1186011%_
                       '4
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%ctx+1186011%_
                       _%ctx186008%_
                       '5
                       '#f
                       '#f)
                      _%ctx+1186011%_)))
                 (_%make-phi/down185959%_
                  (lambda (_%ctx186003%_ _%super186004%_)
                    (let ((_%ctx-1186006%_
                           (_%make-phi185957%_ _%super186004%_)))
                      (##unchecked-structure-set!
                       _%ctx-1186006%_
                       _%ctx186003%_
                       '4
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%ctx186003%_
                       _%ctx-1186006%_
                       '5
                       '#f
                       '#f)
                      _%ctx-1186006%_)))
                 (_%shift185960%_
                  (lambda (_%ctx185986%_
                           _%delta185987%_
                           _%make-delta-context185988%_
                           _%phi185989%_
                           _%K185990%_)
                    (let ((_%$e185992%_
                           (##unchecked-structure-ref
                            _%ctx185986%_
                            '3
                            '#f
                            '#f)))
                      (if _%$e185992%_
                          (let* ((_%super185997%_
                                  (_%K185990%_ _%$e185992%_ _%delta185987%_))
                                 (_%ctx+d185999%_
                                  (_%make-delta-context185988%_
                                   _%ctx185986%_
                                   _%super185997%_)))
                            (_%K185990%_
                             _%ctx+d185999%_
                             (fx- _%phi185989%_ _%delta185987%_)))
                          (error '"Bad context" _%ctx185986%_))))))
          (let _%K185962%_ ((_%ctx185964%_ _%ctx185954%_)
                            (_%phi185965%_ _%phi185955%_))
            (if (fxzero? _%phi185965%_)
                _%ctx185964%_
                (if (##structure-instance-of? _%ctx185964%_ 'gx#phi-context::t)
                    (if (fxpositive? _%phi185965%_)
                        (let ((_%$e185969%_
                               (##unchecked-structure-ref
                                _%ctx185964%_
                                '4
                                '#f
                                '#f)))
                          (if _%$e185969%_
                              (_%K185962%_
                               _%$e185969%_
                               (##fx- _%phi185965%_ '1))
                              (_%shift185960%_
                               _%ctx185964%_
                               '1
                               _%make-phi/up185958%_
                               _%phi185965%_
                               _%K185962%_)))
                        (let ((_%$e185977%_
                               (##unchecked-structure-ref
                                _%ctx185964%_
                                '5
                                '#f
                                '#f)))
                          (if _%$e185977%_
                              (_%K185962%_
                               _%$e185977%_
                               (##fx+ _%phi185965%_ '1))
                              (_%shift185960%_
                               _%ctx185964%_
                               '-1
                               _%make-phi/down185959%_
                               _%phi185965%_
                               _%K185962%_))))
                    _%ctx185964%_))))))
    (define gx#core-context-get
      (lambda (_%ctx185951%_ _%key185952%_)
        (hash-get
         (##unchecked-structure-ref _%ctx185951%_ '2 '#f '#f)
         _%key185952%_)))
    (define gx#core-context-put!
      (lambda (_%ctx185947%_ _%key185948%_ _%val185949%_)
        (hash-put!
         (##unchecked-structure-ref _%ctx185947%_ '2 '#f '#f)
         _%key185948%_
         _%val185949%_)
        _%val185949%_))
    (define gx#core-context-resolve
      (lambda (_%ctx185933%_ _%key185934%_)
        (let _%lp185936%_ ((_%ctx185938%_ _%ctx185933%_))
          (let ((_%$e185940%_
                 (gx#core-context-get _%ctx185938%_ _%key185934%_)))
            (if _%$e185940%_
                _%$e185940%_
                (let ((_%$e185943%_
                       (if (##structure-instance-of?
                            _%ctx185938%_
                            'gx#phi-context::t)
                           (##unchecked-structure-ref _%ctx185938%_ '3 '#f '#f)
                           '#f)))
                  (if _%$e185943%_ (_%lp185936%_ _%$e185943%_) '#f)))))))
    (define gx#core-context-bind!
      (lambda (_%ctx185922%_ _%key185923%_ _%val185924%_ _%rebind185925%_)
        (let ((_%$e185927%_ (gx#core-context-get _%ctx185922%_ _%key185923%_)))
          (if _%$e185927%_
              (gx#core-context-put!
               _%ctx185922%_
               _%key185923%_
               (_%rebind185925%_ _%$e185927%_))
              (gx#core-context-put!
               _%ctx185922%_
               _%key185923%_
               _%val185924%_)))))
    (define gx#core-context-top__%
      (lambda (_%ctx185897%_ _%stop?185898%_)
        (let _%lp185900%_ ((_%ctx185902%_ _%ctx185897%_))
          (if (_%stop?185898%_ _%ctx185902%_)
              _%ctx185902%_
              (if (##structure-instance-of? _%ctx185902%_ 'gx#phi-context::t)
                  (_%lp185900%_
                   (##unchecked-structure-ref _%ctx185902%_ '3 '#f '#f))
                  '#f)))))
    (define gx#core-context-top__0
      (lambda ()
        (let* ((_%ctx185911%_ (gx#current-expander-context))
               (_%stop?185913%_ gx#top-context?))
          (gx#core-context-top__% _%ctx185911%_ _%stop?185913%_))))
    (define gx#core-context-top__1
      (lambda (_%ctx185915%_)
        (let ((_%stop?185917%_ gx#top-context?))
          (gx#core-context-top__% _%ctx185915%_ _%stop?185917%_))))
    (define gx#core-context-top
      (lambda _g189942_
        (let ((_g189943_ (##length _g189942_)))
          (cond ((##fx= _g189943_ 0) (apply gx#core-context-top__0 _g189942_))
                ((##fx= _g189943_ 1) (apply gx#core-context-top__1 _g189942_))
                ((##fx= _g189943_ 2) (apply gx#core-context-top__% _g189942_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-context-top
                  _g189942_))))))
    (define gx#core-context-root__%
      (lambda (_%ctx185882%_)
        (let _%lp185884%_ ((_%ctx185886%_ _%ctx185882%_))
          (if (##structure-instance-of? _%ctx185886%_ 'gx#phi-context::t)
              (_%lp185884%_
               (##unchecked-structure-ref _%ctx185886%_ '3 '#f '#f))
              _%ctx185886%_))))
    (define gx#core-context-root__0
      (lambda ()
        (let ((_%ctx185892%_ (gx#current-expander-context)))
          (gx#core-context-root__% _%ctx185892%_))))
    (define gx#core-context-root
      (lambda _g189944_
        (let ((_g189945_ (##length _g189944_)))
          (cond ((##fx= _g189945_ 0) (apply gx#core-context-root__0 _g189944_))
                ((##fx= _g189945_ 1) (apply gx#core-context-root__% _g189944_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-context-root
                  _g189944_))))))
    (define gx#core-context-rebind?__%
      (lambda (_%ctx185864%_ . _%ignore185865%_)
        (let ((_%$e185867%_ (gx#current-expander-allow-rebind?)))
          (if _%$e185867%_
              _%$e185867%_
              (if (##structure-instance-of? _%ctx185864%_ 'gx#top-context::t)
                  (if (##structure-instance-of?
                       _%ctx185864%_
                       'gx#module-context::t)
                      '#f
                      (not (##structure-instance-of?
                            _%ctx185864%_
                            'gx#prelude-context::t)))
                  '#f)))))
    (define gx#core-context-rebind?__0
      (lambda ()
        (let ((_%ctx185874%_ (gx#current-expander-context)))
          (gx#core-context-rebind?__% _%ctx185874%_))))
    (define gx#core-context-rebind?
      (lambda _g189946_
        (let ((_g189947_ (##length _g189946_)))
          (cond ((##fx= _g189947_ 0)
                 (apply gx#core-context-rebind?__0 _g189946_))
                ((##fx= _g189947_ 1)
                 (apply gx#core-context-rebind?__% _g189946_))
                ((##fx>= _g189947_ 1)
                 (apply gx#core-context-rebind?__% _g189946_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-context-rebind?
                  _g189946_))))))
    (define gx#core-context-namespace__%
      (lambda (_%ctx185847%_)
        (let ((_%$e185849%_ (gx#core-context-top__1 _%ctx185847%_)))
          (if _%$e185849%_
              (if (##structure-instance-of? _%$e185849%_ 'gx#module-context::t)
                  (##unchecked-structure-ref _%$e185849%_ '6 '#f '#f)
                  '#f)
              '#f))))
    (define gx#core-context-namespace__0
      (lambda ()
        (let ((_%ctx185859%_ (gx#current-expander-context)))
          (gx#core-context-namespace__% _%ctx185859%_))))
    (define gx#core-context-namespace
      (lambda _g189948_
        (let ((_g189949_ (##length _g189948_)))
          (cond ((##fx= _g189949_ 0)
                 (apply gx#core-context-namespace__0 _g189948_))
                ((##fx= _g189949_ 1)
                 (apply gx#core-context-namespace__% _g189948_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-context-namespace
                  _g189948_))))))
    (define gx#expander-binding?__%
      (lambda (_%bind185833%_ _%is?185834%_)
        (if (##structure-direct-instance-of?
             _%bind185833%_
             'gx#syntax-binding::t)
            (_%is?185834%_
             (##unchecked-structure-ref _%bind185833%_ '5 '#f '#f))
            '#f)))
    (define gx#expander-binding?__0
      (lambda (_%bind185839%_)
        (let ((_%is?185841%_ gx#expander?))
          (gx#expander-binding?__% _%bind185839%_ _%is?185841%_))))
    (define gx#expander-binding?
      (lambda _g189950_
        (let ((_g189951_ (##length _g189950_)))
          (cond ((##fx= _g189951_ 1) (apply gx#expander-binding?__0 _g189950_))
                ((##fx= _g189951_ 2) (apply gx#expander-binding?__% _g189950_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#expander-binding?
                  _g189950_))))))
    (define gx#core-expander-binding?
      (lambda (_%bind185830%_)
        (gx#expander-binding?__% _%bind185830%_ gx#core-expander?)))
    (define gx#expression-form-binding?
      (lambda (_%bind185828%_)
        (gx#expander-binding?__% _%bind185828%_ gx#expression-form?)))
    (define gx#direct-special-form-binding?
      (lambda (_%bind185822%_)
        (letrec ((_%direct-special-form?185824%_
                  (lambda (_%obj185826%_)
                    (##structure-direct-instance-of?
                     _%obj185826%_
                     (##type-id gx#special-form::t)))))
          (gx#expander-binding?__%
           _%bind185822%_
           _%direct-special-form?185824%_))))
    (define gx#special-form-binding?
      (lambda (_%bind185820%_)
        (gx#expander-binding?__% _%bind185820%_ gx#special-form?)))
    (define gx#feature-binding?
      (lambda (_%bind185811%_)
        (letrec ((_%feature?185813%_
                  (lambda (_%e185815%_)
                    (let ((_%$e185817%_
                           (##structure-instance-of?
                            _%e185815%_
                            'gx#feature-expander::t)))
                      (if _%$e185817%_
                          _%$e185817%_
                          (##structure-instance-of?
                           _%e185815%_
                           'gx#module-context::t))))))
          (gx#expander-binding?__% _%bind185811%_ _%feature?185813%_))))
    (define gx#private-feature-binding?
      (lambda (_%bind185809%_)
        (gx#expander-binding?__% _%bind185809%_ gx#private-feature-expander?)))
    (define gx#core-bound-identifier?__%
      (lambda (_%id185796%_ _%bound?185797%_)
        (if (gx#identifier? _%id185796%_)
            (_%bound?185797%_ (gx#resolve-identifier__0 _%id185796%_))
            '#f)))
    (define gx#core-bound-identifier?__0
      (lambda (_%id185802%_)
        (let ((_%bound?185804%_ gx#core-expander-binding?))
          (gx#core-bound-identifier?__% _%id185802%_ _%bound?185804%_))))
    (define gx#core-bound-identifier?
      (lambda _g189952_
        (let ((_g189953_ (##length _g189952_)))
          (cond ((##fx= _g189953_ 1)
                 (apply gx#core-bound-identifier?__0 _g189952_))
                ((##fx= _g189953_ 2)
                 (apply gx#core-bound-identifier?__% _g189952_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bound-identifier?
                  _g189952_))))))
    (define gx#core-identifier=?
      (lambda (_%x185786%_ _%y185787%_)
        (letrec ((_%y=?185789%_
                  (lambda (_%xid185793%_)
                    ((if (list? _%y185787%_) memq eq?)
                     _%xid185793%_
                     _%y185787%_))))
          (let ((_%bind185791%_ (gx#resolve-identifier__0 _%x185786%_)))
            (if (##structure-instance-of? _%bind185791%_ 'gx#binding::t)
                (_%y=?185789%_
                 (##unchecked-structure-ref _%bind185791%_ '1 '#f '#f))
                (_%y=?185789%_ (gx#stx-e _%x185786%_)))))))
    (define gx#core-extern-symbol?
      (lambda (_%e185784%_)
        (if (interned-symbol? _%e185784%_)
            (string-index__0 (symbol->string _%e185784%_) '#\#)
            '#f)))
    (define gx#core-quote-syntax__%
      (lambda (_%stx185737%_ _%src185738%_ _%ctx185739%_ _%marks185740%_)
        (if (##structure? _%stx185737%_)
            (let ((_%$e185742%_ (gx#sealed-syntax-unwrap _%stx185737%_)))
              (if _%$e185742%_
                  _%$e185742%_
                  (if (gx#identifier? _%stx185737%_)
                      (let ((_%id185746%_
                             (gx#stx-unwrap__% _%stx185737%_ _%marks185740%_)))
                        (##structure
                         gx#syntax-quote::t
                         (##unchecked-structure-ref _%id185746%_ '1 '#f '#f)
                         (let ((_%$e185748%_
                                (##unchecked-structure-ref
                                 _%id185746%_
                                 '2
                                 '#f
                                 '#f)))
                           (if _%$e185748%_ _%$e185748%_ _%src185738%_))
                         _%ctx185739%_
                         (##unchecked-structure-ref _%id185746%_ '3 '#f '#f)))
                      (##structure
                       gx#syntax-quote::t
                       (gx#stx-e _%stx185737%_)
                       (let ((_%$e185752%_ (gx#stx-source _%stx185737%_)))
                         (if _%$e185752%_ _%$e185752%_ _%src185738%_))
                       _%ctx185739%_
                       (reverse _%marks185740%_)))))
            (##structure
             gx#syntax-quote::t
             _%stx185737%_
             _%src185738%_
             _%ctx185739%_
             (reverse _%marks185740%_)))))
    (define gx#core-quote-syntax__0
      (lambda (_%stx185758%_)
        (let* ((_%src185760%_ '#f)
               (_%ctx185762%_ (gx#current-expander-context))
               (_%marks185764%_ (gx#current-expander-marks)))
          (gx#core-quote-syntax__%
           _%stx185758%_
           _%src185760%_
           _%ctx185762%_
           _%marks185764%_))))
    (define gx#core-quote-syntax__1
      (lambda (_%stx185766%_ _%src185767%_)
        (let* ((_%ctx185769%_ (gx#current-expander-context))
               (_%marks185771%_ (gx#current-expander-marks)))
          (gx#core-quote-syntax__%
           _%stx185766%_
           _%src185767%_
           _%ctx185769%_
           _%marks185771%_))))
    (define gx#core-quote-syntax__2
      (lambda (_%stx185773%_ _%src185774%_ _%ctx185775%_)
        (let ((_%marks185777%_ (gx#current-expander-marks)))
          (gx#core-quote-syntax__%
           _%stx185773%_
           _%src185774%_
           _%ctx185775%_
           _%marks185777%_))))
    (define gx#core-quote-syntax
      (lambda _g189954_
        (let ((_g189955_ (##length _g189954_)))
          (cond ((##fx= _g189955_ 1) (apply gx#core-quote-syntax__0 _g189954_))
                ((##fx= _g189955_ 2) (apply gx#core-quote-syntax__1 _g189954_))
                ((##fx= _g189955_ 3) (apply gx#core-quote-syntax__2 _g189954_))
                ((##fx= _g189955_ 4) (apply gx#core-quote-syntax__% _g189954_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-quote-syntax
                  _g189954_))))))
    (define gx#core-cons
      (lambda (_%hd185733%_ _%tl185734%_)
        (cons (gx#core-quote-syntax__0 _%hd185733%_) _%tl185734%_)))
    (define gx#core-list
      (lambda (_%hd185730%_ . _%rest185731%_)
        (cons (gx#core-quote-syntax__0 _%hd185730%_) _%rest185731%_)))
    (define gx#core-cons*
      (lambda (_%hd185727%_ . _%rest185728%_)
        (apply cons* (gx#core-quote-syntax__0 _%hd185727%_) _%rest185728%_)))
    (define gx#core-resolve-path__%
      (lambda (_%stx-path185696%_ _%rel185697%_)
        (let ((_%path185714%_ (gx#stx-e _%stx-path185696%_))
              (_%reldir185715%_
               (let _%lp185699%_ ((_%relsrc185701%_
                                   (let ((_%$e185711%_
                                          (gx#stx-source _%stx-path185696%_)))
                                     (if _%$e185711%_
                                         _%$e185711%_
                                         _%rel185697%_))))
                 (if (##structure-instance-of? _%relsrc185701%_ 'gerbil#AST::t)
                     (_%lp185699%_
                      (let ((_%$e185704%_ (gx#stx-source _%relsrc185701%_)))
                        (if _%$e185704%_
                            _%$e185704%_
                            (gx#stx-e _%relsrc185701%_))))
                     (if (source-location-path? _%relsrc185701%_)
                         (path-directory
                          (source-location-path _%relsrc185701%_))
                         (if (string? _%relsrc185701%_)
                             (path-directory _%relsrc185701%_)
                             (if (null? (gx#current-expander-path))
                                 (current-directory)
                                 (path-directory
                                  (car (gx#current-expander-path))))))))))
          (path-expand _%path185714%_ (path-normalize _%reldir185715%_)))))
    (define gx#core-resolve-path__0
      (lambda (_%stx-path185720%_)
        (let ((_%rel185722%_ '#f))
          (gx#core-resolve-path__% _%stx-path185720%_ _%rel185722%_))))
    (define gx#core-resolve-path
      (lambda _g189956_
        (let ((_g189957_ (##length _g189956_)))
          (cond ((##fx= _g189957_ 1) (apply gx#core-resolve-path__0 _g189956_))
                ((##fx= _g189957_ 2) (apply gx#core-resolve-path__% _g189956_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-resolve-path
                  _g189956_))))))
    (define gx#core-deserialize-mark__%
      (lambda (_%repr185652%_ _%ctx185653%_)
        (let* ((_%$%repr185654185661%_ _%repr185652%_)
               (_%$%E185656185665%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%repr185654185661%_
                         '([phi . subs]))
                  '#!void))
               (_%$%K185657185673%_
                (lambda (_%subs185668%_ _%phi185669%_)
                  (let ((_%subst185671%_
                         (if (null? _%subs185668%_)
                             '#f
                             (list->hash-table-eq _%subs185668%_))))
                    (##structure
                     gx#expander-mark::t
                     _%subst185671%_
                     _%ctx185653%_
                     _%phi185669%_
                     '#f)))))
          (if (pair? _%$%repr185654185661%_)
              (let ((_%$%hd185658185676%_ (##car _%$%repr185654185661%_))
                    (_%$%tl185659185678%_ (##cdr _%$%repr185654185661%_)))
                (let* ((_%phi185681%_ _%$%hd185658185676%_)
                       (_%subs185683%_ _%$%tl185659185678%_))
                  (_%$%K185657185673%_ _%subs185683%_ _%phi185681%_)))
              (_%$%E185656185665%_)))))
    (define gx#core-deserialize-mark__0
      (lambda (_%repr185688%_)
        (let ((_%ctx185690%_ (gx#current-expander-context)))
          (gx#core-deserialize-mark__% _%repr185688%_ _%ctx185690%_))))
    (define gx#core-deserialize-mark
      (lambda _g189958_
        (let ((_g189959_ (##length _g189958_)))
          (cond ((##fx= _g189959_ 1)
                 (apply gx#core-deserialize-mark__0 _g189958_))
                ((##fx= _g189959_ 2)
                 (apply gx#core-deserialize-mark__% _g189958_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-deserialize-mark
                  _g189958_))))))
    (define gx#syntax-local-rewrap
      (lambda (_%stx185649%_)
        (gx#stx-rewrap _%stx185649%_ (gx#current-expander-marks))))
    (define gx#syntax-local-unwrap
      (lambda (_%stx185647%_)
        (gx#stx-unwrap__% _%stx185647%_ (gx#current-expander-marks))))
    (define gx#syntax-local-introduce
      (lambda (_%stx185617%_)
        (let* ((_%$%g185618185626%_ (gx#current-expander-marks))
               (_%$%else185620185634%_ (lambda () _%stx185617%_))
               (_%$%K185622185639%_
                (lambda (_%hd185637%_)
                  (gx#stx-apply-mark _%stx185617%_ _%hd185637%_))))
          (if (pair? _%$%g185618185626%_)
              (let* ((_%$%hd185623185642%_ (##car _%$%g185618185626%_))
                     (_%hd185645%_ _%$%hd185623185642%_))
                (_%$%K185622185639%_ _%hd185645%_))
              (_%$%else185620185634%_)))))
    (define gx#syntax-local-temp
      (lambda (_%sym185615%_)
        (gx#syntax-local-introduce (make-symbol__0 (gensym _%sym185615%_)))))
    (define gx#syntax-local-e__%
      (lambda (_%stx185600%_ _%E185601%_)
        (let ((_%bind185603%_ (gx#resolve-identifier__0 _%stx185600%_)))
          (if (##structure-direct-instance-of?
               _%bind185603%_
               'gx#syntax-binding::t)
              (##unchecked-structure-ref _%bind185603%_ '5 '#f '#f)
              (_%E185601%_ _%stx185600%_)))))
    (define gx#syntax-local-e__0
      (lambda (_%stx185608%_)
        (let ((_%E185610%_ gx#raise-syntax-ref-error))
          (gx#syntax-local-e__% _%stx185608%_ _%E185610%_))))
    (define gx#syntax-local-e
      (lambda _g189960_
        (let ((_g189961_ (##length _g189960_)))
          (cond ((##fx= _g189961_ 1) (apply gx#syntax-local-e__0 _g189960_))
                ((##fx= _g189961_ 2) (apply gx#syntax-local-e__% _g189960_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#syntax-local-e
                  _g189960_))))))
    (define gx#syntax-local-value__%
      (lambda (_%stx185584%_ _%E185585%_)
        (let ((_%e185587%_ (gx#syntax-local-e__% _%stx185584%_ _%E185585%_)))
          (if (##structure-instance-of? _%e185587%_ 'gx#expander::t)
              (##unchecked-structure-ref _%e185587%_ '1 '#f '#f)
              _%e185587%_))))
    (define gx#syntax-local-value__0
      (lambda (_%stx185592%_)
        (let ((_%E185594%_ gx#raise-syntax-ref-error))
          (gx#syntax-local-value__% _%stx185592%_ _%E185594%_))))
    (define gx#syntax-local-value
      (lambda _g189962_
        (let ((_g189963_ (##length _g189962_)))
          (cond ((##fx= _g189963_ 1)
                 (apply gx#syntax-local-value__0 _g189962_))
                ((##fx= _g189963_ 2)
                 (apply gx#syntax-local-value__% _g189962_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#syntax-local-value
                  _g189962_))))))
    (define gx#raise-syntax-ref-error
      (lambda (_%stx185581%_)
        (gx#raise-syntax-error
         '#f
         '"Bad syntax; not a syntax binding"
         _%stx185581%_)))))
