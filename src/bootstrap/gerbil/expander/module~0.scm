(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/module::timestamp 1795039816)
  (begin
    (declare (not safe))
    (define gx#__module-registry
      (make-hash-table__%
       '#f
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value))
    (define gx#__module-pkg-cache
      (make-hash-table__%
       '#f
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value
       absent-value))
    (define gx#module-import::t
      (make-class-type
       'gx#module-import::t
       'module-import
       (list)
       '(source name phi weak?)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print: name))))
       '#f))
    (define gx#module-import? (__make-class-predicate gx#module-import::t))
    (define gx#make-module-import
      (lambda _%$args197814%_
        (apply make-instance gx#module-import::t _%$args197814%_)))
    (define gx#module-import-source
      (__make-class-slot-accessor gx#module-import::t 'source))
    (define gx#module-import-name
      (__make-class-slot-accessor gx#module-import::t 'name))
    (define gx#module-import-phi
      (__make-class-slot-accessor gx#module-import::t 'phi))
    (define gx#module-import-weak?
      (__make-class-slot-accessor gx#module-import::t 'weak?))
    (define gx#module-import-source-set!
      (__make-class-slot-mutator gx#module-import::t 'source))
    (define gx#module-import-name-set!
      (__make-class-slot-mutator gx#module-import::t 'name))
    (define gx#module-import-phi-set!
      (__make-class-slot-mutator gx#module-import::t 'phi))
    (define gx#module-import-weak?-set!
      (__make-class-slot-mutator gx#module-import::t 'weak?))
    (define gx#&module-import-source
      (__make-class-slot-unchecked-accessor gx#module-import::t 'source))
    (define gx#&module-import-name
      (__make-class-slot-unchecked-accessor gx#module-import::t 'name))
    (define gx#&module-import-phi
      (__make-class-slot-unchecked-accessor gx#module-import::t 'phi))
    (define gx#&module-import-weak?
      (__make-class-slot-unchecked-accessor gx#module-import::t 'weak?))
    (define gx#&module-import-source-set!
      (__make-class-slot-unchecked-mutator gx#module-import::t 'source))
    (define gx#&module-import-name-set!
      (__make-class-slot-unchecked-mutator gx#module-import::t 'name))
    (define gx#&module-import-phi-set!
      (__make-class-slot-unchecked-mutator gx#module-import::t 'phi))
    (define gx#&module-import-weak?-set!
      (__make-class-slot-unchecked-mutator gx#module-import::t 'weak?))
    (define gx#module-export::t
      (make-class-type
       'gx#module-export::t
       'module-export
       (list)
       '(context key phi name weak?)
       (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '((print: name))))
       '#f))
    (define gx#module-export? (__make-class-predicate gx#module-export::t))
    (define gx#make-module-export
      (lambda _%$args197811%_
        (apply make-instance gx#module-export::t _%$args197811%_)))
    (define gx#module-export-context
      (__make-class-slot-accessor gx#module-export::t 'context))
    (define gx#module-export-key
      (__make-class-slot-accessor gx#module-export::t 'key))
    (define gx#module-export-phi
      (__make-class-slot-accessor gx#module-export::t 'phi))
    (define gx#module-export-name
      (__make-class-slot-accessor gx#module-export::t 'name))
    (define gx#module-export-weak?
      (__make-class-slot-accessor gx#module-export::t 'weak?))
    (define gx#module-export-context-set!
      (__make-class-slot-mutator gx#module-export::t 'context))
    (define gx#module-export-key-set!
      (__make-class-slot-mutator gx#module-export::t 'key))
    (define gx#module-export-phi-set!
      (__make-class-slot-mutator gx#module-export::t 'phi))
    (define gx#module-export-name-set!
      (__make-class-slot-mutator gx#module-export::t 'name))
    (define gx#module-export-weak?-set!
      (__make-class-slot-mutator gx#module-export::t 'weak?))
    (define gx#&module-export-context
      (__make-class-slot-unchecked-accessor gx#module-export::t 'context))
    (define gx#&module-export-key
      (__make-class-slot-unchecked-accessor gx#module-export::t 'key))
    (define gx#&module-export-phi
      (__make-class-slot-unchecked-accessor gx#module-export::t 'phi))
    (define gx#&module-export-name
      (__make-class-slot-unchecked-accessor gx#module-export::t 'name))
    (define gx#&module-export-weak?
      (__make-class-slot-unchecked-accessor gx#module-export::t 'weak?))
    (define gx#&module-export-context-set!
      (__make-class-slot-unchecked-mutator gx#module-export::t 'context))
    (define gx#&module-export-key-set!
      (__make-class-slot-unchecked-mutator gx#module-export::t 'key))
    (define gx#&module-export-phi-set!
      (__make-class-slot-unchecked-mutator gx#module-export::t 'phi))
    (define gx#&module-export-name-set!
      (__make-class-slot-unchecked-mutator gx#module-export::t 'name))
    (define gx#&module-export-weak?-set!
      (__make-class-slot-unchecked-mutator gx#module-export::t 'weak?))
    (define gx#import-set::t
      (make-class-type
       'gx#import-set::t
       'import-set
       (list)
       '(source phi imports)
       (cons (cons 'struct: '#t)
             (cons (cons 'final: '#t) '((print: source phi))))
       '#f))
    (define gx#import-set? (__make-class-predicate gx#import-set::t))
    (define gx#make-import-set
      (lambda _%$args197808%_
        (apply make-instance gx#import-set::t _%$args197808%_)))
    (define gx#import-set-source
      (__make-class-slot-accessor gx#import-set::t 'source))
    (define gx#import-set-phi
      (__make-class-slot-accessor gx#import-set::t 'phi))
    (define gx#import-set-imports
      (__make-class-slot-accessor gx#import-set::t 'imports))
    (define gx#import-set-source-set!
      (__make-class-slot-mutator gx#import-set::t 'source))
    (define gx#import-set-phi-set!
      (__make-class-slot-mutator gx#import-set::t 'phi))
    (define gx#import-set-imports-set!
      (__make-class-slot-mutator gx#import-set::t 'imports))
    (define gx#&import-set-source
      (__make-class-slot-unchecked-accessor gx#import-set::t 'source))
    (define gx#&import-set-phi
      (__make-class-slot-unchecked-accessor gx#import-set::t 'phi))
    (define gx#&import-set-imports
      (__make-class-slot-unchecked-accessor gx#import-set::t 'imports))
    (define gx#&import-set-source-set!
      (__make-class-slot-unchecked-mutator gx#import-set::t 'source))
    (define gx#&import-set-phi-set!
      (__make-class-slot-unchecked-mutator gx#import-set::t 'phi))
    (define gx#&import-set-imports-set!
      (__make-class-slot-unchecked-mutator gx#import-set::t 'imports))
    (define gx#export-set::t
      (make-class-type
       'gx#export-set::t
       'export-set
       (list)
       '(source phi exports)
       (cons (cons 'struct: '#t)
             (cons (cons 'final: '#t) '((print: source phi))))
       '#f))
    (define gx#export-set? (__make-class-predicate gx#export-set::t))
    (define gx#make-export-set
      (lambda _%$args197805%_
        (apply make-instance gx#export-set::t _%$args197805%_)))
    (define gx#export-set-source
      (__make-class-slot-accessor gx#export-set::t 'source))
    (define gx#export-set-phi
      (__make-class-slot-accessor gx#export-set::t 'phi))
    (define gx#export-set-exports
      (__make-class-slot-accessor gx#export-set::t 'exports))
    (define gx#export-set-source-set!
      (__make-class-slot-mutator gx#export-set::t 'source))
    (define gx#export-set-phi-set!
      (__make-class-slot-mutator gx#export-set::t 'phi))
    (define gx#export-set-exports-set!
      (__make-class-slot-mutator gx#export-set::t 'exports))
    (define gx#&export-set-source
      (__make-class-slot-unchecked-accessor gx#export-set::t 'source))
    (define gx#&export-set-phi
      (__make-class-slot-unchecked-accessor gx#export-set::t 'phi))
    (define gx#&export-set-exports
      (__make-class-slot-unchecked-accessor gx#export-set::t 'exports))
    (define gx#&export-set-source-set!
      (__make-class-slot-unchecked-mutator gx#export-set::t 'source))
    (define gx#&export-set-phi-set!
      (__make-class-slot-unchecked-mutator gx#export-set::t 'phi))
    (define gx#&export-set-exports-set!
      (__make-class-slot-unchecked-mutator gx#export-set::t 'exports))
    (define gx#import-expander::t
      (make-class-type
       'gx#import-expander::t
       'import-expander
       (list gx#user-expander::t)
       '()
       '()
       ':init!))
    (define gx#import-expander? (__make-class-predicate gx#import-expander::t))
    (define gx#make-import-expander
      (lambda _%$args197802%_
        (apply make-instance gx#import-expander::t _%$args197802%_)))
    (define gx#import-expander-context
      (__make-class-slot-accessor gx#import-expander::t 'context))
    (define gx#import-expander-phi
      (__make-class-slot-accessor gx#import-expander::t 'phi))
    (define gx#import-expander-e
      (__make-class-slot-accessor gx#import-expander::t 'e))
    (define gx#import-expander-context-set!
      (__make-class-slot-mutator gx#import-expander::t 'context))
    (define gx#import-expander-phi-set!
      (__make-class-slot-mutator gx#import-expander::t 'phi))
    (define gx#import-expander-e-set!
      (__make-class-slot-mutator gx#import-expander::t 'e))
    (define gx#&import-expander-context
      (__make-class-slot-unchecked-accessor gx#import-expander::t 'context))
    (define gx#&import-expander-phi
      (__make-class-slot-unchecked-accessor gx#import-expander::t 'phi))
    (define gx#&import-expander-e
      (__make-class-slot-unchecked-accessor gx#import-expander::t 'e))
    (define gx#&import-expander-context-set!
      (__make-class-slot-unchecked-mutator gx#import-expander::t 'context))
    (define gx#&import-expander-phi-set!
      (__make-class-slot-unchecked-mutator gx#import-expander::t 'phi))
    (define gx#&import-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#import-expander::t 'e))
    (define gx#export-expander::t
      (make-class-type
       'gx#export-expander::t
       'export-expander
       (list gx#user-expander::t)
       '()
       '()
       ':init!))
    (define gx#export-expander? (__make-class-predicate gx#export-expander::t))
    (define gx#make-export-expander
      (lambda _%$args197799%_
        (apply make-instance gx#export-expander::t _%$args197799%_)))
    (define gx#export-expander-context
      (__make-class-slot-accessor gx#export-expander::t 'context))
    (define gx#export-expander-phi
      (__make-class-slot-accessor gx#export-expander::t 'phi))
    (define gx#export-expander-e
      (__make-class-slot-accessor gx#export-expander::t 'e))
    (define gx#export-expander-context-set!
      (__make-class-slot-mutator gx#export-expander::t 'context))
    (define gx#export-expander-phi-set!
      (__make-class-slot-mutator gx#export-expander::t 'phi))
    (define gx#export-expander-e-set!
      (__make-class-slot-mutator gx#export-expander::t 'e))
    (define gx#&export-expander-context
      (__make-class-slot-unchecked-accessor gx#export-expander::t 'context))
    (define gx#&export-expander-phi
      (__make-class-slot-unchecked-accessor gx#export-expander::t 'phi))
    (define gx#&export-expander-e
      (__make-class-slot-unchecked-accessor gx#export-expander::t 'e))
    (define gx#&export-expander-context-set!
      (__make-class-slot-unchecked-mutator gx#export-expander::t 'context))
    (define gx#&export-expander-phi-set!
      (__make-class-slot-unchecked-mutator gx#export-expander::t 'phi))
    (define gx#&export-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#export-expander::t 'e))
    (define gx#import-export-expander::t
      (make-class-type
       'gx#import-export-expander::t
       'import-export-expander
       (list gx#import-expander::t gx#export-expander::t)
       '()
       '()
       ':init!))
    (define gx#import-export-expander?
      (__make-class-predicate gx#import-export-expander::t))
    (define gx#make-import-export-expander
      (lambda _%$args197796%_
        (apply make-instance gx#import-export-expander::t _%$args197796%_)))
    (define gx#import-export-expander-context
      (__make-class-slot-accessor gx#import-export-expander::t 'context))
    (define gx#import-export-expander-phi
      (__make-class-slot-accessor gx#import-export-expander::t 'phi))
    (define gx#import-export-expander-e
      (__make-class-slot-accessor gx#import-export-expander::t 'e))
    (define gx#import-export-expander-context-set!
      (__make-class-slot-mutator gx#import-export-expander::t 'context))
    (define gx#import-export-expander-phi-set!
      (__make-class-slot-mutator gx#import-export-expander::t 'phi))
    (define gx#import-export-expander-e-set!
      (__make-class-slot-mutator gx#import-export-expander::t 'e))
    (define gx#&import-export-expander-context
      (__make-class-slot-unchecked-accessor
       gx#import-export-expander::t
       'context))
    (define gx#&import-export-expander-phi
      (__make-class-slot-unchecked-accessor gx#import-export-expander::t 'phi))
    (define gx#&import-export-expander-e
      (__make-class-slot-unchecked-accessor gx#import-export-expander::t 'e))
    (define gx#&import-export-expander-context-set!
      (__make-class-slot-unchecked-mutator
       gx#import-export-expander::t
       'context))
    (define gx#&import-export-expander-phi-set!
      (__make-class-slot-unchecked-mutator gx#import-export-expander::t 'phi))
    (define gx#&import-export-expander-e-set!
      (__make-class-slot-unchecked-mutator gx#import-export-expander::t 'e))
    (define gx#current-import-expander-phi (make-parameter '#f))
    (define gx#current-export-expander-phi (make-parameter '#f))
    (define gx#current-module-reader-path (make-parameter '#f))
    (define gx#current-module-reader-args (make-parameter '#f))
    (define gx#source-file-settings '(char-encoding: UTF-8 eol-encoding: lf))
    (define gx#call-with-input-source-file
      (lambda (_%path197793%_ _%fun197794%_)
        (call-with-input-file
         (cons 'path: (cons _%path197793%_ gx#source-file-settings))
         _%fun197794%_)))
    (define gx#module-context:::init!
      (lambda (_%self197776%_
               _%id197777%_
               _%super197778%_
               _%ns197779%_
               _%path197780%_)
        (let ((_%self197783%_ _%self197776%_))
          (if (##fx< '11 (##structure-length _%self197783%_))
              (begin
                (##unchecked-structure-set!
                 _%self197783%_
                 _%id197777%_
                 '1
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self197783%_
                 (make-hash-table-eq)
                 '2
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self197783%_
                 _%super197778%_
                 '3
                 '#f
                 '#f)
                (##unchecked-structure-set! _%self197783%_ '#f '4 '#f '#f)
                (##unchecked-structure-set! _%self197783%_ '#f '5 '#f '#f)
                (##unchecked-structure-set!
                 _%self197783%_
                 _%ns197779%_
                 '6
                 '#f
                 '#f)
                (##unchecked-structure-set!
                 _%self197783%_
                 _%path197780%_
                 '7
                 '#f
                 '#f)
                (##unchecked-structure-set! _%self197783%_ '() '8 '#f '#f)
                (##unchecked-structure-set! _%self197783%_ '() '9 '#f '#f)
                (##unchecked-structure-set! _%self197783%_ '#f '10 '#f '#f)
                (##unchecked-structure-set! _%self197783%_ '#f '11 '#f '#f)
                '#!void)
              (error '"struct-instance-init!: too many arguments for struct"
                     _%self197783%_
                     '11
                     (##structure-length _%self197783%_))))))
    (__bind-method!__%
     gx#module-context::t
     ':init!
     gx#module-context:::init!
     '#f)
    (define gx#prelude-context:::init!__%
      (lambda (_%self197609%_ _%ctx197610%_ _%root197611%_)
        (let* ((_%self197614%_ _%self197609%_)
               (_%super197630%_
                (let ((_%$e197624%_ _%root197611%_))
                  (if _%$e197624%_
                      _%$e197624%_
                      (let ((_%$e197627%_ (gx#core-context-root__0)))
                        (if _%$e197627%_
                            _%$e197627%_
                            (let ((__obj197858
                                   (##structure gx#root-context::t '#f '#f)))
                              (let ((__constructor197859
                                     (direct-method-ref
                                      gx#root-context::t
                                      __obj197858
                                      ':init!)))
                                (if __constructor197859
                                    (__constructor197859 __obj197858)
                                    (error '"missing constructor method implementation"
                                           'class:
                                           gx#root-context::t
                                           'method:
                                           ':init!)))
                              __obj197858)))))))
          (if _%ctx197610%_
              (let ((_%id197633%_
                     (##structure-ref
                      _%ctx197610%_
                      '1
                      gx#expander-context::t
                      '#f))
                    (_%path197634%_
                     (##structure-ref
                      _%ctx197610%_
                      '7
                      gx#module-context::t
                      '#f))
                    (_%in197635%_
                     (map gx#core-module-export->import
                          (##structure-ref
                           _%ctx197610%_
                           '9
                           gx#module-context::t
                           '#f)))
                    (_%e197636%_
                     (__make-atomic-promise
                      (lambda () (gx#eval-module _%ctx197610%_)))))
                (if (##fx< '8 (##structure-length _%self197614%_))
                    (begin
                      (##unchecked-structure-set!
                       _%self197614%_
                       _%id197633%_
                       '1
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       (make-hash-table-eq 'size: (##length _%in197635%_))
                       '2
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       _%super197630%_
                       '3
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       '#f
                       '4
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       '#f
                       '5
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       _%path197634%_
                       '6
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       _%in197635%_
                       '7
                       '#f
                       '#f)
                      (##unchecked-structure-set!
                       _%self197614%_
                       _%e197636%_
                       '8
                       '#f
                       '#f)
                      '#!void)
                    (error '"struct-instance-init!: too many arguments for struct"
                           _%self197614%_
                           '8
                           (##structure-length _%self197614%_)))
                (##for-each
                 (lambda (_%$%g197637197639%_)
                   (gx#core-bind-weak-import!__%
                    _%$%g197637197639%_
                    _%self197614%_))
                 _%in197635%_))
              (if (##fx< '8 (##structure-length _%self197614%_))
                  (begin
                    (##unchecked-structure-set! _%self197614%_ '#f '1 '#f '#f)
                    (##unchecked-structure-set!
                     _%self197614%_
                     (make-hash-table-eq)
                     '2
                     '#f
                     '#f)
                    (##unchecked-structure-set!
                     _%self197614%_
                     _%super197630%_
                     '3
                     '#f
                     '#f)
                    (##unchecked-structure-set! _%self197614%_ '#f '4 '#f '#f)
                    (##unchecked-structure-set! _%self197614%_ '#f '5 '#f '#f)
                    (##unchecked-structure-set! _%self197614%_ '#f '6 '#f '#f)
                    (##unchecked-structure-set! _%self197614%_ '() '7 '#f '#f)
                    (##unchecked-structure-set! _%self197614%_ '#f '8 '#f '#f)
                    '#!void)
                  (error '"struct-instance-init!: too many arguments for struct"
                         _%self197614%_
                         '8
                         (##structure-length _%self197614%_)))))))
    (define gx#prelude-context:::init!__0
      (lambda (_%self197645%_ _%ctx197646%_)
        (let ((_%root197648%_ '#f))
          (gx#prelude-context:::init!__%
           _%self197645%_
           _%ctx197646%_
           _%root197648%_))))
    (define gx#prelude-context:::init!
      (lambda _g197865_
        (let ((_g197866_ (##length _g197865_)))
          (cond ((##fx= _g197866_ 2)
                 (apply gx#prelude-context:::init!__0 _g197865_))
                ((##fx= _g197866_ 3)
                 (apply gx#prelude-context:::init!__% _g197865_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#prelude-context:::init!
                  _g197865_))))))
    (__bind-method!__%
     gx#prelude-context::t
     ':init!
     gx#prelude-context:::init!
     '#f)
    (define gx#import-export-expander-init!
      (lambda (_%self197483%_ _%e197484%_)
        (if (##fx< '3 (##structure-length _%self197483%_))
            (begin
              (##unchecked-structure-set!
               _%self197483%_
               _%e197484%_
               '1
               '#f
               '#f)
              (##unchecked-structure-set!
               _%self197483%_
               (gx#current-expander-context)
               '2
               '#f
               '#f)
              (##unchecked-structure-set!
               _%self197483%_
               (##fx- (gx#current-expander-phi) '1)
               '3
               '#f
               '#f)
              '#!void)
            (error '"struct-instance-init!: too many arguments for struct"
                   _%self197483%_
                   '3
                   (##structure-length _%self197483%_)))))
    (define gx#import-expander:::init! gx#import-export-expander-init!)
    (__bind-method!__%
     gx#import-expander::t
     ':init!
     gx#import-expander:::init!
     '#f)
    (define gx#export-expander:::init! gx#import-export-expander-init!)
    (__bind-method!__%
     gx#export-expander::t
     ':init!
     gx#export-expander:::init!
     '#f)
    (define gx#import-export-expander:::init! gx#import-export-expander-init!)
    (__bind-method!__%
     gx#import-export-expander::t
     ':init!
     gx#import-export-expander:::init!
     '#f)
    (define gx#import-expander::apply-import-expander
      (lambda (_%$%g197109197112%_ _%$%g197110197114%_)
        (gx#core-apply-user-expander__%
         _%$%g197109197112%_
         _%$%g197110197114%_
         'apply-import-expander)))
    (__bind-method!__%
     gx#import-expander::t
     'apply-import-expander
     gx#import-expander::apply-import-expander
     '#f)
    (define gx#export-expander::apply-export-expander
      (lambda (_%$%g196980196983%_ _%$%g196981196985%_)
        (gx#core-apply-user-expander__%
         _%$%g196980196983%_
         _%$%g196981196985%_
         'apply-export-expander)))
    (__bind-method!__%
     gx#export-expander::t
     'apply-export-expander
     gx#export-expander::apply-export-expander
     '#f)
    (define gx#module-source-path
      (lambda (_%ctx196851%_)
        (let* ((_%path196853%_
                (##structure-ref _%ctx196851%_ '7 gx#module-context::t '#f))
               (_%path196855%_
                (if (pair? _%path196853%_)
                    (##last _%path196853%_)
                    _%path196853%_)))
          (if (string? _%path196855%_) _%path196855%_ '#f))))
    (define gx#import-module__%
      (lambda (_%path196827%_ _%reload?196828%_ _%eval?196829%_)
        (let ((_%ctx196831%_
               ((gx#current-expander-module-import)
                _%path196827%_
                _%reload?196828%_)))
          (if (and _%ctx196831%_ _%eval?196829%_)
              (gx#eval-module _%ctx196831%_)
              '#!void)
          _%ctx196831%_)))
    (define gx#import-module__0
      (lambda (_%path196836%_)
        (let* ((_%reload?196838%_ '#f) (_%eval?196840%_ '#f))
          (gx#import-module__%
           _%path196836%_
           _%reload?196838%_
           _%eval?196840%_))))
    (define gx#import-module__1
      (lambda (_%path196842%_ _%reload?196843%_)
        (let ((_%eval?196845%_ '#f))
          (gx#import-module__%
           _%path196842%_
           _%reload?196843%_
           _%eval?196845%_))))
    (define gx#import-module
      (lambda _g197867_
        (let ((_g197868_ (##length _g197867_)))
          (cond ((##fx= _g197868_ 1) (apply gx#import-module__0 _g197867_))
                ((##fx= _g197868_ 2) (apply gx#import-module__1 _g197867_))
                ((##fx= _g197868_ 3) (apply gx#import-module__% _g197867_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#import-module
                  _g197867_))))))
    (define gx#eval-module
      (lambda (_%mod196824%_)
        ((gx#current-expander-module-eval) _%mod196824%_)))
    (define gx#core-eval-module
      (lambda (_%obj196803%_)
        (letrec ((_%force-e196805%_
                  (lambda (_%getf196819%_ _%e196820%_)
                    (call-with-parameters__1
                     (lambda ()
                       (call-with-parameters__1
                        (lambda () (force (_%getf196819%_ _%e196820%_)))
                        gx#current-expander-phi
                        '0))
                     gx#current-expander-context
                     _%e196820%_))))
          (let _%recur196807%_ ((_%e196809%_ _%obj196803%_))
            (if (##structure-instance-of? _%e196809%_ 'gx#module-context::t)
                (let ()
                  (let ((_%$e196812%_
                         (gx#core-context-prelude__% _%e196809%_)))
                    (if _%$e196812%_ (_%recur196807%_ _%$e196812%_) '#!void))
                  (_%force-e196805%_ gx#module-context-e _%e196809%_))
                (if (##structure-instance-of?
                     _%e196809%_
                     'gx#prelude-context::t)
                    (_%force-e196805%_ gx#prelude-context-e _%e196809%_)
                    (if (gx#stx-string? _%e196809%_)
                        (_%recur196807%_
                         (gx#import-module__0
                          (gx#core-resolve-module-path__0 _%e196809%_)))
                        (if (gx#core-library-module-path? _%e196809%_)
                            (_%recur196807%_
                             (gx#import-module__0
                              (gx#core-resolve-library-module-path
                               _%e196809%_)))
                            (error '"cannot eval module" _%obj196803%_)))))))))
    (define gx#core-context-prelude__%
      (lambda (_%ctx196783%_)
        (let _%lp196785%_ ((_%e196787%_ _%ctx196783%_))
          (if (or (##structure-instance-of? _%e196787%_ 'gx#module-context::t)
                  (##structure-instance-of? _%e196787%_ 'gx#local-context::t))
              (_%lp196785%_ (##unchecked-structure-ref _%e196787%_ '3 '#f '#f))
              (if (##structure-instance-of? _%e196787%_ 'gx#prelude-context::t)
                  _%e196787%_
                  '#f)))))
    (define gx#core-context-prelude__0
      (lambda ()
        (let ((_%ctx196799%_ (gx#current-expander-context)))
          (gx#core-context-prelude__% _%ctx196799%_))))
    (define gx#core-context-prelude
      (lambda _g197869_
        (let ((_g197870_ (##length _g197869_)))
          (cond ((##fx= _g197870_ 0)
                 (apply gx#core-context-prelude__0 _g197869_))
                ((##fx= _g197870_ 1)
                 (apply gx#core-context-prelude__% _g197869_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-context-prelude
                  _g197869_))))))
    (define gx#core-module->prelude-context
      (lambda (_%ctx196774%_)
        (let ((_%$e196776%_ (__hash-get gx#__module-registry _%ctx196774%_)))
          (if _%$e196776%_
              _%$e196776%_
              (let ((_%pre196780%_
                     (let ((__obj197860
                            (##structure
                             gx#prelude-context::t
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f)))
                       (gx#prelude-context:::init!__0
                        __obj197860
                        _%ctx196774%_)
                       __obj197860)))
                (__hash-put! gx#__module-registry _%ctx196774%_ _%pre196780%_)
                _%pre196780%_)))))
    (define gx#core-import-module__%
      (lambda (_%rpath196642%_ _%reload?196643%_)
        (letrec ((_%import-source196645%_
                  (lambda (_%path196733%_)
                    (if (member _%path196733%_ (gx#current-expander-path))
                        (gx#raise-syntax-error
                         '#f
                         '"Cyclic expansion"
                         (##append
                          (##member
                           _%path196733%_
                           (reverse (gx#current-expander-path)))
                          (cons _%path196733%_ '())))
                        '#!void)
                    (call-with-parameters__1
                     (lambda ()
                       (call-with-parameters__1
                        (lambda ()
                          (call-with-parameters__1
                           (lambda ()
                             (call-with-parameters__1
                              (lambda ()
                                (call-with-parameters__1
                                 (lambda ()
                                   (call-with-parameters__1
                                    (lambda ()
                                      (let ((_g197871_
                                             (gx#core-read-module
                                              _%path196733%_)))
                                        (begin
                                          (let ((_g197872_
                                                 (if (##values? _g197871_)
                                                     (##values-length
                                                      _g197871_)
                                                     1)))
                                            (if (not (##fx= _g197872_ 4))
                                                (error "Context expects 4 values"
                                                       _g197872_)))
                                          (let ((_%pre196741%_
                                                 (##values-ref _g197871_ 0))
                                                (_%id196742%_
                                                 (##values-ref _g197871_ 1))
                                                (_%ns196743%_
                                                 (##values-ref _g197871_ 2))
                                                (_%body196744%_
                                                 (##values-ref _g197871_ 3)))
                                            (let* ((_%prelude196754%_
                                                    (if (##structure-instance-of?
                                                         _%pre196741%_
                                                         'gx#prelude-context::t)
                                                        _%pre196741%_
                                                        (if (##structure-instance-of?
                                                             _%pre196741%_
                                                             'gx#module-context::t)
                                                            (gx#core-module->prelude-context
                                                             _%pre196741%_)
                                                            (if (string? _%pre196741%_)
                                                                (gx#core-module->prelude-context
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#core-import-module__0 _%pre196741%_))
                        (if _%pre196741%_
                            (error '"cannot import module; unknown prelude"
                                   _%rpath196642%_
                                   _%pre196741%_)
                            (let ((_%$e196750%_
                                   (gx#current-expander-module-prelude)))
                              (if _%$e196750%_
                                  _%$e196750%_
                                  (let ((__obj197861
                                         (##structure
                                          gx#prelude-context::t
                                          '#f
                                          '#f
                                          '#f
                                          '#f
                                          '#f
                                          '#f
                                          '#f
                                          '#f)))
                                    (gx#prelude-context:::init!__0
                                     __obj197861
                                     '#f)
                                    __obj197861))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%ctx196756%_
                                                    (let ((__obj197862
                                                           (##structure
                                                            gx#module-context::t
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f
                                                            '#f)))
                                                      (gx#module-context:::init!
                                                       __obj197862
                                                       _%id196742%_
                                                       _%prelude196754%_
                                                       _%ns196743%_
                                                       _%path196733%_)
                                                      __obj197862))
                                                   (_%body196758%_
                                                    (gx#core-expand-module-begin
                                                     _%body196744%_
                                                     _%ctx196756%_))
                                                   (_%body196760%_
                                                    (gx#core-quote-syntax__%
                                                     (gx#core-cons
                                                      '%#begin
                                                      _%body196758%_)
                                                     _%path196733%_
                                                     _%ctx196756%_
                                                     '())))
                                              (##unchecked-structure-set!
                                               _%ctx196756%_
                                               (__make-atomic-promise
                                                (lambda ()
                                                  (gx#eval-syntax*
                                                   _%body196760%_)))
                                               '10
                                               '#f
                                               '#f)
                                              (##unchecked-structure-set!
                                               _%ctx196756%_
                                               _%body196760%_
                                               '11
                                               '#f
                                               '#f)
                                              (__hash-put!
                                               gx#__module-registry
                                               _%path196733%_
                                               _%ctx196756%_)
                                              (__hash-put!
                                               gx#__module-registry
                                               _%id196742%_
                                               _%ctx196756%_)
                                              _%ctx196756%_)))))
                                    gx#current-export-expander-phi
                                    '#f))
                                 gx#current-import-expander-phi
                                 '#f))
                              gx#current-expander-path
                              (cons _%path196733%_
                                    (gx#current-expander-path))))
                           gx#current-expander-phi
                           '0))
                        gx#current-expander-marks
                        '()))
                     gx#current-expander-context
                     (gx#core-context-root__0))))
                 (_%import-submodule196646%_
                  (lambda (_%rpath196662%_)
                    (let* ((_%$%rpath196663196670%_ _%rpath196662%_)
                           (_%$%E196665196673%_
                            (lambda ()
                              (error '"No clause matching"
                                     _%$%rpath196663196670%_
                                     '([origin . refs]))
                              '#!void))
                           (_%$%K196666196721%_
                            (lambda (_%refs196676%_ _%origin196677%_)
                              (let ((_%ctx196679%_
                                     (if _%origin196677%_
                                         (gx#core-import-module__%
                                          _%origin196677%_
                                          _%reload?196643%_)
                                         (gx#current-expander-context))))
                                (let _%lp196681%_ ((_%rest196683%_
                                                    _%refs196676%_)
                                                   (_%ctx196684%_
                                                    _%ctx196679%_))
                                  (let* ((_%$%rest196685196693%_
                                          _%rest196683%_)
                                         (_%$%else196687196701%_
                                          (lambda () _%ctx196684%_))
                                         (_%$%K196689196709%_
                                          (lambda (_%rest196704%_ _%id196705%_)
                                            (let ((_%bind196707%_
                                                   (gx#resolve-identifier__%
                                                    _%id196705%_
                                                    '0
                                                    _%ctx196684%_)))
                                              (if (and (##structure-direct-instance-of?
                                                        _%bind196707%_
                                                        'gx#syntax-binding::t)
                                                       (##structure-instance-of?
                                                        (##unchecked-structure-ref
                                                         _%bind196707%_
                                                         '5
                                                         '#f
                                                         '#f)
                                                        'gx#module-context::t))
                                                  (_%lp196681%_
                                                   _%rest196704%_
                                                   (##unchecked-structure-ref
                                                    _%bind196707%_
                                                    '5
                                                    '#f
                                                    '#f))
                                                  (error '"cannot import submodule; not bound as a module"
                                                         _%rpath196662%_
                                                         _%id196705%_
                                                         _%bind196707%_))))))
                                    (if (pair? _%$%rest196685196693%_)
                                        (let ((_%$%hd196690196712%_
                                               (##car _%$%rest196685196693%_))
                                              (_%$%tl196691196714%_
                                               (##cdr _%$%rest196685196693%_)))
                                          (let* ((_%id196717%_
                                                  _%$%hd196690196712%_)
                                                 (_%rest196719%_
                                                  _%$%tl196691196714%_))
                                            (_%$%K196689196709%_
                                             _%rest196719%_
                                             _%id196717%_)))
                                        (_%$%else196687196701%_))))))))
                      (if (pair? _%$%rpath196663196670%_)
                          (let ((_%$%hd196667196724%_
                                 (##car _%$%rpath196663196670%_))
                                (_%$%tl196668196726%_
                                 (##cdr _%$%rpath196663196670%_)))
                            (let* ((_%origin196729%_ _%$%hd196667196724%_)
                                   (_%refs196731%_ _%$%tl196668196726%_))
                              (_%$%K196666196721%_
                               _%refs196731%_
                               _%origin196729%_)))
                          (_%$%E196665196673%_))))))
          (let ((_%$e196648%_
                 (if _%reload?196643%_
                     '#f
                     (__hash-get gx#__module-registry _%rpath196642%_))))
            (if _%$e196648%_
                _%$e196648%_
                (if (list? _%rpath196642%_)
                    (_%import-submodule196646%_ _%rpath196642%_)
                    (if (gx#core-library-module-path? _%rpath196642%_)
                        (let ((_%ctx196653%_
                               (gx#core-import-module__%
                                (gx#core-resolve-library-module-path
                                 _%rpath196642%_)
                                _%reload?196643%_)))
                          (__hash-put!
                           gx#__module-registry
                           _%rpath196642%_
                           _%ctx196653%_)
                          _%ctx196653%_)
                        (let* ((_%npath196656%_
                                (path-normalize _%rpath196642%_))
                               (_%$e196658%_
                                (if _%reload?196643%_
                                    '#f
                                    (__hash-get
                                     gx#__module-registry
                                     _%npath196656%_))))
                          (if _%$e196658%_
                              _%$e196658%_
                              (_%import-source196645%_
                               _%npath196656%_))))))))))
    (define gx#core-import-module__0
      (lambda (_%rpath196767%_)
        (let ((_%reload?196769%_ '#f))
          (gx#core-import-module__% _%rpath196767%_ _%reload?196769%_))))
    (define gx#core-import-module
      (lambda _g197873_
        (let ((_g197874_ (##length _g197873_)))
          (cond ((##fx= _g197874_ 1)
                 (apply gx#core-import-module__0 _g197873_))
                ((##fx= _g197874_ 2)
                 (apply gx#core-import-module__% _g197873_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-import-module
                  _g197873_))))))
    (define gx#core-read-module
      (lambda (_%path196624%_)
        (__with-catch
         (lambda (_%exn196626%_)
           (if (datum-parsing-exception? _%exn196626%_)
               (let ((_%pos196628%_
                      (datum-parsing-exception-filepos _%exn196626%_)))
                 (if (= _%pos196628%_ '0)
                     (gx#core-read-module/lang _%path196624%_)
                     (gx#raise-syntax-error
                      'read-module
                      '"error reading module"
                      _%path196624%_
                      (call-with-parameters__1
                       (lambda ()
                         (call-with-output-string
                          '""
                          (lambda (_%$%g196630196632%_)
                            (display-exception__%
                             _%exn196626%_
                             _%$%g196630196632%_))))
                       dump-stack-trace?
                       '#f)
                      (cons 'line:
                            (cons (##filepos-line _%pos196628%_)
                                  (cons 'col:
                                        (cons (##filepos-col _%pos196628%_)
                                              '())))))))
               (gx#raise-syntax-error
                'read-module
                '"error reading module"
                _%path196624%_
                (call-with-parameters__1
                 (lambda ()
                   (call-with-output-string
                    '""
                    (lambda (_%$%g196635196637%_)
                      (display-exception__%
                       _%exn196626%_
                       _%$%g196635196637%_))))
                 dump-stack-trace?
                 '#f))))
         (lambda () (gx#core-read-module/sexp _%path196624%_)))))
    (define gx#core-read-module/sexp
      (lambda (_%path196476%_)
        (let _%lp196478%_ ((_%body196480%_
                            (read-syntax-from-file _%path196476%_))
                           (_%pre196481%_ '#f)
                           (_%ns196482%_ '#f)
                           (_%pkg196483%_ '#f))
          (let* ((_%$%e196484196508%_ _%body196480%_)
                 (_%$%E196500196534%_
                  (lambda ()
                    (let ((_g197875_
                           (if _%pkg196483%_
                               (values _%pre196481%_
                                       _%ns196482%_
                                       _%pkg196483%_)
                               (gx#core-read-module-package
                                _%path196476%_
                                _%pre196481%_
                                _%ns196482%_))))
                      (begin
                        (let ((_g197876_
                               (if (##values? _g197875_)
                                   (##values-length _g197875_)
                                   1)))
                          (if (not (##fx= _g197876_ 3))
                              (error "Context expects 3 values" _g197876_)))
                        (let ((_%pre196512%_ (##values-ref _g197875_ 0))
                              (_%ns196513%_ (##values-ref _g197875_ 1))
                              (_%pkg196514%_ (##values-ref _g197875_ 2)))
                          (let* ((_%prelude196520%_
                                  (if (gx#core-bound-module-prelude?
                                       _%pre196512%_)
                                      (gx#syntax-local-e__0 _%pre196512%_)
                                      (if (gx#core-library-module-path?
                                           _%pre196512%_)
                                          (gx#core-resolve-library-module-path
                                           _%pre196512%_)
                                          (if (gx#stx-string? _%pre196512%_)
                                              (gx#core-resolve-module-path__%
                                               _%pre196512%_
                                               _%path196476%_)
                                              (gx#stx-e _%pre196512%_)))))
                                 (_%path-id196522%_
                                  (gx#core-module-path->namespace
                                   _%path196476%_))
                                 (_%pkg-id196524%_
                                  (if _%pkg196514%_
                                      (##string-append
                                       _%pkg196514%_
                                       '"/"
                                       _%path-id196522%_)
                                      _%path-id196522%_))
                                 (_%module-id196526%_
                                  (##string->symbol _%pkg-id196524%_))
                                 (_%module-ns196531%_
                                  (if (eq? _%ns196513%_ '#!void)
                                      '#f
                                      (let ((_%$e196528%_ _%ns196513%_))
                                        (if _%$e196528%_
                                            _%$e196528%_
                                            _%pkg-id196524%_)))))
                            (values _%prelude196520%_
                                    _%module-id196526%_
                                    _%module-ns196531%_
                                    _%body196480%_)))))))
                 (_%$%E196493196566%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e196484196508%_)
                        (let ((_%$%e196501196538%_
                               (gx#syntax-e _%$%e196484196508%_)))
                          (let ((_%$%hd196502196541%_
                                 (##car _%$%e196501196538%_))
                                (_%$%tl196503196543%_
                                 (##cdr _%$%e196501196538%_)))
                            (if (eq? (gx#stx-e _%$%hd196502196541%_) 'package:)
                                (if (gx#stx-pair? _%$%tl196503196543%_)
                                    (let ((_%$%e196504196546%_
                                           (gx#syntax-e _%$%tl196503196543%_)))
                                      (let ((_%$%hd196505196549%_
                                             (##car _%$%e196504196546%_))
                                            (_%$%tl196506196551%_
                                             (##cdr _%$%e196504196546%_)))
                                        (let* ((_%pkg196554%_
                                                _%$%hd196505196549%_)
                                               (_%rest196556%_
                                                _%$%tl196506196551%_)
                                               (_%pkg196564%_
                                                (if (gx#identifier?
                                                     _%pkg196554%_)
                                                    (symbol->string
                                                     (gx#stx-e _%pkg196554%_))
                                                    (if (or (gx#stx-string?
                                                             _%pkg196554%_)
                                                            (gx#stx-false?
                                                             _%pkg196554%_))
                                                        (gx#stx-e
                                                         _%pkg196554%_)
                                                        (gx#raise-syntax-error
                                                         'import
                                                         '"Bad syntax; Illegal package name"
                                                         _%pkg196554%_)))))
                                          (_%lp196478%_
                                           _%rest196556%_
                                           _%pre196481%_
                                           _%ns196482%_
                                           _%pkg196564%_))))
                                    (_%$%E196500196534%_))
                                (_%$%E196500196534%_))))
                        (_%$%E196500196534%_))))
                 (_%$%E196486196596%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e196484196508%_)
                        (let ((_%$%e196494196570%_
                               (gx#syntax-e _%$%e196484196508%_)))
                          (let ((_%$%hd196495196573%_
                                 (##car _%$%e196494196570%_))
                                (_%$%tl196496196575%_
                                 (##cdr _%$%e196494196570%_)))
                            (if (eq? (gx#stx-e _%$%hd196495196573%_)
                                     'namespace:)
                                (if (gx#stx-pair? _%$%tl196496196575%_)
                                    (let ((_%$%e196497196578%_
                                           (gx#syntax-e _%$%tl196496196575%_)))
                                      (let ((_%$%hd196498196581%_
                                             (##car _%$%e196497196578%_))
                                            (_%$%tl196499196583%_
                                             (##cdr _%$%e196497196578%_)))
                                        (let* ((_%ns196586%_
                                                _%$%hd196498196581%_)
                                               (_%rest196588%_
                                                _%$%tl196499196583%_)
                                               (_%ns196594%_
                                                (if (gx#identifier?
                                                     _%ns196586%_)
                                                    (symbol->string
                                                     (gx#stx-e _%ns196586%_))
                                                    (if (gx#stx-string?
                                                         _%ns196586%_)
                                                        (gx#stx-e _%ns196586%_)
                                                        (if (gx#stx-false?
                                                             _%ns196586%_)
                                                            '#!void
                                                            (gx#raise-syntax-error
                                                             'import
                                                             '"Bad syntax; illegal namespace"
                                                             _%ns196586%_))))))
                                          (_%lp196478%_
                                           _%rest196588%_
                                           _%pre196481%_
                                           _%ns196594%_
                                           _%pkg196483%_))))
                                    (_%$%E196493196566%_))
                                (_%$%E196493196566%_))))
                        (_%$%E196493196566%_))))
                 (_%$%E196485196620%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e196484196508%_)
                        (let ((_%$%e196487196600%_
                               (gx#syntax-e _%$%e196484196508%_)))
                          (let ((_%$%hd196488196603%_
                                 (##car _%$%e196487196600%_))
                                (_%$%tl196489196605%_
                                 (##cdr _%$%e196487196600%_)))
                            (if (eq? (gx#stx-e _%$%hd196488196603%_) 'prelude:)
                                (if (gx#stx-pair? _%$%tl196489196605%_)
                                    (let ((_%$%e196490196608%_
                                           (gx#syntax-e _%$%tl196489196605%_)))
                                      (let ((_%$%hd196491196611%_
                                             (##car _%$%e196490196608%_))
                                            (_%$%tl196492196613%_
                                             (##cdr _%$%e196490196608%_)))
                                        (let* ((_%prelude196616%_
                                                _%$%hd196491196611%_)
                                               (_%rest196618%_
                                                _%$%tl196492196613%_))
                                          (_%lp196478%_
                                           _%rest196618%_
                                           _%prelude196616%_
                                           _%ns196482%_
                                           _%pkg196483%_))))
                                    (_%$%E196486196596%_))
                                (_%$%E196486196596%_))))
                        (_%$%E196486196596%_)))))
            (_%$%E196485196620%_)))))
    (define gx#core-read-module/lang
      (lambda (_%path196297%_)
        (letrec ((_%default-read-module-body196299%_
                  (lambda (_%inp196468%_)
                    (let _%lp196470%_ ((_%body196472%_ '()))
                      (let ((_%next196474%_ (read-syntax__% _%inp196468%_)))
                        (if (eof-object? _%next196474%_)
                            (reverse _%body196472%_)
                            (_%lp196470%_
                             (cons _%next196474%_ _%body196472%_)))))))
                 (_%read-body196300%_
                  (lambda (_%inp196385%_
                           _%pre196386%_
                           _%ns196387%_
                           _%pkg196388%_
                           _%args196389%_)
                    (let ((_g197877_
                           (if _%pkg196388%_
                               (values _%pre196386%_
                                       _%ns196387%_
                                       _%pkg196388%_)
                               (gx#core-read-module-package
                                _%path196297%_
                                _%pre196386%_
                                _%ns196387%_))))
                      (begin
                        (let ((_g197878_
                               (if (##values? _g197877_)
                                   (##values-length _g197877_)
                                   1)))
                          (if (not (##fx= _g197878_ 3))
                              (error "Context expects 3 values" _g197878_)))
                        (let ((_%pre196391%_ (##values-ref _g197877_ 0))
                              (_%ns196392%_ (##values-ref _g197877_ 1))
                              (_%pkg196393%_ (##values-ref _g197877_ 2)))
                          (let* ((_%prelude196395%_
                                  (gx#import-module__0 _%pre196391%_))
                                 (_%read-module-body196450%_
                                  (let ((_%$e196441%_
                                         (__find (lambda (_%$%e196396196398%_)
                                                   (let* ((_%$%$%e196396196400196410%_
                                                           _%$%e196396196398%_)
                                                          (_%$%else196402196418%_
                                                           (lambda () '#f))
                                                          (_%$%K196404196422%_
                                                           (lambda () '#t)))
                                                     (if (##structure-direct-instance-of?
                                                          _%$%$%e196396196400196410%_
                                                          'gx#module-export::t)
                                                         (let* ((_%$%e196405196425%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##unchecked-structure-ref
                          _%$%$%e196396196400196410%_
                          '1
                          '#f
                          '#f))
                        (_%$%e196406196428%_
                         (##unchecked-structure-ref
                          _%$%$%e196396196400196410%_
                          '2
                          '#f
                          '#f))
                        (_%$%e196407196431%_
                         (##unchecked-structure-ref
                          _%$%$%e196396196400196410%_
                          '3
                          '#f
                          '#f)))
                   (if (##eq? _%$%e196407196431%_ '1)
                       (let ((_%$%e196408196434%_
                              (##unchecked-structure-ref
                               _%$%$%e196396196400196410%_
                               '4
                               '#f
                               '#f)))
                         (if (eq? _%$%e196408196434%_ 'read-module-body)
                             (_%$%K196404196422%_)
                             (_%$%else196402196418%_)))
                       (_%$%else196402196418%_)))
                 (_%$%else196402196418%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (##unchecked-structure-ref
                                                  _%prelude196395%_
                                                  '9
                                                  '#f
                                                  '#f))))
                                    (if _%$e196441%_
                                        (let ((_%proc196447%_
                                               (__with-catch
                                                void
                                                (lambda ()
                                                  (gx#eval-syntax__0
                                                   (##structure-ref
                                                    (gx#core-resolve-module-export
                                                     _%$e196441%_)
                                                    '1
                                                    gx#binding::t
                                                    '#f))))))
                                          (if (procedure? _%proc196447%_)
                                              _%proc196447%_
                                              (gx#raise-syntax-error
                                               '#f
                                               '"Illegal #lang prelude; read-module-body is not a procedure"
                                               _%path196297%_
                                               _%pre196391%_
                                               _%proc196447%_)))
                                        _%default-read-module-body196299%_)))
                                 (_%path-id196452%_
                                  (gx#core-module-path->namespace
                                   _%path196297%_))
                                 (_%pkg-id196454%_
                                  (if _%pkg196393%_
                                      (##string-append
                                       _%pkg196393%_
                                       '"/"
                                       _%path-id196452%_)
                                      _%path-id196452%_))
                                 (_%module-id196456%_
                                  (##string->symbol _%pkg-id196454%_))
                                 (_%module-ns196461%_
                                  (let ((_%$e196458%_ _%ns196392%_))
                                    (if _%$e196458%_
                                        _%$e196458%_
                                        _%pkg-id196454%_)))
                                 (_%body196465%_
                                  (call-with-parameters__1
                                   (lambda ()
                                     (call-with-parameters__1
                                      (lambda ()
                                        (_%read-module-body196450%_
                                         _%inp196385%_))
                                      gx#current-module-reader-args
                                      _%args196389%_))
                                   gx#current-module-reader-path
                                   _%path196297%_)))
                            (values _%prelude196395%_
                                    _%module-id196456%_
                                    _%module-ns196461%_
                                    _%body196465%_)))))))
                 (_%string-e196301%_
                  (lambda (_%obj196379%_ _%what196380%_)
                    (if (string? _%obj196379%_)
                        _%obj196379%_
                        (if (symbol? _%obj196379%_)
                            (##symbol->string _%obj196379%_)
                            (gx#raise-syntax-error
                             '#f
                             (string-append '"Illegal module " _%what196380%_)
                             _%path196297%_
                             _%obj196379%_)))))
                 (_%read-lang-args196302%_
                  (lambda (_%inp196334%_ _%args196335%_)
                    (let* ((_%$%args196336196344%_ _%args196335%_)
                           (_%$%else196338196352%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Illegal #lang arguments; missing prelude"
                               _%path196297%_)))
                           (_%$%K196340196367%_
                            (lambda (_%args196355%_ _%prelude196356%_)
                              (let* ((_%pkg196358%_
                                      (pgetq__0 'package: _%args196355%_))
                                     (_%pkg196360%_
                                      (if _%pkg196358%_
                                          (_%string-e196301%_
                                           _%pkg196358%_
                                           '"package")
                                          '#f))
                                     (_%ns196362%_
                                      (pgetq__0 'namespace: _%args196355%_))
                                     (_%ns196364%_
                                      (if _%ns196362%_
                                          (_%string-e196301%_
                                           _%ns196362%_
                                           '"namespace")
                                          '#f)))
                                (_%read-body196300%_
                                 _%inp196334%_
                                 _%prelude196356%_
                                 _%ns196364%_
                                 _%pkg196360%_
                                 _%args196355%_)))))
                      (if (pair? _%$%args196336196344%_)
                          (let ((_%$%hd196341196370%_
                                 (##car _%$%args196336196344%_))
                                (_%$%tl196342196372%_
                                 (##cdr _%$%args196336196344%_)))
                            (let* ((_%prelude196375%_ _%$%hd196341196370%_)
                                   (_%args196377%_ _%$%tl196342196372%_))
                              (_%$%K196340196367%_
                               _%args196377%_
                               _%prelude196375%_)))
                          (_%$%else196338196352%_)))))
                 (_%read-lang196303%_
                  (lambda (_%inp196308%_)
                    (let* ((_%head196310%_ (read-line _%inp196308%_))
                           (_%$e196312%_
                            (string-index__0 _%head196310%_ '#\space)))
                      (if _%$e196312%_
                          (let ((_%lang196317%_
                                 (substring _%head196310%_ '0 _%$e196312%_)))
                            (if (equal? _%lang196317%_ '"#lang")
                                (let* ((_%rest196319%_
                                        (substring
                                         _%head196310%_
                                         (##fx+ _%$e196312%_ '1)
                                         (string-length _%head196310%_)))
                                       (_%args196330%_
                                        (__with-catch
                                         (lambda (_%$%g196320196322%_)
                                           (gx#raise-syntax-error
                                            '#f
                                            '"Illegal #lang arguments"
                                            _%path196297%_
                                            _%$%g196320196322%_))
                                         (lambda ()
                                           (call-with-input-string
                                            _%rest196319%_
                                            (lambda (_%$%g196325196327%_)
                                              (read-all
                                               _%$%g196325196327%_
                                               read)))))))
                                  (_%read-lang-args196302%_
                                   _%inp196308%_
                                   _%args196330%_))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Illegal module syntax"
                                 _%path196297%_)))
                          (gx#raise-syntax-error
                           '#f
                           '"Illegal module syntax"
                           _%path196297%_)))))
                 (_%read-e196304%_
                  (lambda (_%inp196306%_)
                    (if (eq? (peek-char _%inp196306%_) '#\#)
                        (_%read-lang196303%_ _%inp196306%_)
                        (gx#raise-syntax-error
                         '#f
                         '"Illegal module syntax"
                         _%path196297%_)))))
          (gx#call-with-input-source-file _%path196297%_ _%read-e196304%_))))
    (define gx#core-read-module-package
      (lambda (_%path196245%_ _%pre196246%_ _%ns196247%_)
        (letrec ((_%string-e196249%_
                  (lambda (_%e196292%_)
                    (if (symbol? _%e196292%_)
                        (##symbol->string _%e196292%_)
                        (if (string? _%e196292%_)
                            _%e196292%_
                            (gx#raise-syntax-error
                             '#f
                             '"Malformed package info; unexpected datum"
                             _%e196292%_))))))
          (let _%lp196251%_ ((_%dir196253%_ (path-directory _%path196245%_))
                             (_%pkg-path196254%_ '()))
            (let ((_%gerbil.pkg196256%_
                   (path-expand '"gerbil.pkg" _%dir196253%_)))
              (if (##file-exists? _%gerbil.pkg196256%_)
                  (let ((_%plist196258%_
                         (gx#core-library-package-plist__% _%dir196253%_ '#t)))
                    (if (null? _%plist196258%_)
                        (let ((_%pkg196261%_
                               (if (null? _%pkg-path196254%_)
                                   '#f
                                   (string-join _%pkg-path196254%_ '"/"))))
                          (values _%pre196246%_ _%ns196247%_ _%pkg196261%_))
                        (if (list? _%plist196258%_)
                            (let* ((_%root196264%_
                                    (pgetq__0 'package: _%plist196258%_))
                                   (_%pkg196268%_
                                    (let ((_%pkg-path196266%_
                                           (if _%root196264%_
                                               (cons (_%string-e196249%_
                                                      _%root196264%_)
                                                     _%pkg-path196254%_)
                                               _%pkg-path196254%_)))
                                      (if (null? _%pkg-path196266%_)
                                          '#f
                                          (string-join
                                           _%pkg-path196266%_
                                           '"/"))))
                                   (_%ns196275%_
                                    (let ((_%ns196273%_
                                           (let ((_%$e196270%_ _%ns196247%_))
                                             (if _%$e196270%_
                                                 _%$e196270%_
                                                 (pgetq__0
                                                  'namespace:
                                                  _%plist196258%_)))))
                                      (if _%ns196273%_
                                          (_%string-e196249%_ _%ns196273%_)
                                          '#f)))
                                   (_%pre196280%_
                                    (let ((_%$e196277%_ _%pre196246%_))
                                      (if _%$e196277%_
                                          _%$e196277%_
                                          (pgetq__0
                                           'prelude:
                                           _%plist196258%_)))))
                              (values _%pre196280%_
                                      _%ns196275%_
                                      _%pkg196268%_))
                            (gx#raise-syntax-error
                             '#f
                             '"Malformed package info; unexpected datum"
                             _%plist196258%_))))
                  (let ((_%dir*196284%_
                         (path-strip-trailing-directory-separator
                          _%dir196253%_)))
                    (if (or (__string-empty? _%dir*196284%_)
                            (equal? _%dir196253%_ _%dir*196284%_))
                        (values _%pre196246%_ _%ns196247%_ '#f)
                        (let ((_%xpath196289%_
                               (path-strip-directory _%dir*196284%_))
                              (_%xdir196290%_ (path-directory _%dir*196284%_)))
                          (_%lp196251%_
                           _%xdir196290%_
                           (cons _%xpath196289%_ _%pkg-path196254%_)))))))))))
    (define gx#core-module-path->namespace
      (lambda (_%path196243%_)
        (path-strip-extension (path-strip-directory _%path196243%_))))
    (define gx#core-module-path->id
      (lambda (_%path196241%_)
        (##string->symbol (gx#core-module-path->namespace _%path196241%_))))
    (define gx#core-resolve-module-path__%
      (lambda (_%stx-path196220%_ _%rel196221%_)
        (let* ((_%path196223%_ (gx#stx-e _%stx-path196220%_))
               (_%path196225%_
                (if (__string-empty? (path-extension _%path196223%_))
                    (##string-append _%path196223%_ '".ss")
                    _%path196223%_)))
          (gx#core-resolve-path__%
           _%path196225%_
           (let ((_%$e196228%_ (gx#stx-source _%stx-path196220%_)))
             (if _%$e196228%_ _%$e196228%_ _%rel196221%_))))))
    (define gx#core-resolve-module-path__0
      (lambda (_%stx-path196234%_)
        (let ((_%rel196236%_ '#f))
          (gx#core-resolve-module-path__% _%stx-path196234%_ _%rel196236%_))))
    (define gx#core-resolve-module-path
      (lambda _g197879_
        (let ((_g197880_ (##length _g197879_)))
          (cond ((##fx= _g197880_ 1)
                 (apply gx#core-resolve-module-path__0 _g197879_))
                ((##fx= _g197880_ 2)
                 (apply gx#core-resolve-module-path__% _g197879_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-resolve-module-path
                  _g197879_))))))
    (define gx#core-resolve-library-module-path
      (lambda (_%libpath196105%_)
        (let* ((_%spath196107%_ (symbol->string (gx#stx-e _%libpath196105%_)))
               (_%spath196109%_
                (substring
                 _%spath196107%_
                 '1
                 (##string-length _%spath196107%_)))
               (_%ext196111%_ (path-extension _%spath196109%_))
               (_%ssi196113%_
                (if (__string-empty? _%ext196111%_)
                    (##string-append _%spath196109%_ '".ssi")
                    (##string-append
                     (path-strip-extension _%spath196109%_)
                     '".ssi")))
               (_%srcs196117%_
                (if (__string-empty? _%ext196111%_)
                    (##map (lambda (_%ext196115%_)
                             (string-append _%spath196109%_ _%ext196115%_))
                           '(".ss" ".sld" ".scm"))
                    (cons _%spath196109%_ '()))))
          (let _%lp196120%_ ((_%rest196122%_ (load-path)))
            (let* ((_%$%rest196123196132%_ _%rest196122%_)
                   (_%$%E196126196136%_
                    (lambda ()
                      (error '"No clause matching"
                             _%$%rest196123196132%_
                             '([dir . rest])
                             '([]))
                      '#!void)))
              (let ((_%$%K196128196207%_
                     (lambda (_%rest196147%_ _%dir196148%_)
                       (letrec ((_%resolve196150%_
                                 (lambda (_%ssi196163%_ _%srcs196164%_)
                                   (let ((_%compiled-path196166%_
                                          (path-expand
                                           _%ssi196163%_
                                           _%dir196148%_)))
                                     (if (##file-exists?
                                          _%compiled-path196166%_)
                                         (path-normalize
                                          _%compiled-path196166%_)
                                         (let _%lpr196168%_ ((_%rest-src196170%_
                                                              _%srcs196164%_))
                                           (let* ((_%$%rest-src196171196179%_
                                                   _%rest-src196170%_)
                                                  (_%$%else196173196187%_
                                                   (lambda ()
                                                     (_%lp196120%_
                                                      _%rest196147%_)))
                                                  (_%$%K196175196195%_
                                                   (lambda (_%rest-src196190%_
                                                            _%src196191%_)
                                                     (let ((_%src-path196193%_
                                                            (path-expand
                                                             _%src196191%_
                                                             _%dir196148%_)))
                                                       (if (##file-exists?
                                                            _%src-path196193%_)
                                                           (path-normalize
                                                            _%src-path196193%_)
                                                           (_%lpr196168%_
                                                            _%rest-src196190%_))))))
                                             (if (pair? _%$%rest-src196171196179%_)
                                                 (let ((_%$%hd196176196198%_
                                                        (##car _%$%rest-src196171196179%_))
                                                       (_%$%tl196177196200%_
                                                        (##cdr _%$%rest-src196171196179%_)))
                                                   (let* ((_%src196203%_
                                                           _%$%hd196176196198%_)
                                                          (_%rest-src196205%_
                                                           _%$%tl196177196200%_))
                                                     (_%$%K196175196195%_
                                                      _%rest-src196205%_
                                                      _%src196203%_)))
                                                 (_%$%else196173196187%_)))))))))
                         (let ((_%$e196152%_
                                (gx#core-library-package-path-prefix
                                 _%dir196148%_)))
                           (if _%$e196152%_
                               (if (##string-prefix?
                                    _%$e196152%_
                                    _%spath196109%_)
                                   (let ((_%ssi196159%_
                                          (substring
                                           _%ssi196113%_
                                           (##string-length _%$e196152%_)
                                           (##string-length _%ssi196113%_)))
                                         (_%srcs196160%_
                                          (##map (lambda (_%src196157%_)
                                                   (substring
                                                    _%src196157%_
                                                    (##string-length
                                                     _%$e196152%_)
                                                    (string-length
                                                     _%src196157%_)))
                                                 _%srcs196117%_)))
                                     (_%resolve196150%_
                                      _%ssi196159%_
                                      _%srcs196160%_))
                                   (_%lp196120%_ _%rest196147%_))
                               (_%resolve196150%_
                                _%ssi196113%_
                                _%srcs196117%_))))))
                    (_%$%K196127196141%_
                     (lambda ()
                       (gx#raise-syntax-error
                        '#f
                        '"cannot find library module"
                        _%libpath196105%_))))
                (let ((_%$%try-match196125196144%_
                       (lambda ()
                         (if (null? _%$%rest196123196132%_)
                             (_%$%K196127196141%_)
                             (_%$%E196126196136%_)))))
                  (if (pair? _%$%rest196123196132%_)
                      (let ((_%$%tl196130196212%_
                             (##cdr _%$%rest196123196132%_))
                            (_%$%hd196129196210%_
                             (##car _%$%rest196123196132%_)))
                        (let ((_%dir196215%_ _%$%hd196129196210%_)
                              (_%rest196217%_ _%$%tl196130196212%_))
                          (_%$%K196128196207%_ _%rest196217%_ _%dir196215%_)))
                      (_%$%try-match196125196144%_)))))))))
    (define gx#core-resolve-library-relative-module-path
      (lambda (_%modpath196073%_)
        (letrec ((_%resolve196075%_
                  (lambda (_%path196096%_ _%base196097%_)
                    (let ((_%$e196099%_
                           (string-rindex__0 _%base196097%_ '#\/)))
                      (if _%$e196099%_
                          (gx#core-resolve-library-module-path
                           (##string->symbol
                            (string-append
                             '":"
                             (substring _%base196097%_ '0 _%$e196099%_)
                             '"/"
                             _%path196096%_)))
                          (gx#core-resolve-library-module-path
                           (##string->symbol
                            (string-append '":" _%path196096%_))))))))
          (let ((_%spath196077%_ (symbol->string (gx#stx-e _%modpath196073%_)))
                (_%mod196078%_
                 (gx#core-context-top__%
                  (gx#current-expander-context)
                  gx#module-context?)))
            (if _%mod196078%_
                '#!void
                (gx#raise-syntax-error
                 '#f
                 '"cannot resolve relative module path; not in module context"
                 _%modpath196073%_))
            (let ((_%mpath196080%_
                   (symbol->string
                    (##structure-ref
                     _%mod196078%_
                     '1
                     gx#expander-context::t
                     '#f))))
              (let _%lp196082%_ ((_%spath196084%_ _%spath196077%_)
                                 (_%mpath196085%_ _%mpath196080%_))
                (if (string-prefix? '"../" _%spath196084%_)
                    (let ((_%$e196088%_
                           (string-rindex__0 _%mpath196085%_ '#\/)))
                      (if _%$e196088%_
                          (_%lp196082%_
                           (substring
                            _%spath196084%_
                            '3
                            (string-length _%spath196084%_))
                           (substring _%mpath196085%_ '0 _%$e196088%_))
                          (gx#raise-syntax-error
                           '#f
                           '"cannot resolve relative module path; illegal traversal"
                           _%modpath196073%_)))
                    (if (string-prefix? '"./" _%spath196084%_)
                        (_%lp196082%_
                         (substring
                          _%spath196084%_
                          '2
                          (string-length _%spath196084%_))
                         _%mpath196085%_)
                        (_%resolve196075%_
                         _%spath196084%_
                         _%mpath196085%_)))))))))
    (define gx#core-library-package-path-prefix
      (lambda (_%dir196065%_)
        (let ((_%$e196067%_
               (pgetq__0
                'package:
                (gx#core-library-package-plist__0 _%dir196065%_))))
          (if _%$e196067%_
              (##string-append (symbol->string _%$e196067%_) '"/")
              '#f))))
    (define gx#core-library-package-plist__%
      (lambda (_%dir196035%_ _%exists?196036%_)
        (let ((_%$e196038%_ (__hash-get gx#__module-pkg-cache _%dir196035%_)))
          (if _%$e196038%_
              _%$e196038%_
              (let* ((_%gerbil.pkg196042%_
                      (path-expand '"gerbil.pkg" _%dir196035%_))
                     (_%plist196052%_
                      (if (or _%exists?196036%_
                              (##file-exists? _%gerbil.pkg196042%_))
                          (let ((_%e196047%_
                                 (gx#call-with-input-source-file
                                  _%gerbil.pkg196042%_
                                  read)))
                            (if (eof-object? _%e196047%_)
                                '()
                                (if (list? _%e196047%_)
                                    _%e196047%_
                                    (gx#raise-syntax-error
                                     '#f
                                     '"Malformed package info; unexpected datum"
                                     _%gerbil.pkg196042%_
                                     _%e196047%_))))
                          '())))
                (__hash-put!
                 gx#__module-pkg-cache
                 _%dir196035%_
                 _%plist196052%_)
                _%plist196052%_)))))
    (define gx#core-library-package-plist__0
      (lambda (_%dir196058%_)
        (let ((_%exists?196060%_ '#f))
          (gx#core-library-package-plist__% _%dir196058%_ _%exists?196060%_))))
    (define gx#core-library-package-plist
      (lambda _g197881_
        (let ((_g197882_ (##length _g197881_)))
          (cond ((##fx= _g197882_ 1)
                 (apply gx#core-library-package-plist__0 _g197881_))
                ((##fx= _g197882_ 2)
                 (apply gx#core-library-package-plist__% _g197881_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-library-package-plist
                  _g197881_))))))
    (define gx#core-library-module-path?
      (lambda (_%stx196032%_)
        (gx#core-special-module-path? _%stx196032%_ '#\:)))
    (define gx#core-library-relative-module-path?
      (lambda (_%stx196030%_)
        (gx#core-special-module-path? _%stx196030%_ '#\.)))
    (define gx#core-special-module-path?
      (lambda (_%stx196025%_ _%char196026%_)
        (if (gx#identifier? _%stx196025%_)
            (if (interned-symbol? (gx#stx-e _%stx196025%_))
                (let ((_%str196028%_
                       (symbol->string (gx#stx-e _%stx196025%_))))
                  (if (##fx> (##string-length _%str196028%_) '1)
                      (eq? (string-ref _%str196028%_ '0) _%char196026%_)
                      '#f))
                '#f)
            '#f)))
    (define gx#core-bound-prelude?
      (lambda (_%stx196019%_)
        (gx#core-bound-identifier?__%
         _%stx196019%_
         (lambda (_%$%g196020196022%_)
           (gx#expander-binding?__%
            _%$%g196020196022%_
            gx#prelude-context?)))))
    (define gx#core-bound-module?
      (lambda (_%stx196013%_)
        (gx#core-bound-identifier?__%
         _%stx196013%_
         (lambda (_%$%g196014196016%_)
           (gx#expander-binding?__% _%$%g196014196016%_ gx#module-context?)))))
    (define gx#core-bound-module-prelude?
      (lambda (_%stx196000%_)
        (letrec ((_%module-prelude?196002%_
                  (lambda (_%e196008%_)
                    (let ((_%$e196010%_
                           (##structure-instance-of?
                            _%e196008%_
                            'gx#module-context::t)))
                      (if _%$e196010%_
                          _%$e196010%_
                          (##structure-instance-of?
                           _%e196008%_
                           'gx#prelude-context::t))))))
          (gx#core-bound-identifier?__%
           _%stx196000%_
           (lambda (_%$%g196003196005%_)
             (gx#expander-binding?__%
              _%$%g196003196005%_
              _%module-prelude?196002%_))))))
    (define gx#core-bind-import!__%
      (lambda (_%in195931%_ _%ctx195932%_ _%force-weak?195933%_)
        (let* ((_%$%in195934195943%_ _%in195931%_)
               (_%$%E195936195946%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%in195934195943%_
                         '((module-import source key phi weak?)))
                  '#!void))
               (_%$%K195937195959%_
                (lambda (_%weak?195949%_
                         _%phi195950%_
                         _%key195951%_
                         _%source195952%_)
                  (gx#core-bind!__%
                   _%key195951%_
                   (let* ((_%e195954%_
                           (gx#core-resolve-module-export _%source195952%_))
                          (__obj197863
                           (##structure
                            gx#import-binding::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f)))
                     (gx#import-binding:::init!
                      __obj197863
                      (##unchecked-structure-ref _%e195954%_ '1 '#f '#f)
                      _%key195951%_
                      _%phi195950%_
                      _%e195954%_
                      (##unchecked-structure-ref _%source195952%_ '1 '#f '#f)
                      (let ((_%$e195956%_ _%force-weak?195933%_))
                        (if _%$e195956%_ _%$e195956%_ _%weak?195949%_)))
                     __obj197863)
                   gx#core-context-rebind?
                   _%phi195950%_
                   _%ctx195932%_))))
          (if (##structure-direct-instance-of?
               _%$%in195934195943%_
               'gx#module-import::t)
              (let* ((_%$%e195938195962%_
                      (##unchecked-structure-ref
                       _%$%in195934195943%_
                       '1
                       '#f
                       '#f))
                     (_%source195965%_ _%$%e195938195962%_)
                     (_%$%e195939195967%_
                      (##unchecked-structure-ref
                       _%$%in195934195943%_
                       '2
                       '#f
                       '#f))
                     (_%key195970%_ _%$%e195939195967%_)
                     (_%$%e195940195972%_
                      (##unchecked-structure-ref
                       _%$%in195934195943%_
                       '3
                       '#f
                       '#f))
                     (_%phi195975%_ _%$%e195940195972%_)
                     (_%$%e195941195977%_
                      (##unchecked-structure-ref
                       _%$%in195934195943%_
                       '4
                       '#f
                       '#f))
                     (_%weak?195980%_ _%$%e195941195977%_))
                (_%$%K195937195959%_
                 _%weak?195980%_
                 _%phi195975%_
                 _%key195970%_
                 _%source195965%_))
              (_%$%E195936195946%_)))))
    (define gx#core-bind-import!__0
      (lambda (_%in195985%_)
        (let* ((_%ctx195987%_ (gx#current-expander-context))
               (_%force-weak?195989%_ '#f))
          (gx#core-bind-import!__%
           _%in195985%_
           _%ctx195987%_
           _%force-weak?195989%_))))
    (define gx#core-bind-import!__1
      (lambda (_%in195991%_ _%ctx195992%_)
        (let ((_%force-weak?195994%_ '#f))
          (gx#core-bind-import!__%
           _%in195991%_
           _%ctx195992%_
           _%force-weak?195994%_))))
    (define gx#core-bind-import!
      (lambda _g197883_
        (let ((_g197884_ (##length _g197883_)))
          (cond ((##fx= _g197884_ 1) (apply gx#core-bind-import!__0 _g197883_))
                ((##fx= _g197884_ 2) (apply gx#core-bind-import!__1 _g197883_))
                ((##fx= _g197884_ 3) (apply gx#core-bind-import!__% _g197883_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-import!
                  _g197883_))))))
    (define gx#core-bind-weak-import!__%
      (lambda (_%in195917%_ _%ctx195918%_)
        (gx#core-bind-import!__% _%in195917%_ _%ctx195918%_ '#t)))
    (define gx#core-bind-weak-import!__0
      (lambda (_%in195923%_)
        (let ((_%ctx195925%_ (gx#current-expander-context)))
          (gx#core-bind-weak-import!__% _%in195923%_ _%ctx195925%_))))
    (define gx#core-bind-weak-import!
      (lambda _g197885_
        (let ((_g197886_ (##length _g197885_)))
          (cond ((##fx= _g197886_ 1)
                 (apply gx#core-bind-weak-import!__0 _g197885_))
                ((##fx= _g197886_ 2)
                 (apply gx#core-bind-weak-import!__% _g197885_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-weak-import!
                  _g197885_))))))
    (define gx#core-resolve-module-export
      (lambda (_%out195810%_)
        (letrec ((_%subst195812%_
                  (lambda (_%key195857%_)
                    (let* ((_%$%key195858195866%_ _%key195857%_)
                           (_%$%else195860195874%_ (lambda () _%key195857%_))
                           (_%$%K195862195904%_
                            (lambda (_%mark195877%_ _%id195878%_)
                              (let* ((_%$%mark195879195885%_ _%mark195877%_)
                                     (_%$%E195881195888%_
                                      (lambda ()
                                        (error '"No clause matching"
                                               _%$%mark195879195885%_
                                               '((expander-mark subst)))
                                        '#!void))
                                     (_%$%K195882195896%_
                                      (lambda (_%subst195891%_)
                                        (let ((_%$e195893%_
                                               (if _%subst195891%_
                                                   (hash-get
                                                    _%subst195891%_
                                                    _%id195878%_)
                                                   '#f)))
                                          (if _%$e195893%_
                                              _%$e195893%_
                                              (gx#raise-syntax-error
                                               '#f
                                               '"Illegal key; missing substitution"
                                               _%key195857%_))))))
                                (if (##structure-instance-of?
                                     _%$%mark195879195885%_
                                     'gx#expander-mark::t)
                                    (let* ((_%$%e195883195899%_
                                            (##unchecked-structure-ref
                                             _%$%mark195879195885%_
                                             '1
                                             '#f
                                             '#f))
                                           (_%subst195902%_
                                            _%$%e195883195899%_))
                                      (_%$%K195882195896%_ _%subst195902%_))
                                    (_%$%E195881195888%_))))))
                      (if (pair? _%$%key195858195866%_)
                          (let ((_%$%hd195863195907%_
                                 (##car _%$%key195858195866%_))
                                (_%$%tl195864195909%_
                                 (##cdr _%$%key195858195866%_)))
                            (let* ((_%id195912%_ _%$%hd195863195907%_)
                                   (_%mark195914%_ _%$%tl195864195909%_))
                              (_%$%K195862195904%_
                               _%mark195914%_
                               _%id195912%_)))
                          (_%$%else195860195874%_))))))
          (let* ((_%$%out195813195823%_ _%out195810%_)
                 (_%$%E195815195826%_
                  (lambda ()
                    (error '"No clause matching"
                           _%$%out195813195823%_
                           '((module-export ctx key phi _ _)))
                    '#!void))
                 (_%$%K195816195833%_
                  (lambda (_%phi195829%_ _%key195830%_ _%ctx195831%_)
                    (gx#core-context-resolve
                     (gx#core-context-shift _%ctx195831%_ _%phi195829%_)
                     (_%subst195812%_ _%key195830%_)))))
            (if (##structure-direct-instance-of?
                 _%$%out195813195823%_
                 'gx#module-export::t)
                (let* ((_%$%e195817195836%_
                        (##unchecked-structure-ref
                         _%$%out195813195823%_
                         '1
                         '#f
                         '#f))
                       (_%ctx195839%_ _%$%e195817195836%_)
                       (_%$%e195818195841%_
                        (##unchecked-structure-ref
                         _%$%out195813195823%_
                         '2
                         '#f
                         '#f))
                       (_%key195844%_ _%$%e195818195841%_)
                       (_%$%e195819195846%_
                        (##unchecked-structure-ref
                         _%$%out195813195823%_
                         '3
                         '#f
                         '#f))
                       (_%phi195849%_ _%$%e195819195846%_)
                       (_%$%e195820195851%_
                        (##unchecked-structure-ref
                         _%$%out195813195823%_
                         '4
                         '#f
                         '#f))
                       (_%$%e195821195854%_
                        (##unchecked-structure-ref
                         _%$%out195813195823%_
                         '5
                         '#f
                         '#f)))
                  (_%$%K195816195833%_
                   _%phi195849%_
                   _%key195844%_
                   _%ctx195839%_))
                (_%$%E195815195826%_))))))
    (define gx#core-module-export->import__%
      (lambda (_%out195736%_ _%rename195737%_ _%dphi195738%_)
        (let* ((_%$%out195739195749%_ _%out195736%_)
               (_%$%E195741195752%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%out195739195749%_
                         '((module-export ctx key phi name weak?)))
                  '#!void))
               (_%$%K195742195764%_
                (lambda (_%weak?195755%_
                         _%name195756%_
                         _%phi195757%_
                         _%key195758%_
                         _%ctx195759%_)
                  (##structure
                   gx#module-import::t
                   _%out195736%_
                   (let ((_%$e195761%_ _%rename195737%_))
                     (if _%$e195761%_ _%$e195761%_ _%name195756%_))
                   (fx+ _%phi195757%_ _%dphi195738%_)
                   _%weak?195755%_))))
          (if (##structure-direct-instance-of?
               _%$%out195739195749%_
               'gx#module-export::t)
              (let* ((_%$%e195743195767%_
                      (##unchecked-structure-ref
                       _%$%out195739195749%_
                       '1
                       '#f
                       '#f))
                     (_%ctx195770%_ _%$%e195743195767%_)
                     (_%$%e195744195772%_
                      (##unchecked-structure-ref
                       _%$%out195739195749%_
                       '2
                       '#f
                       '#f))
                     (_%key195775%_ _%$%e195744195772%_)
                     (_%$%e195745195777%_
                      (##unchecked-structure-ref
                       _%$%out195739195749%_
                       '3
                       '#f
                       '#f))
                     (_%phi195780%_ _%$%e195745195777%_)
                     (_%$%e195746195782%_
                      (##unchecked-structure-ref
                       _%$%out195739195749%_
                       '4
                       '#f
                       '#f))
                     (_%name195785%_ _%$%e195746195782%_)
                     (_%$%e195747195787%_
                      (##unchecked-structure-ref
                       _%$%out195739195749%_
                       '5
                       '#f
                       '#f))
                     (_%weak?195790%_ _%$%e195747195787%_))
                (_%$%K195742195764%_
                 _%weak?195790%_
                 _%name195785%_
                 _%phi195780%_
                 _%key195775%_
                 _%ctx195770%_))
              (_%$%E195741195752%_)))))
    (define gx#core-module-export->import__0
      (lambda (_%out195795%_)
        (let* ((_%rename195797%_ '#f) (_%dphi195799%_ '0))
          (gx#core-module-export->import__%
           _%out195795%_
           _%rename195797%_
           _%dphi195799%_))))
    (define gx#core-module-export->import__1
      (lambda (_%out195801%_ _%rename195802%_)
        (let ((_%dphi195804%_ '0))
          (gx#core-module-export->import__%
           _%out195801%_
           _%rename195802%_
           _%dphi195804%_))))
    (define gx#core-module-export->import
      (lambda _g197887_
        (let ((_g197888_ (##length _g197887_)))
          (cond ((##fx= _g197888_ 1)
                 (apply gx#core-module-export->import__0 _g197887_))
                ((##fx= _g197888_ 2)
                 (apply gx#core-module-export->import__1 _g197887_))
                ((##fx= _g197888_ 3)
                 (apply gx#core-module-export->import__% _g197887_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-module-export->import
                  _g197887_))))))
    (define gx#core-expand-module%
      (lambda (_%stx195635%_)
        (letrec ((_%make-context195637%_
                  (lambda (_%id195714%_)
                    (let* ((_%super195716%_ (gx#current-expander-context))
                           (_%bind-id195718%_ (gx#stx-e _%id195714%_))
                           (_%mod-id195720%_
                            (if (##structure-instance-of?
                                 _%super195716%_
                                 'gx#module-context::t)
                                (make-symbol__1
                                 (##unchecked-structure-ref
                                  _%super195716%_
                                  '1
                                  '#f
                                  '#f)
                                 '"~"
                                 _%bind-id195718%_)
                                _%bind-id195718%_))
                           (_%ns195722%_ (symbol->string _%mod-id195720%_))
                           (_%path195732%_
                            (if (##structure-instance-of?
                                 _%super195716%_
                                 'gx#module-context::t)
                                (let ((_%path195724%_
                                       (##unchecked-structure-ref
                                        _%super195716%_
                                        '7
                                        '#f
                                        '#f)))
                                  (if (or (pair? _%path195724%_)
                                          (null? _%path195724%_))
                                      (cons _%bind-id195718%_ _%path195724%_)
                                      (if _%path195724%_
                                          (cons _%bind-id195718%_
                                                (cons _%path195724%_ '()))
                                          _%bind-id195718%_)))
                                _%bind-id195718%_))
                           (__obj197864
                            (##structure
                             gx#module-context::t
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f
                             '#f)))
                      (gx#module-context:::init!
                       __obj197864
                       _%mod-id195720%_
                       _%super195716%_
                       _%ns195722%_
                       _%path195732%_)
                      __obj197864)))
                 (_%valid-module-id?195638%_
                  (lambda (_%id195689%_)
                    (let* ((_%str195691%_ (symbol->string _%id195689%_))
                           (_%len195693%_ (##string-length _%str195691%_)))
                      (if (##fx>= _%len195693%_ '1)
                          (let _%loop195696%_ ((_%index195698%_
                                                (##fx- (##string-length
                                                        _%str195691%_)
                                                       '1)))
                            (if (##fx>= _%index195698%_ '0)
                                (let ((_%c195700%_
                                       (string-ref
                                        _%str195691%_
                                        _%index195698%_)))
                                  (if (or (and (##char>=? _%c195700%_ '#\a)
                                               (##char<=? _%c195700%_ '#\z))
                                          (and (##char>=? _%c195700%_ '#\A)
                                               (##char<=? _%c195700%_ '#\Z))
                                          (and (##char>=? _%c195700%_ '#\0)
                                               (##char<=? _%c195700%_ '#\9))
                                          (##char=? _%c195700%_ '#\_)
                                          (##char=? _%c195700%_ '#\-))
                                      (_%loop195696%_
                                       (##fx- _%index195698%_ '1))
                                      '#f))
                                '#t))
                          '#f)))))
          (let* ((_%$%e195639195649%_ _%stx195635%_)
                 (_%$%E195641195653%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e195639195649%_)))
                 (_%$%E195640195685%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e195639195649%_)
                        (let ((_%$%e195642195657%_
                               (gx#syntax-e _%$%e195639195649%_)))
                          (let ((_%$%hd195643195660%_
                                 (##car _%$%e195642195657%_))
                                (_%$%tl195644195662%_
                                 (##cdr _%$%e195642195657%_)))
                            (if (gx#stx-pair? _%$%tl195644195662%_)
                                (let ((_%$%e195645195665%_
                                       (gx#syntax-e _%$%tl195644195662%_)))
                                  (let ((_%$%hd195646195668%_
                                         (##car _%$%e195645195665%_))
                                        (_%$%tl195647195670%_
                                         (##cdr _%$%e195645195665%_)))
                                    (let* ((_%id195673%_ _%$%hd195646195668%_)
                                           (_%body195675%_
                                            _%$%tl195647195670%_))
                                      (if (and (gx#identifier? _%id195673%_)
                                               (gx#stx-list? _%body195675%_))
                                          (if (_%valid-module-id?195638%_
                                               (gx#stx-e
                                                (gx#datum->syntax__0 '#f 'id)))
                                              (let* ((_%ctx195677%_
                                                      (_%make-context195637%_
                                                       _%id195673%_))
                                                     (_%body195679%_
                                                      (gx#core-expand-module-begin
                                                       _%body195675%_
                                                       _%ctx195677%_))
                                                     (_%body195681%_
                                                      (gx#core-quote-syntax__1
                                                       (gx#core-cons
                                                        '%#begin
                                                        _%body195679%_)
                                                       (gx#stx-source
                                                        _%stx195635%_))))
                                                (##unchecked-structure-set!
                                                 _%ctx195677%_
                                                 (__make-atomic-promise
                                                  (lambda ()
                                                    (gx#eval-syntax*
                                                     _%body195681%_)))
                                                 '10
                                                 '#f
                                                 '#f)
                                                (##unchecked-structure-set!
                                                 _%ctx195677%_
                                                 _%body195681%_
                                                 '11
                                                 '#f
                                                 '#f)
                                                (gx#core-bind-syntax!__0
                                                 _%id195673%_
                                                 _%ctx195677%_)
                                                (gx#core-quote-syntax__1
                                                 (gx#core-list
                                                  '%#module
                                                  (gx#core-quote-syntax__0
                                                   _%id195673%_)
                                                  _%body195681%_)
                                                 (gx#stx-source
                                                  _%stx195635%_)))
                                              (gx#raise-syntax-error
                                               '#f
                                               '"invalid module id; allowed characters are A-Z,a-z,0-9,_,-"
                                               _%stx195635%_
                                               (gx#datum->syntax__0 '#f 'id)))
                                          (_%$%E195641195653%_)))))
                                (_%$%E195641195653%_))))
                        (_%$%E195641195653%_)))))
            (_%$%E195640195685%_)))))
    (define gx#core-expand-module-begin
      (lambda (_%body195600%_ _%ctx195601%_)
        (call-with-parameters__1
         (lambda ()
           (call-with-parameters__1
            (lambda ()
              (gx#core-bind-feature!__1 'gerbil-module '#t)
              (let* ((_%stx195605%_
                      (gx#core-expand-head
                       (cons '%%begin-module _%body195600%_)))
                     (_%$%e195606195613%_ _%stx195605%_)
                     (_%$%E195608195617%_
                      (lambda ()
                        (gx#raise-syntax-error
                         '#f
                         '"Illegal module body expansion"
                         _%stx195605%_)))
                     (_%$%E195607195631%_
                      (lambda ()
                        (if (gx#stx-pair? _%$%e195606195613%_)
                            (let ((_%$%e195609195621%_
                                   (gx#syntax-e _%$%e195606195613%_)))
                              (let ((_%$%hd195610195624%_
                                     (##car _%$%e195609195621%_))
                                    (_%$%tl195611195626%_
                                     (##cdr _%$%e195609195621%_)))
                                (if (and (gx#identifier? _%$%hd195610195624%_)
                                         (gx#core-identifier=?
                                          _%$%hd195610195624%_
                                          '%#begin-module))
                                    (let ((_%body195629%_
                                           _%$%tl195611195626%_))
                                      (if (gx#sealed-syntax? _%stx195605%_)
                                          _%body195629%_
                                          (gx#core-expand-module-body
                                           _%body195629%_)))
                                    (_%$%E195608195617%_))))
                            (_%$%E195608195617%_)))))
                (_%$%E195607195631%_)))
            gx#current-expander-phi
            '0))
         gx#current-expander-context
         _%ctx195601%_)))
    (define gx#core-expand-module-body
      (lambda (_%body195297%_)
        (letrec ((_%expand-special195299%_
                  (lambda (_%hd195428%_ _%K195429%_ _%rest195430%_ _%r195431%_)
                    (let* ((_%$%e195432195472%_ _%hd195428%_)
                           (_%$%E195467195476%_
                            (lambda ()
                              (_%K195429%_
                               _%rest195430%_
                               (cons (gx#core-expand-top _%hd195428%_)
                                     _%r195431%_))))
                           (_%$%E195454195488%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195432195472%_)
                                  (let ((_%$%e195468195480%_
                                         (gx#syntax-e _%$%e195432195472%_)))
                                    (let ((_%$%hd195469195483%_
                                           (##car _%$%e195468195480%_))
                                          (_%$%tl195470195485%_
                                           (##cdr _%$%e195468195480%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd195469195483%_)
                                               (gx#core-identifier=?
                                                _%$%hd195469195483%_
                                                '%#export))
                                          (_%K195429%_
                                           _%rest195430%_
                                           (cons _%hd195428%_ _%r195431%_))
                                          (_%$%E195467195476%_))))
                                  (_%$%E195467195476%_))))
                           (_%$%E195444195530%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195432195472%_)
                                  (let ((_%$%e195455195492%_
                                         (gx#syntax-e _%$%e195432195472%_)))
                                    (let ((_%$%hd195456195495%_
                                           (##car _%$%e195455195492%_))
                                          (_%$%tl195457195497%_
                                           (##cdr _%$%e195455195492%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd195456195495%_)
                                               (gx#core-identifier=?
                                                _%$%hd195456195495%_
                                                '%#bind-runtime-properties!))
                                          (if (gx#stx-pair?
                                               _%$%tl195457195497%_)
                                              (let ((_%$%e195458195500%_
                                                     (gx#syntax-e
                                                      _%$%tl195457195497%_)))
                                                (let ((_%$%hd195459195503%_
                                                       (##car _%$%e195458195500%_))
                                                      (_%$%tl195460195505%_
                                                       (##cdr _%$%e195458195500%_)))
                                                  (if (gx#stx-pair?
                                                       _%$%hd195459195503%_)
                                                      (let ((_%$%e195464195508%_
                                                             (gx#syntax-e
                                                              _%$%hd195459195503%_)))
                                                        (let ((_%$%hd195465195511%_
                                                               (##car _%$%e195464195508%_))
                                                              (_%$%tl195466195513%_
                                                               (##cdr _%$%e195464195508%_)))
                                                          (let ((_%id195516%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%hd195465195511%_))
                    (if (gx#stx-null? _%$%tl195466195513%_)
                        (if (gx#stx-pair? _%$%tl195460195505%_)
                            (let ((_%$%e195461195518%_
                                   (gx#syntax-e _%$%tl195460195505%_)))
                              (let ((_%$%hd195462195521%_
                                     (##car _%$%e195461195518%_))
                                    (_%$%tl195463195523%_
                                     (##cdr _%$%e195461195518%_)))
                                (let ((_%props195526%_ _%$%hd195462195521%_))
                                  (if (gx#stx-null? _%$%tl195463195523%_)
                                      (let ((_%bind195528%_
                                             (gx#resolve-identifier__0
                                              _%id195516%_)))
                                        (gx#core-bind-runtime-properties!
                                         _%bind195528%_
                                         _%props195526%_)
                                        (_%K195429%_
                                         _%rest195430%_
                                         _%r195431%_))
                                      (_%$%E195454195488%_)))))
                            (_%$%E195454195488%_))
                        (_%$%E195454195488%_)))))
              (_%$%E195454195488%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E195454195488%_))
                                          (_%$%E195454195488%_))))
                                  (_%$%E195454195488%_))))
                           (_%$%E195434195562%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195432195472%_)
                                  (let ((_%$%e195445195534%_
                                         (gx#syntax-e _%$%e195432195472%_)))
                                    (let ((_%$%hd195446195537%_
                                           (##car _%$%e195445195534%_))
                                          (_%$%tl195447195539%_
                                           (##cdr _%$%e195445195534%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd195446195537%_)
                                               (gx#core-identifier=?
                                                _%$%hd195446195537%_
                                                '%#define-values))
                                          (if (gx#stx-pair?
                                               _%$%tl195447195539%_)
                                              (let ((_%$%e195448195542%_
                                                     (gx#syntax-e
                                                      _%$%tl195447195539%_)))
                                                (let ((_%$%hd195449195545%_
                                                       (##car _%$%e195448195542%_))
                                                      (_%$%tl195450195547%_
                                                       (##cdr _%$%e195448195542%_)))
                                                  (let ((_%hd-bind195550%_
                                                         _%$%hd195449195545%_))
                                                    (if (gx#stx-pair?
                                                         _%$%tl195450195547%_)
                                                        (let ((_%$%e195451195552%_
                                                               (gx#syntax-e
                                                                _%$%tl195450195547%_)))
                                                          (let ((_%$%hd195452195555%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e195451195552%_))
                        (_%$%tl195453195557%_ (##cdr _%$%e195451195552%_)))
                    (let ((_%expr195560%_ _%$%hd195452195555%_))
                      (if (gx#stx-null? _%$%tl195453195557%_)
                          (if (gx#core-bind-values? _%hd-bind195550%_)
                              (begin
                                (gx#core-bind-values!__0 _%hd-bind195550%_)
                                (_%K195429%_
                                 _%rest195430%_
                                 (cons _%hd195428%_ _%r195431%_)))
                              (_%$%E195444195530%_))
                          (_%$%E195444195530%_)))))
                (_%$%E195444195530%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E195444195530%_))
                                          (_%$%E195444195530%_))))
                                  (_%$%E195444195530%_))))
                           (_%$%E195433195596%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195432195472%_)
                                  (let ((_%$%e195435195566%_
                                         (gx#syntax-e _%$%e195432195472%_)))
                                    (let ((_%$%hd195436195569%_
                                           (##car _%$%e195435195566%_))
                                          (_%$%tl195437195571%_
                                           (##cdr _%$%e195435195566%_)))
                                      (if (and (gx#identifier?
                                                _%$%hd195436195569%_)
                                               (gx#core-identifier=?
                                                _%$%hd195436195569%_
                                                '%#define-values))
                                          (if (gx#stx-pair?
                                               _%$%tl195437195571%_)
                                              (let ((_%$%e195438195574%_
                                                     (gx#syntax-e
                                                      _%$%tl195437195571%_)))
                                                (let ((_%$%hd195439195577%_
                                                       (##car _%$%e195438195574%_))
                                                      (_%$%tl195440195579%_
                                                       (##cdr _%$%e195438195574%_)))
                                                  (let ((_%hd-bind195582%_
                                                         _%$%hd195439195577%_))
                                                    (if (gx#stx-pair?
                                                         _%$%tl195440195579%_)
                                                        (let ((_%$%e195441195584%_
                                                               (gx#syntax-e
                                                                _%$%tl195440195579%_)))
                                                          (let ((_%$%hd195442195587%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (##car _%$%e195441195584%_))
                        (_%$%tl195443195589%_ (##cdr _%$%e195441195584%_)))
                    (let* ((_%expr195592%_ _%$%hd195442195587%_)
                           (_%props195594%_ _%$%tl195443195589%_))
                      (if (and (gx#core-bind-values? _%hd-bind195582%_)
                               (gx#stx-list? _%props195594%_)
                               (not (gx#stx-null? _%props195594%_)))
                          (begin
                            (gx#core-bind-values!__0 _%hd-bind195582%_)
                            (_%K195429%_
                             (cons (gx#core-cons
                                    '%#bind-runtime-properties!
                                    (cons _%hd-bind195582%_
                                          (cons _%props195594%_ '())))
                                   _%rest195430%_)
                             (cons (gx#core-cons
                                    '%#define-values
                                    (cons _%hd-bind195582%_
                                          (cons _%expr195592%_ '())))
                                   _%r195431%_)))
                          (_%$%E195434195562%_)))))
                (_%$%E195434195562%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E195434195562%_))
                                          (_%$%E195434195562%_))))
                                  (_%$%E195434195562%_)))))
                      (_%$%E195433195596%_))))
                 (_%expand-body195300%_
                  (lambda (_%rbody195302%_)
                    (let _%lp195304%_ ((_%rest195306%_ _%rbody195302%_)
                                       (_%body195307%_ '()))
                      (let* ((_%$%rest195308195316%_ _%rest195306%_)
                             (_%$%else195310195324%_
                              (lambda () _%body195307%_))
                             (_%$%K195312195416%_
                              (lambda (_%rest195327%_ _%hd195328%_)
                                (let* ((_%$%e195329195350%_ _%hd195328%_)
                                       (_%$%E195345195354%_
                                        (lambda ()
                                          (_%lp195304%_
                                           _%rest195327%_
                                           (cons (gx#core-expand-expression
                                                  _%hd195328%_)
                                                 _%body195307%_))))
                                       (_%$%E195341195368%_
                                        (lambda ()
                                          (if (gx#stx-pair?
                                               _%$%e195329195350%_)
                                              (let ((_%$%e195346195358%_
                                                     (gx#syntax-e
                                                      _%$%e195329195350%_)))
                                                (let ((_%$%hd195347195361%_
                                                       (##car _%$%e195346195358%_))
                                                      (_%$%tl195348195363%_
                                                       (##cdr _%$%e195346195358%_)))
                                                  (let ((_%form195366%_
                                                         _%$%hd195347195361%_))
                                                    (if (gx#core-bound-identifier?__%
                                                         _%form195366%_
                                                         gx#special-form-binding?)
                                                        (_%lp195304%_
                                                         _%rest195327%_
                                                         (cons _%hd195328%_
                                                               _%body195307%_))
                                                        (_%$%E195345195354%_)))))
                                              (_%$%E195345195354%_))))
                                       (_%$%E195331195380%_
                                        (lambda ()
                                          (if (gx#stx-pair?
                                               _%$%e195329195350%_)
                                              (let ((_%$%e195342195372%_
                                                     (gx#syntax-e
                                                      _%$%e195329195350%_)))
                                                (let ((_%$%hd195343195375%_
                                                       (##car _%$%e195342195372%_))
                                                      (_%$%tl195344195377%_
                                                       (##cdr _%$%e195342195372%_)))
                                                  (if (and (gx#identifier?
                                                            _%$%hd195343195375%_)
                                                           (gx#core-identifier=?
                                                            _%$%hd195343195375%_
                                                            '%#export))
                                                      (_%lp195304%_
                                                       _%rest195327%_
                                                       (cons (gx#core-expand-export%__0
                                                              _%hd195328%_)
                                                             _%body195307%_))
                                                      (_%$%E195341195368%_))))
                                              (_%$%E195341195368%_))))
                                       (_%$%E195330195412%_
                                        (lambda ()
                                          (if (gx#stx-pair?
                                               _%$%e195329195350%_)
                                              (let ((_%$%e195332195384%_
                                                     (gx#syntax-e
                                                      _%$%e195329195350%_)))
                                                (let ((_%$%hd195333195387%_
                                                       (##car _%$%e195332195384%_))
                                                      (_%$%tl195334195389%_
                                                       (##cdr _%$%e195332195384%_)))
                                                  (if (and (gx#identifier?
                                                            _%$%hd195333195387%_)
                                                           (gx#core-identifier=?
                                                            _%$%hd195333195387%_
                                                            '%#define-values))
                                                      (if (gx#stx-pair?
                                                           _%$%tl195334195389%_)
                                                          (let ((_%$%e195335195392%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl195334195389%_)))
                    (let ((_%$%hd195336195395%_ (##car _%$%e195335195392%_))
                          (_%$%tl195337195397%_ (##cdr _%$%e195335195392%_)))
                      (let ((_%hd-bind195400%_ _%$%hd195336195395%_))
                        (if (gx#stx-pair? _%$%tl195337195397%_)
                            (let ((_%$%e195338195402%_
                                   (gx#syntax-e _%$%tl195337195397%_)))
                              (let ((_%$%hd195339195405%_
                                     (##car _%$%e195338195402%_))
                                    (_%$%tl195340195407%_
                                     (##cdr _%$%e195338195402%_)))
                                (let ((_%expr195410%_ _%$%hd195339195405%_))
                                  (if (gx#stx-null? _%$%tl195340195407%_)
                                      (_%lp195304%_
                                       _%rest195327%_
                                       (cons (gx#core-quote-syntax__1
                                              (gx#core-list
                                               '%#define-values
                                               (gx#core-quote-bind-values
                                                _%hd-bind195400%_)
                                               (gx#core-expand-expression
                                                _%expr195410%_))
                                              (gx#stx-source _%hd195328%_))
                                             _%body195307%_))
                                      (_%$%E195331195380%_)))))
                            (_%$%E195331195380%_)))))
                  (_%$%E195331195380%_))
              (_%$%E195331195380%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E195331195380%_)))))
                                  (_%$%E195330195412%_)))))
                        (if (pair? _%$%rest195308195316%_)
                            (let ((_%$%hd195313195419%_
                                   (##car _%$%rest195308195316%_))
                                  (_%$%tl195314195421%_
                                   (##cdr _%$%rest195308195316%_)))
                              (let* ((_%hd195424%_ _%$%hd195313195419%_)
                                     (_%rest195426%_ _%$%tl195314195421%_))
                                (_%$%K195312195416%_
                                 _%rest195426%_
                                 _%hd195424%_)))
                            (_%$%else195310195324%_)))))))
          (_%expand-body195300%_
           (gx#core-expand-block__%
            (cons '%#begin-module _%body195297%_)
            _%expand-special195299%_
            '#f
            values)))))
    (define gx#core-expand-import/export
      (lambda (_%stx195138%_
               _%expanded?195139%_
               _%method195140%_
               _%current-phi195141%_
               _%expand1195142%_)
        (letrec ((_%K195144%_
                  (lambda (_%rest195264%_ _%r195265%_)
                    (let* ((_%$%e195266195273%_ _%rest195264%_)
                           (_%$%E195268195277%_ (lambda () _%r195265%_))
                           (_%$%E195267195293%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195266195273%_)
                                  (let ((_%$%e195269195281%_
                                         (gx#syntax-e _%$%e195266195273%_)))
                                    (let ((_%$%hd195270195284%_
                                           (##car _%$%e195269195281%_))
                                          (_%$%tl195271195286%_
                                           (##cdr _%$%e195269195281%_)))
                                      (let* ((_%hd195289%_
                                              _%$%hd195270195284%_)
                                             (_%rest195291%_
                                              _%$%tl195271195286%_))
                                        (_%step195145%_
                                         _%hd195289%_
                                         _%rest195291%_
                                         _%r195265%_))))
                                  (_%$%E195268195277%_)))))
                      (_%$%E195267195293%_))))
                 (_%step195145%_
                  (lambda (_%hd195178%_ _%rest195179%_ _%r195180%_)
                    (let* ((_%$%e195181195199%_ _%hd195178%_)
                           (_%$%E195194195203%_
                            (lambda ()
                              (if (_%expanded?195139%_ (gx#stx-e _%hd195178%_))
                                  (_%K195144%_
                                   _%rest195179%_
                                   (cons (gx#stx-e _%hd195178%_) _%r195180%_))
                                  (_%expand1195142%_
                                   _%hd195178%_
                                   _%K195144%_
                                   _%rest195179%_
                                   _%r195180%_))))
                           (_%$%E195190195219%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195181195199%_)
                                  (let ((_%$%e195195195207%_
                                         (gx#syntax-e _%$%e195181195199%_)))
                                    (let ((_%$%hd195196195210%_
                                           (##car _%$%e195195195207%_))
                                          (_%$%tl195197195212%_
                                           (##cdr _%$%e195195195207%_)))
                                      (let* ((_%macro195215%_
                                              _%$%hd195196195210%_)
                                             (_%body195217%_
                                              _%$%tl195197195212%_))
                                        (if (gx#core-bound-identifier?__%
                                             _%macro195215%_
                                             gx#syntax-binding?)
                                            (_%K195144%_
                                             (cons (gx#core-apply-expander__%
                                                    (gx#syntax-local-e__0
                                                     _%macro195215%_)
                                                    _%hd195178%_
                                                    _%method195140%_)
                                                   _%rest195179%_)
                                             _%r195180%_)
                                            (_%$%E195194195203%_)))))
                                  (_%$%E195194195203%_))))
                           (_%$%E195183195233%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195181195199%_)
                                  (let ((_%$%e195191195223%_
                                         (gx#syntax-e _%$%e195181195199%_)))
                                    (let ((_%$%hd195192195226%_
                                           (##car _%$%e195191195223%_))
                                          (_%$%tl195193195228%_
                                           (##cdr _%$%e195191195223%_)))
                                      (if (eq? (gx#stx-e _%$%hd195192195226%_)
                                               'begin:)
                                          (let ((_%body195231%_
                                                 _%$%tl195193195228%_))
                                            (_%K195144%_
                                             (gx#stx-foldr
                                              cons
                                              _%rest195179%_
                                              _%body195231%_)
                                             _%r195180%_))
                                          (_%$%E195190195219%_))))
                                  (_%$%E195190195219%_))))
                           (_%$%E195182195260%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195181195199%_)
                                  (let ((_%$%e195184195237%_
                                         (gx#syntax-e _%$%e195181195199%_)))
                                    (let ((_%$%hd195185195240%_
                                           (##car _%$%e195184195237%_))
                                          (_%$%tl195186195242%_
                                           (##cdr _%$%e195184195237%_)))
                                      (if (eq? (gx#stx-e _%$%hd195185195240%_)
                                               'phi:)
                                          (if (gx#stx-pair?
                                               _%$%tl195186195242%_)
                                              (let ((_%$%e195187195245%_
                                                     (gx#syntax-e
                                                      _%$%tl195186195242%_)))
                                                (let ((_%$%hd195188195248%_
                                                       (##car _%$%e195187195245%_))
                                                      (_%$%tl195189195250%_
                                                       (##cdr _%$%e195187195245%_)))
                                                  (let* ((_%dphi195253%_
                                                          _%$%hd195188195248%_)
                                                         (_%body195255%_
                                                          _%$%tl195189195250%_))
                                                    (if (gx#stx-fixnum?
                                                         _%dphi195253%_)
                                                        (let ((_%rbody195258%_
                                                               (call-with-parameters__1
                                                                (lambda ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (_%K195144%_ _%body195255%_ '()))
                        _%current-phi195141%_
                        (fx+ (gx#stx-e _%dphi195253%_)
                             (_%current-phi195141%_)))))
                  (_%K195144%_
                   _%rest195179%_
                   (append _%rbody195258%_ _%r195180%_)))
                (_%$%E195183195233%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E195183195233%_))
                                          (_%$%E195183195233%_))))
                                  (_%$%E195183195233%_)))))
                      (_%$%E195182195260%_)))))
          (let* ((_%$%e195146195153%_ _%stx195138%_)
                 (_%$%E195148195157%_
                  (lambda ()
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid syntax-case clause"
                     _%$%e195146195153%_)))
                 (_%$%E195147195174%_
                  (lambda ()
                    (if (gx#stx-pair? _%$%e195146195153%_)
                        (let ((_%$%e195149195161%_
                               (gx#syntax-e _%$%e195146195153%_)))
                          (let ((_%$%hd195150195164%_
                                 (##car _%$%e195149195161%_))
                                (_%$%tl195151195166%_
                                 (##cdr _%$%e195149195161%_)))
                            (let ((_%body195169%_ _%$%tl195151195166%_))
                              (if (_%current-phi195141%_)
                                  (_%K195144%_ _%body195169%_ '())
                                  (call-with-parameters__1
                                   (lambda () (_%K195144%_ _%body195169%_ '()))
                                   _%current-phi195141%_
                                   (gx#current-expander-phi))))))
                        (_%$%E195148195157%_)))))
            (_%$%E195147195174%_)))))
    (define gx#core-expand-import%__%
      (lambda (_%stx194792%_ _%internal-expand?194793%_)
        (letrec ((_%expand1194795%_
                  (lambda (_%hd195110%_ _%K195111%_ _%rest195112%_ _%r195113%_)
                    (if (gx#core-bound-module? _%hd195110%_)
                        (_%import1194796%_
                         (gx#syntax-local-e__0 _%hd195110%_)
                         _%K195111%_
                         _%rest195112%_
                         _%r195113%_)
                        (if (gx#core-library-module-path? _%hd195110%_)
                            (_%import1194796%_
                             (gx#import-module__0
                              (gx#core-resolve-library-module-path
                               _%hd195110%_))
                             _%K195111%_
                             _%rest195112%_
                             _%r195113%_)
                            (if (gx#core-library-relative-module-path?
                                 _%hd195110%_)
                                (_%import1194796%_
                                 (gx#import-module__0
                                  (gx#core-resolve-library-relative-module-path
                                   _%hd195110%_))
                                 _%K195111%_
                                 _%rest195112%_
                                 _%r195113%_)
                                (let ((_%e195119%_ (gx#stx-e _%hd195110%_)))
                                  (if (pair? _%e195119%_)
                                      (let ((_%$e195122%_
                                             (gx#stx-e (##car _%e195119%_))))
                                        (if (eq? 'spec: _%$e195122%_)
                                            (_%import-spec194799%_
                                             _%hd195110%_
                                             _%K195111%_
                                             _%rest195112%_
                                             _%r195113%_)
                                            (if (eq? 'in: _%$e195122%_)
                                                (_%import-submodule194797%_
                                                 _%hd195110%_
                                                 _%K195111%_
                                                 _%rest195112%_
                                                 _%r195113%_)
                                                (if (eq? 'runtime:
                                                         _%$e195122%_)
                                                    (_%import-runtime194798%_
                                                     _%hd195110%_
                                                     _%K195111%_
                                                     _%rest195112%_
                                                     _%r195113%_)
                                                    (gx#raise-syntax-error
                                                     '#f
                                                     '"Bad syntax; illegal import"
                                                     _%stx194792%_
                                                     _%hd195110%_)))))
                                      (if (string? _%e195119%_)
                                          (_%import1194796%_
                                           (gx#import-module__0
                                            (gx#core-resolve-module-path__%
                                             _%hd195110%_
                                             (gx#stx-source _%stx194792%_)))
                                           _%K195111%_
                                           _%rest195112%_
                                           _%r195113%_)
                                          (if (##structure-instance-of?
                                               _%e195119%_
                                               'gx#module-context::t)
                                              (_%K195111%_
                                               _%rest195112%_
                                               (cons _%e195119%_ _%r195113%_))
                                              (gx#raise-syntax-error
                                               '#f
                                               '"Bad syntax; illegal import"
                                               _%stx194792%_
                                               _%hd195110%_))))))))))
                 (_%import1194796%_
                  (lambda (_%ctx195099%_
                           _%K195100%_
                           _%rest195101%_
                           _%r195102%_)
                    (let ((_%dphi195104%_
                           (fx- (gx#current-import-expander-phi)
                                (gx#current-expander-phi))))
                      (_%K195100%_
                       _%rest195101%_
                       (cons (##structure
                              gx#import-set::t
                              _%ctx195099%_
                              _%dphi195104%_
                              (map (lambda (_%$%g195105195107%_)
                                     (gx#core-module-export->import__%
                                      _%$%g195105195107%_
                                      '#f
                                      _%dphi195104%_))
                                   (##unchecked-structure-ref
                                    _%ctx195099%_
                                    '9
                                    '#f
                                    '#f)))
                             _%r195102%_)))))
                 (_%import-submodule194797%_
                  (lambda (_%hd195066%_ _%K195067%_ _%rest195068%_ _%r195069%_)
                    (let* ((_%$%e195070195077%_ _%hd195066%_)
                           (_%$%E195072195081%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e195070195077%_)))
                           (_%$%E195071195095%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195070195077%_)
                                  (let ((_%$%e195073195085%_
                                         (gx#syntax-e _%$%e195070195077%_)))
                                    (let ((_%$%hd195074195088%_
                                           (##car _%$%e195073195085%_))
                                          (_%$%tl195075195090%_
                                           (##cdr _%$%e195073195085%_)))
                                      (let ((_%spath195093%_
                                             _%$%tl195075195090%_))
                                        (_%import1194796%_
                                         (_%import-spec-source194800%_
                                          _%spath195093%_)
                                         _%K195067%_
                                         _%rest195068%_
                                         _%r195069%_))))
                                  (_%$%E195072195081%_)))))
                      (_%$%E195071195095%_))))
                 (_%import-runtime194798%_
                  (lambda (_%hd195033%_ _%K195034%_ _%rest195035%_ _%r195036%_)
                    (let* ((_%$%e195037195044%_ _%hd195033%_)
                           (_%$%E195039195048%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e195037195044%_)))
                           (_%$%E195038195062%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e195037195044%_)
                                  (let ((_%$%e195040195052%_
                                         (gx#syntax-e _%$%e195037195044%_)))
                                    (let ((_%$%hd195041195055%_
                                           (##car _%$%e195040195052%_))
                                          (_%$%tl195042195057%_
                                           (##cdr _%$%e195040195052%_)))
                                      (let ((_%spath195060%_
                                             _%$%tl195042195057%_))
                                        (_%K195034%_
                                         _%rest195035%_
                                         (cons (_%import-spec-source194800%_
                                                _%spath195060%_)
                                               _%r195036%_)))))
                                  (_%$%E195039195048%_)))))
                      (_%$%E195038195062%_))))
                 (_%import-spec194799%_
                  (lambda (_%hd194871%_ _%K194872%_ _%rest194873%_ _%r194874%_)
                    (let* ((_%$%e194875194892%_ _%hd194871%_)
                           (_%$%E194884194896%_
                            (lambda ()
                              (gx#raise-syntax-error
                               '#f
                               '"Bad syntax; invalid syntax-case clause"
                               _%$%e194875194892%_)))
                           (_%$%E194877195007%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e194875194892%_)
                                  (let ((_%$%e194885194900%_
                                         (gx#syntax-e _%$%e194875194892%_)))
                                    (let ((_%$%hd194886194903%_
                                           (##car _%$%e194885194900%_))
                                          (_%$%tl194887194905%_
                                           (##cdr _%$%e194885194900%_)))
                                      (if (gx#stx-pair? _%$%tl194887194905%_)
                                          (let ((_%$%e194888194908%_
                                                 (gx#syntax-e
                                                  _%$%tl194887194905%_)))
                                            (let ((_%$%hd194889194911%_
                                                   (##car _%$%e194888194908%_))
                                                  (_%$%tl194890194913%_
                                                   (##cdr _%$%e194888194908%_)))
                                              (let* ((_%path194916%_
                                                      _%$%hd194889194911%_)
                                                     (_%specs194918%_
                                                      _%$%tl194890194913%_))
                                                (let ((_%src-ctx194920%_
                                                       (_%import-spec-source194800%_
                                                        _%path194916%_))
                                                      (_%exports194921%_
                                                       (make-hash-table__%
                                                        '#f
                                                        absent-value
                                                        absent-value
                                                        absent-value
                                                        absent-value
                                                        absent-value
                                                        absent-value
                                                        absent-value
                                                        absent-value))
                                                      (_%specs194922%_
                                                       (gx#syntax->list
                                                        _%specs194918%_)))
                                                  (for-each
                                                   (lambda (_%out194924%_)
                                                     (__hash-put!
                                                      _%exports194921%_
                                                      (cons (##unchecked-structure-ref
                                                             _%out194924%_
                                                             '3
                                                             '#f
                                                             '#f)
                                                            (##unchecked-structure-ref
                                                             _%out194924%_
                                                             '4
                                                             '#f
                                                             '#f))
                                                      _%out194924%_))
                                                   (##unchecked-structure-ref
                                                    _%src-ctx194920%_
                                                    '9
                                                    '#f
                                                    '#f))
                                                  (_%K194872%_
                                                   _%rest194873%_
                                                   (foldl__0
                                                    (lambda (_%spec194926%_
                                                             _%r194927%_)
                                                      (let* ((_%$%e194928194944%_
                                                              _%spec194926%_)
                                                             (_%$%E194930194948%_
                                                              (lambda ()
                                                                (gx#raise-syntax-error
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '#f
                         '"Bad syntax; invalid syntax-case clause"
                         _%$%e194928194944%_)))
                     (_%$%E194929195003%_
                      (lambda ()
                        (if (gx#stx-pair? _%$%e194928194944%_)
                            (let ((_%$%e194931194952%_
                                   (gx#syntax-e _%$%e194928194944%_)))
                              (let ((_%$%hd194932194955%_
                                     (##car _%$%e194931194952%_))
                                    (_%$%tl194933194957%_
                                     (##cdr _%$%e194931194952%_)))
                                (let ((_%phi194960%_ _%$%hd194932194955%_))
                                  (if (gx#stx-pair? _%$%tl194933194957%_)
                                      (let ((_%$%e194934194962%_
                                             (gx#syntax-e
                                              _%$%tl194933194957%_)))
                                        (let ((_%$%hd194935194965%_
                                               (##car _%$%e194934194962%_))
                                              (_%$%tl194936194967%_
                                               (##cdr _%$%e194934194962%_)))
                                          (let ((_%name194970%_
                                                 _%$%hd194935194965%_))
                                            (if (gx#stx-pair?
                                                 _%$%tl194936194967%_)
                                                (let ((_%$%e194937194972%_
                                                       (gx#syntax-e
                                                        _%$%tl194936194967%_)))
                                                  (let ((_%$%hd194938194975%_
                                                         (##car _%$%e194937194972%_))
                                                        (_%$%tl194939194977%_
                                                         (##cdr _%$%e194937194972%_)))
                                                    (let ((_%src-phi194980%_
                                                           _%$%hd194938194975%_))
                                                      (if (gx#stx-pair?
                                                           _%$%tl194939194977%_)
                                                          (let ((_%$%e194940194982%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (gx#syntax-e _%$%tl194939194977%_)))
                    (let ((_%$%hd194941194985%_ (##car _%$%e194940194982%_))
                          (_%$%tl194942194987%_ (##cdr _%$%e194940194982%_)))
                      (let ((_%src-name194990%_ _%$%hd194941194985%_))
                        (if (gx#stx-null? _%$%tl194942194987%_)
                            (if (and (gx#stx-fixnum? _%src-phi194980%_)
                                     (gx#identifier? _%src-name194990%_)
                                     (gx#stx-fixnum? _%phi194960%_)
                                     (gx#identifier? _%name194970%_))
                                (let ((_%src-phi194992%_
                                       (gx#stx-e _%src-phi194980%_))
                                      (_%src-name194993%_
                                       (gx#core-identifier-key
                                        _%src-name194990%_))
                                      (_%phi194994%_ (gx#stx-e _%phi194960%_))
                                      (_%name194995%_
                                       (gx#core-identifier-key
                                        _%name194970%_)))
                                  (let ((_%$e194997%_
                                         (__hash-get
                                          _%exports194921%_
                                          (cons _%src-phi194992%_
                                                _%src-name194993%_))))
                                    (if _%$e194997%_
                                        (cons (gx#core-module-export->import__%
                                               _%$e194997%_
                                               _%name194995%_
                                               (fx- _%phi194994%_
                                                    _%src-phi194992%_))
                                              _%r194927%_)
                                        (gx#raise-syntax-error
                                         '#f
                                         '"Bad syntax; no matching export"
                                         _%stx194792%_
                                         _%hd194871%_))))
                                (_%$%E194930194948%_))
                            (_%$%E194930194948%_)))))
                  (_%$%E194930194948%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%E194930194948%_)))))
                                      (_%$%E194930194948%_)))))
                            (_%$%E194930194948%_)))))
                (_%$%E194929195003%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    _%r194874%_
                                                    _%specs194922%_))))))
                                          (_%$%E194884194896%_))))
                                  (_%$%E194884194896%_))))
                           (_%$%E194876195029%_
                            (lambda ()
                              (if (gx#stx-pair? _%$%e194875194892%_)
                                  (let ((_%$%e194878195011%_
                                         (gx#syntax-e _%$%e194875194892%_)))
                                    (let ((_%$%hd194879195014%_
                                           (##car _%$%e194878195011%_))
                                          (_%$%tl194880195016%_
                                           (##cdr _%$%e194878195011%_)))
                                      (if (gx#stx-pair? _%$%tl194880195016%_)
                                          (let ((_%$%e194881195019%_
                                                 (gx#syntax-e
                                                  _%$%tl194880195016%_)))
                                            (let ((_%$%hd194882195022%_
                                                   (##car _%$%e194881195019%_))
                                                  (_%$%tl194883195024%_
                                                   (##cdr _%$%e194881195019%_)))
                                              (let ((_%path195027%_
                                                     _%$%hd194882195022%_))
                                                (if (gx#stx-null?
                                                     _%$%tl194883195024%_)
                                                    (_%K194872%_
                                                     _%rest194873%_
                                                     (cons (_%import-spec-source194800%_
                                                            _%path195027%_)
                                                           _%r194874%_))
                                                    (_%$%E194877195007%_)))))
                                          (_%$%E194877195007%_))))
                                  (_%$%E194877195007%_)))))
                      (_%$%E194876195029%_))))
                 (_%import-spec-source194800%_
                  (lambda (_%spath194869%_)
                    (gx#core-import-nested-module
                     _%spath194869%_
                     _%stx194792%_)))
                 (_%import!194801%_
                  (lambda (_%rbody194814%_)
                    (letrec* ((_%current-ctx194816%_
                               (gx#current-expander-context))
                              (_%deps194817%_ (make-hash-table-eq))
                              (_%bind!194818%_
                               (lambda (_%hd194867%_)
                                 (gx#core-bind-import!__1
                                  _%hd194867%_
                                  _%current-ctx194816%_))))
                      (let _%lp194820%_ ((_%rest194822%_ _%rbody194814%_)
                                         (_%body194823%_ '()))
                        (let* ((_%$%rest194824194832%_ _%rest194822%_)
                               (_%$%else194826194843%_
                                (lambda ()
                                  (if (##structure-instance-of?
                                       _%current-ctx194816%_
                                       'gx#module-context::t)
                                      (##unchecked-structure-set!
                                       _%current-ctx194816%_
                                       (foldl__0
                                        cons
                                        (##unchecked-structure-ref
                                         _%current-ctx194816%_
                                         '8
                                         '#f
                                         '#f)
                                        _%body194823%_)
                                       '8
                                       '#f
                                       '#f)
                                      '#!void)
                                  (__hash-for-each
                                   (lambda (_%ctx194840%_ _%_194841%_)
                                     (gx#eval-module _%ctx194840%_))
                                   _%deps194817%_)
                                  _%body194823%_))
                               (_%$%K194828194855%_
                                (lambda (_%rest194846%_ _%hd194847%_)
                                  (if (##structure-direct-instance-of?
                                       _%hd194847%_
                                       'gx#module-import::t)
                                      (let ()
                                        (_%bind!194818%_ _%hd194847%_)
                                        (if (and (fxpositive?
                                                  (##unchecked-structure-ref
                                                   _%hd194847%_
                                                   '3
                                                   '#f
                                                   '#f))
                                                 (fxzero? (##unchecked-structure-ref
                                                           (##unchecked-structure-ref
                                                            _%hd194847%_
                                                            '1
                                                            '#f
                                                            '#f)
                                                           '3
                                                           '#f
                                                           '#f)))
                                            (__hash-put!
                                             _%deps194817%_
                                             (##unchecked-structure-ref
                                              (##unchecked-structure-ref
                                               _%hd194847%_
                                               '1
                                               '#f
                                               '#f)
                                              '1
                                              '#f
                                              '#f)
                                             '#t)
                                            '#!void))
                                      (if (##structure-direct-instance-of?
                                           _%hd194847%_
                                           'gx#import-set::t)
                                          (let ()
                                            (for-each
                                             _%bind!194818%_
                                             (##unchecked-structure-ref
                                              _%hd194847%_
                                              '3
                                              '#f
                                              '#f))
                                            (if (fxpositive?
                                                 (##unchecked-structure-ref
                                                  _%hd194847%_
                                                  '2
                                                  '#f
                                                  '#f))
                                                (__hash-put!
                                                 _%deps194817%_
                                                 (##unchecked-structure-ref
                                                  _%hd194847%_
                                                  '1
                                                  '#f
                                                  '#f)
                                                 '#t)
                                                '#!void))
                                          (let ((_%$e194851%_
                                                 (##structure-instance-of?
                                                  _%hd194847%_
                                                  'gx#module-context::t)))
                                            (if _%$e194851%_
                                                _%$e194851%_
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Unexpected import"
                                                 _%stx194792%_
                                                 _%hd194847%_)))))
                                  (_%lp194820%_
                                   _%rest194846%_
                                   (cons _%hd194847%_ _%body194823%_)))))
                          (if (pair? _%$%rest194824194832%_)
                              (let ((_%$%hd194829194858%_
                                     (##car _%$%rest194824194832%_))
                                    (_%$%tl194830194860%_
                                     (##cdr _%$%rest194824194832%_)))
                                (let* ((_%hd194863%_ _%$%hd194829194858%_)
                                       (_%rest194865%_ _%$%tl194830194860%_))
                                  (_%$%K194828194855%_
                                   _%rest194865%_
                                   _%hd194863%_)))
                              (_%$%else194826194843%_)))))))
                 (_%expanded-import?194802%_
                  (lambda (_%e194806%_)
                    (let ((_%$e194808%_
                           (##structure-direct-instance-of?
                            _%e194806%_
                            'gx#import-set::t)))
                      (if _%$e194808%_
                          _%$e194808%_
                          (let ((_%$e194811%_
                                 (##structure-direct-instance-of?
                                  _%e194806%_
                                  'gx#module-import::t)))
                            (if _%$e194811%_
                                _%$e194811%_
                                (##structure-instance-of?
                                 _%e194806%_
                                 'gx#module-context::t))))))))
          (let ((_%rbody194804%_
                 (gx#core-expand-import/export
                  _%stx194792%_
                  _%expanded-import?194802%_
                  'apply-import-expander
                  gx#current-import-expander-phi
                  _%expand1194795%_)))
            (if _%internal-expand?194793%_
                (reverse _%rbody194804%_)
                (gx#core-quote-syntax__1
                 (gx#core-cons '%#import (_%import!194801%_ _%rbody194804%_))
                 (gx#stx-source _%stx194792%_)))))))
    (define gx#core-expand-import%__0
      (lambda (_%stx195131%_)
        (let ((_%internal-expand?195133%_ '#f))
          (gx#core-expand-import%__%
           _%stx195131%_
           _%internal-expand?195133%_))))
    (define gx#core-expand-import%
      (lambda _g197889_
        (let ((_g197890_ (##length _g197889_)))
          (cond ((##fx= _g197890_ 1)
                 (apply gx#core-expand-import%__0 _g197889_))
                ((##fx= _g197890_ 2)
                 (apply gx#core-expand-import%__% _g197889_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-import%
                  _g197889_))))))
    (define gx#core-import-nested-module
      (lambda (_%spath194719%_ _%where194720%_)
        (let* ((_%$%e194721194728%_ _%spath194719%_)
               (_%$%E194723194732%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e194721194728%_)))
               (_%$%E194722194787%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e194721194728%_)
                      (let ((_%$%e194724194736%_
                             (gx#syntax-e _%$%e194721194728%_)))
                        (let ((_%$%hd194725194739%_
                               (##car _%$%e194724194736%_))
                              (_%$%tl194726194741%_
                               (##cdr _%$%e194724194736%_)))
                          (let* ((_%origin194744%_ _%$%hd194725194739%_)
                                 (_%sub194746%_ _%$%tl194726194741%_)
                                 (_%origin-ctx194748%_
                                  (if (gx#stx-false? _%origin194744%_)
                                      (gx#current-expander-context)
                                      (gx#import-module__0 _%origin194744%_))))
                            (let _%lp194750%_ ((_%rest194752%_ _%sub194746%_)
                                               (_%ctx194753%_
                                                _%origin-ctx194748%_))
                              (let* ((_%$%e194754194761%_ _%rest194752%_)
                                     (_%$%E194756194765%_
                                      (lambda () _%ctx194753%_))
                                     (_%$%E194755194783%_
                                      (lambda ()
                                        (if (gx#stx-pair? _%$%e194754194761%_)
                                            (let ((_%$%e194757194769%_
                                                   (gx#syntax-e
                                                    _%$%e194754194761%_)))
                                              (let ((_%$%hd194758194772%_
                                                     (##car _%$%e194757194769%_))
                                                    (_%$%tl194759194774%_
                                                     (##cdr _%$%e194757194769%_)))
                                                (let* ((_%id194777%_
                                                        _%$%hd194758194772%_)
                                                       (_%rest194779%_
                                                        _%$%tl194759194774%_)
                                                       (_%bind194781%_
                                                        (gx#resolve-identifier__%
                                                         _%id194777%_
                                                         '0
                                                         _%ctx194753%_)))
                                                  (if (and (##structure-direct-instance-of?
                                                            _%bind194781%_
                                                            'gx#syntax-binding::t)
                                                           (##structure-instance-of?
                                                            (##unchecked-structure-ref
                                                             _%bind194781%_
                                                             '5
                                                             '#f
                                                             '#f)
                                                            'gx#module-context::t))
                                                      '#!void
                                                      (gx#raise-syntax-error
                                                       '#f
                                                       '"Bad syntax; not bound as module"
                                                       _%where194720%_
                                                       _%spath194719%_
                                                       _%id194777%_))
                                                  (_%lp194750%_
                                                   _%rest194779%_
                                                   (##unchecked-structure-ref
                                                    _%bind194781%_
                                                    '5
                                                    '#f
                                                    '#f)))))
                                            (_%$%E194756194765%_)))))
                                (_%$%E194755194783%_))))))
                      (_%$%E194723194732%_)))))
          (_%$%E194722194787%_))))
    (define gx#core-expand-import-source
      (lambda (_%hd194717%_)
        (gx#core-expand-import%__%
         (cons 'import-internal% (cons _%hd194717%_ '()))
         '#t)))
    (define gx#core-expand-export%__%
      (lambda (_%stx194212%_ _%internal-expand?194213%_)
        (letrec* ((_%make-export__197817197818%_
                   (lambda (_%bind194665%_
                            _%phi194666%_
                            _%ctx194667%_
                            _%name194668%_)
                     (let* ((_%key194670%_
                             (##unchecked-structure-ref
                              _%bind194665%_
                              '2
                              '#f
                              '#f))
                            (_%export-key194672%_
                             (if _%name194668%_
                                 (gx#core-identifier-key _%name194668%_)
                                 _%key194670%_)))
                       (##structure
                        gx#module-export::t
                        _%ctx194667%_
                        _%key194670%_
                        _%phi194666%_
                        _%export-key194672%_
                        (let ((_%$e194675%_
                               (##structure-instance-of?
                                _%bind194665%_
                                'gx#extern-binding::t)))
                          (if _%$e194675%_
                              _%$e194675%_
                              (##structure-direct-instance-of?
                               _%bind194665%_
                               'gx#import-binding::t)))))))
                  (_%make-export__0__197819197822%_
                   (lambda (_%bind194681%_)
                     (let* ((_%phi194683%_ (gx#current-export-expander-phi))
                            (_%ctx194685%_ (gx#current-expander-context))
                            (_%name194687%_ '#f))
                       (_%make-export__197817197818%_
                        _%bind194681%_
                        _%phi194683%_
                        _%ctx194685%_
                        _%name194687%_))))
                  (_%make-export__1__197820197823%_
                   (lambda (_%bind194689%_ _%phi194690%_)
                     (let* ((_%ctx194692%_ (gx#current-expander-context))
                            (_%name194694%_ '#f))
                       (_%make-export__197817197818%_
                        _%bind194689%_
                        _%phi194690%_
                        _%ctx194692%_
                        _%name194694%_))))
                  (_%make-export__2__197821197824%_
                   (lambda (_%bind194696%_ _%phi194697%_ _%ctx194698%_)
                     (let ((_%name194700%_ '#f))
                       (_%make-export__197817197818%_
                        _%bind194696%_
                        _%phi194697%_
                        _%ctx194698%_
                        _%name194700%_))))
                  (_%make-export194215%_
                   (lambda _g197891_
                     (let ((_g197892_ (##length _g197891_)))
                       (cond ((##fx= _g197892_ 1)
                              (apply _%make-export__0__197819197822%_
                                     _g197891_))
                             ((##fx= _g197892_ 2)
                              (apply _%make-export__1__197820197823%_
                                     _g197891_))
                             ((##fx= _g197892_ 3)
                              (apply _%make-export__2__197821197824%_
                                     _g197891_))
                             ((##fx= _g197892_ 4)
                              (apply _%make-export__197817197818%_ _g197891_))
                             (else
                              (##raise-wrong-number-of-arguments-exception
                               'case-lambda-dispatch
                               _g197891_))))))
                  (_%expand1194216%_
                   (lambda (_%hd194370%_
                            _%K194371%_
                            _%rest194372%_
                            _%r194373%_)
                     (let* ((_%$%e194374194406%_ _%hd194370%_)
                            (_%$%E194401194410%_
                             (lambda ()
                               (gx#raise-syntax-error
                                '#f
                                '"Bad syntax; illegal export"
                                _%stx194212%_
                                _%hd194370%_)))
                            (_%$%E194391194494%_
                             (lambda ()
                               (if (gx#stx-pair? _%$%e194374194406%_)
                                   (let ((_%$%e194402194414%_
                                          (gx#syntax-e _%$%e194374194406%_)))
                                     (let ((_%$%hd194403194417%_
                                            (##car _%$%e194402194414%_))
                                           (_%$%tl194404194419%_
                                            (##cdr _%$%e194402194414%_)))
                                       (if (eq? (gx#stx-e _%$%hd194403194417%_)
                                                'import:)
                                           (let ((_%in194422%_
                                                  _%$%tl194404194419%_))
                                             (if (gx#stx-list? _%in194422%_)
                                                 (let _%lp194424%_ ((_%in-rest194426%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%in194422%_)
                            (_%r194427%_ _%r194373%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (let* ((_%$%e194428194435%_
                                                           _%in-rest194426%_)
                                                          (_%$%E194430194439%_
                                                           (lambda ()
                                                             (_%K194371%_
                                                              _%rest194372%_
                                                              _%r194427%_)))
                                                          (_%$%E194429194490%_
                                                           (lambda ()
                                                             (if (gx#stx-pair?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%$%e194428194435%_)
                         (let ((_%$%e194431194443%_
                                (gx#syntax-e _%$%e194428194435%_)))
                           (let ((_%$%hd194432194446%_
                                  (##car _%$%e194431194443%_))
                                 (_%$%tl194433194448%_
                                  (##cdr _%$%e194431194443%_)))
                             (let* ((_%hd194451%_ _%$%hd194432194446%_)
                                    (_%in-rest194453%_ _%$%tl194433194448%_)
                                    (_%src194488%_
                                     (if (gx#core-bound-module? _%hd194451%_)
                                         (gx#syntax-local-e__0 _%hd194451%_)
                                         (if (gx#core-library-module-path?
                                              _%hd194451%_)
                                             (gx#import-module__0
                                              (gx#core-resolve-library-module-path
                                               _%hd194451%_))
                                             (if (gx#core-library-relative-module-path?
                                                  _%hd194451%_)
                                                 (gx#import-module__0
                                                  (gx#core-resolve-library-relative-module-path
                                                   _%hd194451%_))
                                                 (if (gx#stx-string?
                                                      _%hd194451%_)
                                                     (gx#import-module__0
                                                      (gx#core-resolve-module-path__%
                                                       _%hd194451%_
                                                       (gx#stx-source
                                                        _%stx194212%_)))
                                                     (let* ((_%$%e194459194466%_
                                                             _%hd194451%_)
                                                            (_%$%E194461194470%_
                                                             (lambda ()
                                                               (gx#raise-syntax-error
                                                                '#f
                                                                '"Bad syntax; illegal re-export"
                                                                _%stx194212%_
                                                                _%hd194451%_)))
                                                            (_%$%E194460194484%_
                                                             (lambda ()
                                                               (if (gx#stx-pair?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%e194459194466%_)
                           (let ((_%$%e194462194474%_
                                  (gx#syntax-e _%$%e194459194466%_)))
                             (let ((_%$%hd194463194477%_
                                    (##car _%$%e194462194474%_))
                                   (_%$%tl194464194479%_
                                    (##cdr _%$%e194462194474%_)))
                               (if (eq? (gx#stx-e _%$%hd194463194477%_) 'in:)
                                   (let ((_%spath194482%_
                                          _%$%tl194464194479%_))
                                     (gx#core-import-nested-module
                                      _%spath194482%_
                                      _%stx194212%_))
                                   (_%$%E194461194470%_))))
                           (_%$%E194461194470%_)))))
               (_%$%E194460194484%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                               (_%lp194424%_
                                _%in-rest194453%_
                                (_%export-imports194217%_
                                 _%src194488%_
                                 _%r194427%_)))))
                         (_%$%E194430194439%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%E194429194490%_)))
                                                 (_%$%E194401194410%_)))
                                           (_%$%E194401194410%_))))
                                   (_%$%E194401194410%_))))
                            (_%$%E194378194534%_
                             (lambda ()
                               (if (gx#stx-pair? _%$%e194374194406%_)
                                   (let ((_%$%e194392194498%_
                                          (gx#syntax-e _%$%e194374194406%_)))
                                     (let ((_%$%hd194393194501%_
                                            (##car _%$%e194392194498%_))
                                           (_%$%tl194394194503%_
                                            (##cdr _%$%e194392194498%_)))
                                       (if (eq? (gx#stx-e _%$%hd194393194501%_)
                                                'rename:)
                                           (if (gx#stx-pair?
                                                _%$%tl194394194503%_)
                                               (let ((_%$%e194395194506%_
                                                      (gx#syntax-e
                                                       _%$%tl194394194503%_)))
                                                 (let ((_%$%hd194396194509%_
                                                        (##car _%$%e194395194506%_))
                                                       (_%$%tl194397194511%_
                                                        (##cdr _%$%e194395194506%_)))
                                                   (let ((_%id194514%_
                                                          _%$%hd194396194509%_))
                                                     (if (gx#stx-pair?
                                                          _%$%tl194397194511%_)
                                                         (let ((_%$%e194398194516%_
                                                                (gx#syntax-e
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%tl194397194511%_)))
                   (let ((_%$%hd194399194519%_ (##car _%$%e194398194516%_))
                         (_%$%tl194400194521%_ (##cdr _%$%e194398194516%_)))
                     (let ((_%name194524%_ _%$%hd194399194519%_))
                       (if (gx#stx-null? _%$%tl194400194521%_)
                           (let* ((_%phi194526%_
                                   (gx#current-export-expander-phi))
                                  (_%$e194528%_
                                   (gx#core-resolve-identifier__1
                                    _%id194514%_
                                    _%phi194526%_)))
                             (if _%$e194528%_
                                 (_%K194371%_
                                  _%rest194372%_
                                  (cons (_%make-export__197817197818%_
                                         _%$e194528%_
                                         _%phi194526%_
                                         (gx#current-expander-context)
                                         _%name194524%_)
                                        _%r194373%_))
                                 (gx#raise-syntax-error
                                  '#f
                                  '"Reference to unbound identifier"
                                  _%stx194212%_
                                  _%hd194370%_
                                  _%id194514%_)))
                           (_%$%E194391194494%_)))))
                 (_%$%E194391194494%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%E194391194494%_))
                                           (_%$%E194391194494%_))))
                                   (_%$%E194391194494%_))))
                            (_%$%E194377194584%_
                             (lambda ()
                               (if (gx#stx-pair? _%$%e194374194406%_)
                                   (let ((_%$%e194379194538%_
                                          (gx#syntax-e _%$%e194374194406%_)))
                                     (let ((_%$%hd194380194541%_
                                            (##car _%$%e194379194538%_))
                                           (_%$%tl194381194543%_
                                            (##cdr _%$%e194379194538%_)))
                                       (if (eq? (gx#stx-e _%$%hd194380194541%_)
                                                'spec:)
                                           (if (gx#stx-pair?
                                                _%$%tl194381194543%_)
                                               (let ((_%$%e194382194546%_
                                                      (gx#syntax-e
                                                       _%$%tl194381194543%_)))
                                                 (let ((_%$%hd194383194549%_
                                                        (##car _%$%e194382194546%_))
                                                       (_%$%tl194384194551%_
                                                        (##cdr _%$%e194382194546%_)))
                                                   (let ((_%phi194554%_
                                                          _%$%hd194383194549%_))
                                                     (if (gx#stx-pair?
                                                          _%$%tl194384194551%_)
                                                         (let ((_%$%e194385194556%_
                                                                (gx#syntax-e
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%tl194384194551%_)))
                   (let ((_%$%hd194386194559%_ (##car _%$%e194385194556%_))
                         (_%$%tl194387194561%_ (##cdr _%$%e194385194556%_)))
                     (let ((_%id194564%_ _%$%hd194386194559%_))
                       (if (gx#stx-pair? _%$%tl194387194561%_)
                           (let ((_%$%e194388194566%_
                                  (gx#syntax-e _%$%tl194387194561%_)))
                             (let ((_%$%hd194389194569%_
                                    (##car _%$%e194388194566%_))
                                   (_%$%tl194390194571%_
                                    (##cdr _%$%e194388194566%_)))
                               (let ((_%name194574%_ _%$%hd194389194569%_))
                                 (if (gx#stx-null? _%$%tl194390194571%_)
                                     (if (and (gx#stx-fixnum? _%phi194554%_)
                                              (gx#identifier? _%id194564%_)
                                              (gx#identifier? _%name194574%_))
                                         (let* ((_%phi194576%_
                                                 (gx#stx-e _%phi194554%_))
                                                (_%$e194578%_
                                                 (gx#core-resolve-identifier__1
                                                  _%id194564%_
                                                  _%phi194576%_)))
                                           (if _%$e194578%_
                                               (_%K194371%_
                                                _%rest194372%_
                                                (cons (_%make-export__197817197818%_
                                                       _%$e194578%_
                                                       _%phi194576%_
                                                       (gx#current-expander-context)
                                                       _%name194574%_)
                                                      _%r194373%_))
                                               (gx#raise-syntax-error
                                                '#f
                                                '"Reference to unbound identifier"
                                                _%stx194212%_
                                                _%hd194370%_
                                                _%id194564%_)))
                                         (_%$%E194378194534%_))
                                     (_%$%E194378194534%_)))))
                           (_%$%E194378194534%_)))))
                 (_%$%E194378194534%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%E194378194534%_))
                                           (_%$%E194378194534%_))))
                                   (_%$%E194378194534%_))))
                            (_%$%E194376194596%_
                             (lambda ()
                               (let ((_%id194588%_ _%$%e194374194406%_))
                                 (if (gx#identifier? _%id194588%_)
                                     (let ((_%$e194590%_
                                            (gx#core-resolve-identifier__1
                                             _%id194588%_
                                             (gx#current-export-expander-phi))))
                                       (if _%$e194590%_
                                           (_%K194371%_
                                            _%rest194372%_
                                            (cons (_%make-export__0__197819197822%_
                                                   _%$e194590%_)
                                                  _%r194373%_))
                                           (gx#raise-syntax-error
                                            '#f
                                            '"Reference to unbound identifier"
                                            _%stx194212%_
                                            _%hd194370%_)))
                                     (_%$%E194377194584%_)))))
                            (_%$%E194375194660%_
                             (lambda ()
                               (if (eq? (gx#stx-e _%$%e194374194406%_) '#t)
                                   (let* ((_%current-ctx194600%_
                                           (gx#current-expander-context))
                                          (_%current-phi194602%_
                                           (gx#current-export-expander-phi))
                                          (_%phi-ctx194604%_
                                           (gx#core-context-shift
                                            _%current-ctx194600%_
                                            _%current-phi194602%_))
                                          (_%phi-bind194606%_
                                           (hash->list
                                            (##unchecked-structure-ref
                                             _%phi-ctx194604%_
                                             '2
                                             '#f
                                             '#f))))
                                     (let _%lp194609%_ ((_%bind-rest194611%_
                                                         _%phi-bind194606%_)
                                                        (_%set194612%_ '()))
                                       (let* ((_%$%bind-rest194613194623%_
                                               _%bind-rest194611%_)
                                              (_%$%else194615194631%_
                                               (lambda ()
                                                 (_%K194371%_
                                                  _%rest194372%_
                                                  (cons (##structure
                                                         gx#export-set::t
                                                         '#f
                                                         _%current-phi194602%_
                                                         _%set194612%_)
                                                        _%r194373%_))))
                                              (_%$%K194617194641%_
                                               (lambda (_%bind-rest194634%_
                                                        _%bind194635%_
                                                        _%key194636%_)
                                                 (if (or (##structure-direct-instance-of?
                                                          _%bind194635%_
                                                          'gx#import-binding::t)
                                                         (gx#private-feature-binding?
                                                          _%bind194635%_))
                                                     (_%lp194609%_
                                                      _%bind-rest194634%_
                                                      _%set194612%_)
                                                     (_%lp194609%_
                                                      _%bind-rest194634%_
                                                      (cons (_%make-export__2__197821197824%_
                                                             _%bind194635%_
                                                             _%current-phi194602%_
                                                             _%current-ctx194600%_)
                                                            _%set194612%_))))))
                                         (if (pair? _%$%bind-rest194613194623%_)
                                             (let ((_%$%hd194618194644%_
                                                    (##car _%$%bind-rest194613194623%_))
                                                   (_%$%tl194619194646%_
                                                    (##cdr _%$%bind-rest194613194623%_)))
                                               (if (pair? _%$%hd194618194644%_)
                                                   (let ((_%$%hd194620194649%_
                                                          (##car _%$%hd194618194644%_))
                                                         (_%$%tl194621194651%_
                                                          (##cdr _%$%hd194618194644%_)))
                                                     (let* ((_%key194654%_
                                                             _%$%hd194620194649%_)
                                                            (_%bind194656%_
                                                             _%$%tl194621194651%_)
                                                            (_%bind-rest194658%_
                                                             _%$%tl194619194646%_))
                                                       (_%$%K194617194641%_
                                                        _%bind-rest194658%_
                                                        _%bind194656%_
                                                        _%key194654%_)))
                                                   (_%$%else194615194631%_)))
                                             (_%$%else194615194631%_)))))
                                   (_%$%E194376194596%_)))))
                       (_%$%E194375194660%_))))
                  (_%export-imports194217%_
                   (lambda (_%src194247%_ _%r194248%_)
                     (letrec* ((_%current-ctx194250%_
                                (gx#current-expander-context))
                               (_%current-phi194251%_
                                (gx#current-export-expander-phi))
                               (_%import->export194252%_
                                (lambda (_%in194333%_)
                                  (let* ((_%$%in194334194342%_ _%in194333%_)
                                         (_%$%E194336194345%_
                                          (lambda ()
                                            (error '"No clause matching"
                                                   _%$%in194334194342%_
                                                   '((module-import
                                                      out
                                                      key
                                                      phi)))
                                            '#!void))
                                         (_%$%K194337194352%_
                                          (lambda (_%phi194348%_
                                                   _%key194349%_
                                                   _%out194350%_)
                                            (##structure
                                             gx#module-export::t
                                             _%current-ctx194250%_
                                             _%key194349%_
                                             _%phi194348%_
                                             _%key194349%_
                                             '#t))))
                                    (if (##structure-direct-instance-of?
                                         _%$%in194334194342%_
                                         'gx#module-import::t)
                                        (let* ((_%$%e194338194355%_
                                                (##unchecked-structure-ref
                                                 _%$%in194334194342%_
                                                 '1
                                                 '#f
                                                 '#f))
                                               (_%out194358%_
                                                _%$%e194338194355%_)
                                               (_%$%e194339194360%_
                                                (##unchecked-structure-ref
                                                 _%$%in194334194342%_
                                                 '2
                                                 '#f
                                                 '#f))
                                               (_%key194363%_
                                                _%$%e194339194360%_)
                                               (_%$%e194340194365%_
                                                (##unchecked-structure-ref
                                                 _%$%in194334194342%_
                                                 '3
                                                 '#f
                                                 '#f))
                                               (_%phi194368%_
                                                _%$%e194340194365%_))
                                          (_%$%K194337194352%_
                                           _%phi194368%_
                                           _%key194363%_
                                           _%out194358%_))
                                        (_%$%E194336194345%_)))))
                               (_%fold-e194253%_
                                (lambda (_%in194255%_ _%r194256%_)
                                  (let* ((_%$%in194257194271%_ _%in194255%_)
                                         (_%$%else194260194279%_
                                          (lambda () _%r194256%_)))
                                    (let ((_%$%K194266194315%_
                                           (lambda (_%phi194311%_
                                                    _%key194312%_
                                                    _%out194313%_)
                                             (if (and (fx= _%phi194311%_
                                                           _%current-phi194251%_)
                                                      (eq? _%src194247%_
                                                           (##unchecked-structure-ref
                                                            _%out194313%_
                                                            '1
                                                            '#f
                                                            '#f)))
                                                 (cons (_%import->export194252%_
                                                        _%in194255%_)
                                                       _%r194256%_)
                                                 _%r194256%_)))
                                          (_%$%K194262194290%_
                                           (lambda (_%imports194283%_
                                                    _%phi194284%_
                                                    _%ctx194285%_)
                                             (if (and (fx= _%phi194284%_
                                                           _%current-phi194251%_)
                                                      (eq? _%src194247%_
                                                           _%ctx194285%_))
                                                 (foldl__0
                                                  (lambda (_%in194287%_
                                                           _%r194288%_)
                                                    (cons (_%import->export194252%_
                                                           _%in194287%_)
                                                          _%r194288%_))
                                                  _%r194256%_
                                                  _%imports194283%_)
                                                 _%r194256%_))))
                                      (let ((_%$%try-match194259194308%_
                                             (lambda ()
                                               (if (##structure-direct-instance-of?
                                                    _%$%in194257194271%_
                                                    'gx#import-set::t)
                                                   (let* ((_%$%e194263194293%_
                                                           (##unchecked-structure-ref
                                                            _%$%in194257194271%_
                                                            '1
                                                            '#f
                                                            '#f))
                                                          (_%$%e194264194298%_
                                                           (##unchecked-structure-ref
                                                            _%$%in194257194271%_
                                                            '2
                                                            '#f
                                                            '#f))
                                                          (_%$%e194265194303%_
                                                           (##unchecked-structure-ref
                                                            _%$%in194257194271%_
                                                            '3
                                                            '#f
                                                            '#f)))
                                                     (let ((_%ctx194296%_
                                                            _%$%e194263194293%_)
                                                           (_%phi194301%_
                                                            _%$%e194264194298%_)
                                                           (_%imports194306%_
                                                            _%$%e194265194303%_))
                                                       (_%$%K194262194290%_
                                                        _%imports194306%_
                                                        _%phi194301%_
                                                        _%ctx194296%_)))
                                                   (_%$%else194260194279%_)))))
                                        (if (##structure-direct-instance-of?
                                             _%$%in194257194271%_
                                             'gx#module-import::t)
                                            (let* ((_%$%e194267194318%_
                                                    (##unchecked-structure-ref
                                                     _%$%in194257194271%_
                                                     '1
                                                     '#f
                                                     '#f))
                                                   (_%$%e194268194323%_
                                                    (##unchecked-structure-ref
                                                     _%$%in194257194271%_
                                                     '2
                                                     '#f
                                                     '#f))
                                                   (_%$%e194269194328%_
                                                    (##unchecked-structure-ref
                                                     _%$%in194257194271%_
                                                     '3
                                                     '#f
                                                     '#f)))
                                              (let ((_%out194321%_
                                                     _%$%e194267194318%_)
                                                    (_%key194326%_
                                                     _%$%e194268194323%_)
                                                    (_%phi194331%_
                                                     _%$%e194269194328%_))
                                                (_%$%K194266194315%_
                                                 _%phi194331%_
                                                 _%key194326%_
                                                 _%out194321%_)))
                                            (_%$%try-match194259194308%_))))))))
                       (cons (##structure
                              gx#export-set::t
                              _%src194247%_
                              _%current-phi194251%_
                              (foldl__0
                               _%fold-e194253%_
                               '()
                               (##unchecked-structure-ref
                                _%current-ctx194250%_
                                '8
                                '#f
                                '#f)))
                             _%r194248%_))))
                  (_%export!194218%_
                   (lambda (_%rbody194234%_)
                     (letrec* ((_%current-ctx194236%_
                                (gx#current-expander-context))
                               (_%fold-e194237%_
                                (lambda (_%out194241%_ _%r194242%_)
                                  (if (##structure-direct-instance-of?
                                       _%out194241%_
                                       'gx#module-export::t)
                                      (cons _%out194241%_ _%r194242%_)
                                      (if (##structure-direct-instance-of?
                                           _%out194241%_
                                           'gx#export-set::t)
                                          (foldl__0
                                           cons
                                           _%r194242%_
                                           (##unchecked-structure-ref
                                            _%out194241%_
                                            '3
                                            '#f
                                            '#f))
                                          _%r194242%_)))))
                       (let ((_%body194239%_ (reverse _%rbody194234%_)))
                         (##unchecked-structure-set!
                          _%current-ctx194236%_
                          (foldl__0
                           _%fold-e194237%_
                           (##unchecked-structure-ref
                            _%current-ctx194236%_
                            '9
                            '#f
                            '#f)
                           _%body194239%_)
                          '9
                          '#f
                          '#f)
                         _%body194239%_))))
                  (_%expanded-export?194219%_
                   (lambda (_%e194229%_)
                     (let ((_%$e194231%_
                            (##structure-direct-instance-of?
                             _%e194229%_
                             'gx#module-export::t)))
                       (if _%$e194231%_
                           _%$e194231%_
                           (##structure-direct-instance-of?
                            _%e194229%_
                            'gx#export-set::t))))))
          (if (or (##structure-instance-of?
                   (gx#current-expander-context)
                   'gx#module-context::t)
                  _%internal-expand?194213%_)
              (let ((_%rbody194225%_
                     (gx#core-expand-import/export
                      _%stx194212%_
                      _%expanded-export?194219%_
                      'apply-export-expander
                      gx#current-export-expander-phi
                      _%expand1194216%_)))
                (if _%internal-expand?194213%_
                    (reverse _%rbody194225%_)
                    (gx#core-quote-syntax__1
                     (gx#core-cons
                      '%#export
                      (_%export!194218%_ _%rbody194225%_))
                     (gx#stx-source _%stx194212%_))))
              (if (##structure-instance-of?
                   (gx#current-expander-context)
                   'gx#top-context::t)
                  (gx#core-quote-syntax__1
                   (gx#core-cons '%#begin '())
                   (gx#stx-source _%stx194212%_))
                  (gx#raise-syntax-error
                   '#f
                   '"Illegal context"
                   _%stx194212%_))))))
    (define gx#core-expand-export%__0
      (lambda (_%stx194710%_)
        (let ((_%internal-expand?194712%_ '#f))
          (gx#core-expand-export%__%
           _%stx194710%_
           _%internal-expand?194712%_))))
    (define gx#core-expand-export%
      (lambda _g197893_
        (let ((_g197894_ (##length _g197893_)))
          (cond ((##fx= _g197894_ 1)
                 (apply gx#core-expand-export%__0 _g197893_))
                ((##fx= _g197894_ 2)
                 (apply gx#core-expand-export%__% _g197893_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-expand-export%
                  _g197893_))))))
    (define gx#core-expand-export-source
      (lambda (_%hd194209%_)
        (gx#core-expand-export%__%
         (cons 'export-macro% (cons _%hd194209%_ '()))
         '#t)))
    (define gx#core-expand-provide%
      (lambda (_%stx194179%_)
        (let* ((_%$%e194180194187%_ _%stx194179%_)
               (_%$%E194182194191%_
                (lambda ()
                  (gx#raise-syntax-error
                   '#f
                   '"Bad syntax; invalid syntax-case clause"
                   _%$%e194180194187%_)))
               (_%$%E194181194205%_
                (lambda ()
                  (if (gx#stx-pair? _%$%e194180194187%_)
                      (let ((_%$%e194183194195%_
                             (gx#syntax-e _%$%e194180194187%_)))
                        (let ((_%$%hd194184194198%_
                               (##car _%$%e194183194195%_))
                              (_%$%tl194185194200%_
                               (##cdr _%$%e194183194195%_)))
                          (let ((_%body194203%_ _%$%tl194185194200%_))
                            (if (gx#identifier-list? _%body194203%_)
                                (begin
                                  (gx#stx-for-each1
                                   gx#core-bind-feature!
                                   _%body194203%_)
                                  (gx#core-quote-syntax__1
                                   (gx#core-cons
                                    '%#provide
                                    (gx#stx-map1
                                     gx#core-quote-syntax
                                     _%body194203%_))
                                   (gx#stx-source _%stx194179%_)))
                                (_%$%E194182194191%_)))))
                      (_%$%E194182194191%_)))))
          (_%$%E194181194205%_))))
    (define gx#core-bind-feature!__%
      (lambda (_%id194145%_ _%private?194146%_ _%phi194147%_ _%ctx194148%_)
        (gx#core-bind-syntax!__%
         _%id194145%_
         ((if _%private?194146%_
              gx#make-private-feature-expander
              gx#make-feature-expander)
          (gx#stx-e _%id194145%_))
         _%private?194146%_
         _%phi194147%_
         _%ctx194148%_)))
    (define gx#core-bind-feature!__0
      (lambda (_%id194153%_)
        (let* ((_%private?194155%_ '#f)
               (_%phi194157%_ (gx#current-expander-phi))
               (_%ctx194159%_ (gx#current-expander-context)))
          (gx#core-bind-feature!__%
           _%id194153%_
           _%private?194155%_
           _%phi194157%_
           _%ctx194159%_))))
    (define gx#core-bind-feature!__1
      (lambda (_%id194161%_ _%private?194162%_)
        (let* ((_%phi194164%_ (gx#current-expander-phi))
               (_%ctx194166%_ (gx#current-expander-context)))
          (gx#core-bind-feature!__%
           _%id194161%_
           _%private?194162%_
           _%phi194164%_
           _%ctx194166%_))))
    (define gx#core-bind-feature!__2
      (lambda (_%id194168%_ _%private?194169%_ _%phi194170%_)
        (let ((_%ctx194172%_ (gx#current-expander-context)))
          (gx#core-bind-feature!__%
           _%id194168%_
           _%private?194169%_
           _%phi194170%_
           _%ctx194172%_))))
    (define gx#core-bind-feature!
      (lambda _g197895_
        (let ((_g197896_ (##length _g197895_)))
          (cond ((##fx= _g197896_ 1)
                 (apply gx#core-bind-feature!__0 _g197895_))
                ((##fx= _g197896_ 2)
                 (apply gx#core-bind-feature!__1 _g197895_))
                ((##fx= _g197896_ 3)
                 (apply gx#core-bind-feature!__2 _g197895_))
                ((##fx= _g197896_ 4)
                 (apply gx#core-bind-feature!__% _g197895_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gx#core-bind-feature!
                  _g197895_))))))))
