(declare (block) (standard-bindings) (extended-bindings) (inlining-limit 200))
(begin
  (define |gerbil/core/contract~TypeEnv[1]#_g107400_|
    (##structure
     gx#syntax-quote::t
     'type-env::t
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107402_|
    (##structure
     gx#syntax-quote::t
     'make-type-env
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107404_|
    (##structure
     gx#syntax-quote::t
     'type-env?
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107406_|
    (##structure
     gx#syntax-quote::t
     'type-env-var
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107407_|
    (##structure
     gx#syntax-quote::t
     'type-env-type
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107408_|
    (##structure
     gx#syntax-quote::t
     'type-env-checked?
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107409_|
    (##structure
     gx#syntax-quote::t
     'type-env-nullable?
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107410_|
    (##structure
     gx#syntax-quote::t
     'type-env-super
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107412_|
    (##structure
     gx#syntax-quote::t
     'type-env-var-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107413_|
    (##structure
     gx#syntax-quote::t
     'type-env-type-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107414_|
    (##structure
     gx#syntax-quote::t
     'type-env-checked?-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107415_|
    (##structure
     gx#syntax-quote::t
     'type-env-nullable?-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107416_|
    (##structure
     gx#syntax-quote::t
     'type-env-super-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107418_|
    (##structure
     gx#syntax-quote::t
     '&type-env-var
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107419_|
    (##structure
     gx#syntax-quote::t
     '&type-env-type
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107420_|
    (##structure
     gx#syntax-quote::t
     '&type-env-checked?
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107421_|
    (##structure
     gx#syntax-quote::t
     '&type-env-nullable?
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107422_|
    (##structure
     gx#syntax-quote::t
     '&type-env-super
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107424_|
    (##structure
     gx#syntax-quote::t
     '&type-env-var-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107425_|
    (##structure
     gx#syntax-quote::t
     '&type-env-type-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107426_|
    (##structure
     gx#syntax-quote::t
     '&type-env-checked?-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107427_|
    (##structure
     gx#syntax-quote::t
     '&type-env-nullable?-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[1]#_g107428_|
    (##structure
     gx#syntax-quote::t
     '&type-env-super-set!
     #f
     (gx#current-expander-context)
     '()))
  (define |gerbil/core/contract~TypeEnv[:0:]#type-env|
    (let ((__obj107211
           (let ()
             (declare (not safe))
             (##structure
              gerbil/core/mop~MOP-2#class-type-info::t
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
              '#f
              '#f
              '#f))))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set!
         __obj107211
         'gerbil/core/contract~TypeEnv#type-env::t
         '2
         '#f
         '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 'type-env '3 '#f '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set!
         __obj107211
         '(var type checked? nullable? super)
         '6
         '#f
         '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 '() '5 '#f '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 '#t '9 '#f '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 '#t '10 '#f '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 '#f '12 '#f '#f))
      (let ()
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 '#f '13 '#f '#f))
      (let ((__tmp107399 |gerbil/core/contract~TypeEnv[1]#_g107400_|))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107399 '4 '#f '#f))
      (let ((__tmp107401 |gerbil/core/contract~TypeEnv[1]#_g107402_|))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107401 '14 '#f '#f))
      (let ((__tmp107403 |gerbil/core/contract~TypeEnv[1]#_g107404_|))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107403 '15 '#f '#f))
      (let ((__tmp107405
             (cons (cons 'var |gerbil/core/contract~TypeEnv[1]#_g107406_|)
                   (cons (cons 'type
                               |gerbil/core/contract~TypeEnv[1]#_g107407_|)
                         (cons (cons 'checked?
                                     |gerbil/core/contract~TypeEnv[1]#_g107408_|)
                               (cons (cons 'nullable?
                                           |gerbil/core/contract~TypeEnv[1]#_g107409_|)
                                     (cons (cons 'super
                                                 |gerbil/core/contract~TypeEnv[1]#_g107410_|)
                                           '())))))))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107405 '16 '#f '#f))
      (let ((__tmp107411
             (cons (cons 'var |gerbil/core/contract~TypeEnv[1]#_g107412_|)
                   (cons (cons 'type
                               |gerbil/core/contract~TypeEnv[1]#_g107413_|)
                         (cons (cons 'checked?
                                     |gerbil/core/contract~TypeEnv[1]#_g107414_|)
                               (cons (cons 'nullable?
                                           |gerbil/core/contract~TypeEnv[1]#_g107415_|)
                                     (cons (cons 'super
                                                 |gerbil/core/contract~TypeEnv[1]#_g107416_|)
                                           '())))))))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107411 '17 '#f '#f))
      (let ((__tmp107417
             (cons (cons 'var |gerbil/core/contract~TypeEnv[1]#_g107418_|)
                   (cons (cons 'type
                               |gerbil/core/contract~TypeEnv[1]#_g107419_|)
                         (cons (cons 'checked?
                                     |gerbil/core/contract~TypeEnv[1]#_g107420_|)
                               (cons (cons 'nullable?
                                           |gerbil/core/contract~TypeEnv[1]#_g107421_|)
                                     (cons (cons 'super
                                                 |gerbil/core/contract~TypeEnv[1]#_g107422_|)
                                           '())))))))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107417 '18 '#f '#f))
      (let ((__tmp107423
             (cons (cons 'var |gerbil/core/contract~TypeEnv[1]#_g107424_|)
                   (cons (cons 'type
                               |gerbil/core/contract~TypeEnv[1]#_g107425_|)
                         (cons (cons 'checked?
                                     |gerbil/core/contract~TypeEnv[1]#_g107426_|)
                               (cons (cons 'nullable?
                                           |gerbil/core/contract~TypeEnv[1]#_g107427_|)
                                     (cons (cons 'super
                                                 |gerbil/core/contract~TypeEnv[1]#_g107428_|)
                                           '())))))))
        (declare (not safe))
        (##unchecked-structure-set! __obj107211 __tmp107423 '19 '#f '#f))
      __obj107211)))
