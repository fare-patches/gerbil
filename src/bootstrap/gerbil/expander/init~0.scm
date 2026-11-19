(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/expander/init::timestamp 1795039817)
  (begin
    (let ((__tmp202100
           (let ((__obj202098
                  (let ()
                    (declare (not safe))
                    (##structure gx#top-context::t '#f '#f '#f '#f '#f))))
             (let ()
               (declare (not safe))
               (gx#top-context:::init!__0 __obj202098))
             __obj202098)))
      (declare (not safe))
      (gx#current-expander-context __tmp202100))
    (let ()
      (declare (not safe))
      (gx#current-expander-module-import gx#core-import-module))
    (let ()
      (declare (not safe))
      (gx#current-expander-module-eval gx#core-eval-module))
    (let () (declare (not safe)) (gx#current-expander-compile __compile-top))
    (let () (declare (not safe)) (gx#current-expander-eval ##eval))
    (let ((__tmp202101
           (let ((__obj202099
                  (let ()
                    (declare (not safe))
                    (##structure
                     gx#prelude-context::t
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
               (gx#prelude-context:::init!__0 __obj202099 '#f))
             __obj202099)))
      (declare (not safe))
      (gx#core-bind-root-syntax!__% ':<root> __tmp202101 '#t))))
