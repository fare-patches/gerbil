;;; -*- Gerbil -*-
;;; An optional value is #f when absent and (Some value) when present.
(import (only-in :std/error raise-context-error))
(export Some Some::t make-Some Some? Some-value option? value->option
        option-ref option-get option-ref/else option->list
        option-map option-map/list option-bind option-for-each)

;; :t documents that Some can hold any Scheme value, including #f.
(defstruct Some ((value : :t)) transparent: #t final: #t)

(def (option? obj)
  => :boolean
  (or (Some? obj) (not obj)))

(def (value->option value (absent #f))
  => (Maybe Some)
  (and (not (eqv? value absent)) (Some value)))

(def (option-ref (opt :? Some) (default absent-value))
  => :t
  (cond
   (opt opt.value)
   ((eq? default absent-value)
    (raise-context-error option-ref "option is absent and no default was supplied"))
   (else default)))

(def (option-get (opt :? Some))
  => :t
  (option-ref opt #f))

(def (option-ref/else (opt :? Some) (fallback : :procedure))
  => :t
  (if opt opt.value (fallback)))

(def (option->list (opt :? Some))
  => :list
  (if opt [opt.value] []))

(def (option-map (f : :procedure) (opt :? Some))
  => (Maybe Some)
  (and opt (Some (f opt.value))))

(def (option-map/list (f : :procedure) (items : :list))
  => (Maybe Some)
  (let loop ((rest items) (acc []))
    (match rest
      ([] (Some (reverse! acc)))
      ([item . tail]
       (using (result (f item) :? Some)
         (and result (loop tail (cons result.value acc))))))))

(def (option-bind (opt :? Some) (f : :procedure))
  => (Maybe Some)
  (and opt (f opt.value)))

(def (option-for-each (f : :procedure) (opt :? Some))
  => :void
  (when opt (f opt.value))
  (void))
