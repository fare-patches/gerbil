;;; -*- Gerbil -*-
(import :std/test (only-in :std/error contract-violation-error? ContextError?) ./option)
(export option-test)

(def option-test
  (test-suite "test :std/struct/option"
    (test-case "absence and presence"
      (check-function option?
        #f => #t
        (Some #f) => #t
        (Some []) => #t
        [#f] => #f
        #t => #f)
      (def (setting (value absent-value)) (value->option value absent-value))
      (check-function setting
        => #f
        #f => (Some #f)
        42 => (Some 42))
      (check-function value->option
        #f => #f
        42 => (Some 42)
        42 42 => #f
        #f absent-value => (Some #f)
        absent-value absent-value => #f
        (Some #f) => (Some (Some #f)))
      (check (Some? #f) => #f)
      (check (Some-value (make-Some 42)) => 42)
      (check (eq? (class-of (make-Some #f)) Some::t) => #t)
      (check (Some-value (Some #f)) => #f)
      (check (match (Some []) ((Some x) x)) => []))

    (test-case "extracting values and defaults"
      (check-function option-ref
        (Some 1) => 1
        (Some 5) => 5
        (Some #f) => #f
        #f =>! (lambda (e) (and (ContextError? e)
                               (eq? (car (error-irritants e)) 'option-ref)))
        #f absent-value =>! ContextError?
        (Some absent-value) => absent-value
        #f #f => #f
        #f 42 => 42
        #f identity => identity
        (Some #f) 'missing => #f
        'invalid =>! contract-violation-error?)
      (check-function option-get
        (Some 1) => 1
        #f => #f
        (Some #f) => #f
        'invalid =>! contract-violation-error?)
      (check (apply option-ref/else [#f]) =>! wrong-number-of-arguments-exception?)
      (check-function option-ref/else
        #f (lambda () 42) => 42
        (Some #f) (lambda () (error "unexpected fallback")) => #f
        'invalid false =>! contract-violation-error?)
      (check-function option->list
        (Some 1) => [1]
        (Some [1 2 3]) => [[1 2 3]]
        ['none 'none 'none] =>! contract-violation-error?
        #f => []
        (Some #f) => [#f]
        (Some []) => [[]]))

    (test-case "mapping, binding and side effects"
      (def (unexpected _) (error "unexpected callback"))
      (check-function option-map
        1+ (Some 1) => (Some 2)
        1+ #f => #f
        list 'also-none =>! contract-violation-error?
        list (Some #f) => (Some [#f])
        not (Some #t) => (Some #f)
        unexpected #f => #f
        unexpected 'failure =>! contract-violation-error?)
      (check-function option-bind
        #f unexpected => #f
        (Some 3) (lambda (x) (Some (1+ x))) => (Some 4)
        (Some 3) 1+ =>! contract-violation-error?
        (Some #f) make-Some => (Some #f)
        (Some #t) not => #f
        'failure unexpected =>! contract-violation-error?)
      (check-function (lambda (opt)
                        (with-output-to-string (cut option-for-each display opt)))
        #f => ""
        (Some #f) => "#f"
        (Some (* 6 7)) => "42")
      (check-function option-for-each
        not (Some #f) => (void)
        unexpected #f => (void)
        unexpected 'invalid =>! contract-violation-error?))

    (test-case "list traversal preserves order and stops at the first failure"
      (check-function option-map/list
        (cut option-map 1+ <>) [(Some 2) (Some 5) (Some 11)] => (Some [3 6 12])
        (cut option-map 1+ <>) [(Some 2) (Some 5) #f (Some 11)] => #f
        (lambda (x) (Some x)) [] => (Some [])
        (lambda (x) (Some x)) [3 #f 1] => (Some [3 #f 1])
        identity [(Some 1) #f] => #f
        identity [(Some 1) 'invalid] =>! contract-violation-error?)
      (def seen [])
      (check (option-map/list
              (lambda (x)
                (set! seen (cons x seen))
                (if (= x 2) #f (Some x)))
              [1 2 3])
             => #f)
      (check (reverse seen) => [1 2]))))
