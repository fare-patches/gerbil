;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Opt-in deterministic checks; no external oracle, timing gate or dependency.
(import ../djot
        ./conformance-test)
(export check-djot-corpus
        check-djot-scaling)

(def (snapshot (document : djot-document)) => :string
  (let (port (open-output-string))
    (write document port)
    (get-output-string port)))

(def (check-djot-corpus) => :fixnum
  (let ((fixtures (read-fixtures))
        (count 0))
    (unless (equal? (conformance-counts) [302 0])
      (error "Djot conformance failure"))
    (for-each
     (lambda ((fixture : djot-fixture)) => :void
       (let* ((input (djot-fixture-input fixture))
              (plain (string->djot input))
              (located (string->djot input source-locations: #t))
              (plain-before (snapshot plain))
              (located-before (snapshot located))
              (html (djot->html plain)))
         (unless (and (string=? html (djot->html located))
                      (string=? html (djot->html plain))
                      (string=? html (djot->html located))
                      (equal? (djot->sxml plain) (djot->sxml located))
                      (string=? plain-before (snapshot plain))
                      (string=? located-before (snapshot located)))
           (error "Djot rendering changed with locations, repetition or mutation"
                  (djot-fixture-file fixture) (djot-fixture-line fixture))))
       (set! count (+ count 1)))
     fixtures)
    count))

(def (check-djot-scaling (sizes : :list := [1000 2000 4000])) => :list
  (map
   (lambda ((size : :fixnum)) => :list
     (unless (> size 0)
       (error "Djot check size must be positive" size))
     (let (count 0)
       ;; Adapted bounded families from pinned pathological.spec.ts (MIT).
       (for-each
        (lambda ((fragment : :string)) => :void
          (let* ((input (apply string-append (make-list size fragment)))
                 (document (string->djot input)))
            (unless (string? (djot->html document))
              (error "Djot rendering failed" fragment))
            (set! count (+ count 1))))
        ["_a " "a_ " "[ (](" "[a](<b" "a{#id k=" "[^"
         "# Duplicate\n\n[Duplicate][]\n\n" "[x][r]\n\n[r]: /url\n\n"])
       [size count]))
   sizes))
