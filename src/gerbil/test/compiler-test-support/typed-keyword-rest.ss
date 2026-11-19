;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Typed keyword arguments combined with a rest argument.
;;; Runtime keyword-dispatch accepts keywords interleaved anywhere among the
;;; positional arguments; statically dispatched typed calls must agree.
;;; Shared by typed-keyword-test (interpreted) and compiler-test (compiled).
(import :std/test
        (only-in :gerbil/runtime/error contract-violation-error?))
(export main check-untyped-control check-typed-keyword-rest
        check-typed-keyword-after-positional check-typed-keywords-rest
        check-typed-positional-keyword-rest check-typed-keyword-escapes)

;; Typed keyword + rest.
(def (f w: (w :? :string := #f) . rest)
  (list w rest))

;; Untyped control: same shape, no contracts, goes through keyword-dispatch.
(def (g w: (w #f) . rest)
  (list w rest))

;; Several typed keywords + rest.
(def (h a: (a :? :string := #f) b: (b : :fixnum := 0) . rest)
  (list a b rest))

;; Typed positional + typed keyword + rest.
(def (p (x : :fixnum) w: (w :? :string := #f) . rest)
  (list x w rest))

;; Report an exception as a value, so one failing call doesn't mask the others.
(def (safe thunk)
  (with-catch (lambda (e) [raised: (if (error? e) (error-message e) e)])
              thunk))

(def (check-untyped-control)
  ;; Untyped control: keyword before, after, and between positionals.
  (check-function safe
    (lambda () (g "x" w: "z")) => ["z" ["x"]]
    (lambda () (g w: "z" "x")) => ["z" ["x"]]
    (lambda () (g "x" w: "z" "y")) => ["z" ["x" "y"]]
    (lambda () (apply g "x" [w: "z"])) => ["z" ["x"]]))

(def (check-typed-keyword-rest)
  ;; Typed keyword + rest: no keyword after a positional.
  (check-function safe
    (lambda () (f)) => [#f []]
    (lambda () (f "x")) => [#f ["x"]]
    (lambda () (f w: "z")) => ["z" []]
    (lambda () (f w: "z" "x")) => ["z" ["x"]]
    (lambda () (apply f "x" [w: "z"])) => ["z" ["x"]]))

(def (check-typed-keyword-after-positional)
  ;; Typed keyword + rest: keyword after a positional.
  (check-function safe
    (lambda () (f "x" w: "z")) => ["z" ["x"]]
    (lambda () (f "x" "y" w: "z")) => ["z" ["x" "y"]]
    (lambda () (f "x" w: "z" "y")) => ["z" ["x" "y"]])
  ;; The keyword's contract still applies wherever the keyword appears.
  (check (f "x" w: 42) =>! contract-violation-error?))

(def (check-typed-keywords-rest)
  ;; Several typed keywords + rest.
  (check-function safe
    (lambda () (h a: "p" b: 1 "x")) => ["p" 1 ["x"]]
    (lambda () (h "x" a: "p" b: 1)) => ["p" 1 ["x"]]
    (lambda () (h a: "p" "x" b: 1)) => ["p" 1 ["x"]]
    (lambda () (h "x" b: 1)) => [#f 1 ["x"]]
    (lambda () (h b: 1 "x" a: "p" "y")) => ["p" 1 ["x" "y"]]))

(def (check-typed-positional-keyword-rest)
  ;; Typed positional + typed keyword + rest.
  (check-function safe
    (lambda () (p 1 w: "z" "x")) => [1 "z" ["x"]]
    (lambda () (p 1 "x")) => [1 #f ["x"]]
    (lambda () (p 1 "x" w: "z")) => [1 "z" ["x"]]
    (lambda () (p 1 "x" w: "z" "y")) => [1 "z" ["x" "y"]]))

(def (check-typed-keyword-escapes)
  ;; A keyword object passed as a positional value, via the #!key escape or
  ;; as the tail of a #!rest, must stay positional when the checked lambda
  ;; forwards its arguments to the unchecked keyword lambda. It must not be
  ;; re-interpreted as a keyword and rejected or bound to the keyword
  ;; parameter.
  (check-function safe
    (lambda () (f #!key w:))          => [#f (list w:)]
    (lambda () (f #!rest w:))         => [#f (list w:)]
    (lambda () (f "x" #!key w:))      => [#f (list "x" w:)]
    (lambda () (f "x" #!rest w:))     => [#f (list "x" w:)]
    (lambda () (apply f [#!key w:]))  => [#f (list w:)]
    (lambda () (apply f [#!rest w:])) => [#f (list w:)]
    (lambda () (h #!rest b:))         => [#f 0 (list b:)]
    (lambda () (h a: "p" #!key b:))   => ["p" 0 (list b:)]
    (lambda () (p 1 #!key w:))        => [1 #f (list w:)]))

(def (main)
  (check-untyped-control)
  (check-typed-keyword-rest)
  (check-typed-keyword-after-positional)
  (check-typed-keywords-rest)
  (check-typed-positional-keyword-rest)
  (check-typed-keyword-escapes))
