;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Direct calls to procedures that collect their keywords in a #!key table.
;;; With optimize: #t, the optimizer rewrites a direct keyword call to such a
;;; procedure into an inline construction of the keyword table followed by a call
;;; to the main lambda; that table must behave like the one built by the runtime
;;; keyword-dispatch (as used by apply, below).
(import :std/test)
(export main)

;; All keywords go to the table.
(def (f a #!key kws)
  (list a (hash-key? kws b:) (hash-ref kws b: #f)))

;; Constructor style: declared keyword plus a table of all passed keywords.
(def (g a b: (b 0) #!key kws)
  (list a b (hash-length kws) (hash-ref kws b: #f) (hash-ref kws c: #f)))

(def (main)
  (check-function f
    1 => [1 #f #f]
    1 b: 2 => [1 #t 2]
    1 b: 2 c: 3 => [1 #t 2])
  (check (apply f 1 [b: 2]) => [1 #t 2])
  (check-function g
    1 => [1 0 0 #f #f]
    1 b: 2 => [1 2 1 2 #f]
    1 c: 3 => [1 0 1 #f 3]
    1 b: 2 c: 3 => [1 2 2 2 3])
  (check (apply g 1 [b: 2 c: 3]) => [1 2 2 2 3]))
