;;; -*- Gerbil -*-
;;; © vyzo
;;; binary serde texts
(import :std/test
        :std/error
        :std/log/compress
	./interface
        ./serialize
	./deserialize
        ./marshal
        ./unmarshal
        ./serde-test-support)
(export binary-serde-test)

(defsyntax-case check-marshal-unmarshal (?)
  ((_ obj)
   (syntax/loc stx
     (check (unmarshal (marshal obj)) => obj)))
  ((_ obj ? pred)
   (syntax/loc stx
     (check (unmarshal (marshal obj)) ? pred))))

;; a class and a procedure defined in this test module itself: the module is loaded
;; from source by the expander, never registered with the runtime loader and never
;; compiled, so unmarshaling must use the already-bound global rather than load-module.
(defclass BinaryTestLocal (x)
  transparent: #t)
;; deserialized objects must be untainted explicitly
(defobject-untaint BinaryTestLocal)
(def (binary-test-local-proc x) x)

(def binary-serde-test
  (test-suite "binary serde"
    (test-case "numbers"
      (check-marshal-unmarshal 1234)
      (check-marshal-unmarshal 12345678901234567890)
      (check-marshal-unmarshal -1234)
      (check-marshal-unmarshal -12345678901234567890)
      (check-marshal-unmarshal 3.333)
      (check-marshal-unmarshal -3.333)
      (check-marshal-unmarshal 1/3)
      (check-marshal-unmarshal -1/3)
      (check-marshal-unmarshal 1+3i)
      (check-marshal-unmarshal 1-3i)
      (check-marshal-unmarshal +i)
      (check-marshal-unmarshal -i)
      (check-marshal-unmarshal +inf.0)
      (check-marshal-unmarshal -inf.0)
      (check-marshal-unmarshal +nan.0 ? nan?))
    (test-case "symbolic"
      (check-marshal-unmarshal 'foo)
      (check-marshal-unmarshal foo:))
    (test-case "strings"
      (check-marshal-unmarshal "the quick brown fox jumped over the fence"))
    (test-case "lists"
      (check-marshal-unmarshal [])
      (check-marshal-unmarshal '(1 . 2))
      (check-marshal-unmarshal '(1 2 3))
      (check-marshal-unmarshal '(1 2 3 . 4)))
    (test-case "cyclic lists"
      (let (x [1 . #f])
        (check-marshal-unmarshal x)
	(set-cdr! x x)
        (check-marshal-unmarshal x)
	(set-cdr! x [2 . x])
        (check-marshal-unmarshal x)
	(set-cdr! x [x . x])
        (check-marshal-unmarshal x))
      (let ((x [1 . #f])
	    (y [#f . #f]))
	(set-cdr! x x)
	(set-cdr! y y)
	(set-car! y x)
	(check-marshal-unmarshal x)))
    (test-case "vectors"
      (check-marshal-unmarshal '#(1 2 3))
      (let (x (vector 1 2 3))
        (vector-set! x 0 x)
        (check-marshal-unmarshal x))
      (check-marshal-unmarshal (values 1 2 3))
      (check-marshal-unmarshal '#u8(1 2 3))
      (check-marshal-unmarshal '#s8(1 2 3))
      (check-marshal-unmarshal '#u16(1 2 3))
      (check-marshal-unmarshal '#s16(1 2 3))
      (check-marshal-unmarshal '#u32(1 2 3))
      (check-marshal-unmarshal '#s32(1 2 3))
      (check-marshal-unmarshal '#u64(1 2 3))
      (check-marshal-unmarshal '#s64(1 2 3))
      (check-marshal-unmarshal '#f32(1. 2. 3.))
      (check-marshal-unmarshal '#f64(1. 2. 3.)))
    (test-case "objects"
      (let ()
	(def b (B x: 2))
	(def a (A b: b))
	(let (obj (unmarshal (marshal a)))
	  (check obj ? A?)
	  (check (A-b obj) ? B?)
	  (check (B-x (A-b obj)) => 2))))
    (test-case "cyclic objects"
      (let ()
	(def c (A b: #f))
	(set! (A-b c) c)
	(let (obj (unmarshal (marshal c)))
	  (check obj ? A?)
	  (check (A-b obj) => obj))))
    (test-case "interfaces"
      (def x (C (A b: 1)))
      (let (obj (unmarshal (marshal x)))
	(check obj ? C?)
	(check (C-foo! obj) => 1)))
    (test-case "hashes"
      (let (obj (unmarshal (marshal (hash (a 1) (b 2)))))
	(check obj ? HashTable?)
	(check (hash-length obj) => 2)
	(check (hash-ref obj 'a) => 1)
	(check (hash-ref obj 'b) => 2)))
    (test-case "dag"
      (let ()
	(def c (A b: #f))
	(set! (A-b c) c)
        (check-exception (marshal c (marshal-context dag: #t))
                         ContractViolation?)
        (let (b (marshal c))
          (check-exception (unmarshal b (unmarshal-environment dag: #t))
                           ContractViolation?))))
    ;; A procedure is marshaled by its global name; unmarshaling resolves the global
    ;; binding, after allow-procedure: accepts the name, passed as a symbol.
    ;; Procedures equal? only when eq?, so => on procedures checks identity.
    (test-case "procedures"
      (def (round-trip obj)
        (unmarshal (marshal obj) (unmarshal-environment allow-procedure: (lambda (name) #t))))
      (check-function round-trip
        compress-gzip => compress-gzip
        serde-test-proc => serde-test-proc
        [compress-gzip serde-test-proc compress-gzip] => [compress-gzip serde-test-proc compress-gzip])
      (let (obj (round-trip (A b: [serde-test-proc (A b: serde-test-proc)])))
        (check obj ? A?)
        (check (car (A-b obj)) => serde-test-proc)
        (check (A-b (cadr (A-b obj))) => serde-test-proc)))
    (test-case "procedures filter receives the name symbol"
      (def calls [])
      (def (unmarshal-recording allow? obj)
        (unmarshal (marshal obj)
                   (unmarshal-environment
                    allow-procedure: (lambda (name) (set! calls (cons name calls)) allow?))))
      (check-exception (unmarshal-recording #f compress-gzip) ContractViolation?)
      (check calls => '(std/log/compress#compress-gzip))
      (set! calls [])
      (check (unmarshal-recording #t serde-test-proc) => serde-test-proc)
      (check calls => '(std/serde/serde-test-support#serde-test-proc)))
    (test-case "procedures denied by default"
      (def (rejected? obj)
        (with-catch ContractViolation? (lambda () (unmarshal (marshal obj)) #f)))
      (check-function rejected?
        compress-gzip => #t
        [serde-test-proc] => #t))
    ;; a procedure that cannot be read back (no global name, or a name that does
    ;; not denote it) fails to marshal
    (test-case "procedures without a global name cannot be marshaled"
      (def (make-inner n) (def (inner x) (+ x n)) inner)
      (def (unwritable? obj)
        (with-catch ContractViolation? (lambda () (marshal obj) #f)))
      (check-function unwritable?
        (lambda (x) x) => #t
        (make-inner 1) => #t
        [serde-test-proc (lambda (x) x)] => #t
        serde-test-proc => #f))
    ;; regression: load-class/load-procedure must not require the module to be
    ;; known to the runtime loader when its globals are already bound
    (test-case "class defined in a module loaded from source"
      (let (obj (unmarshal (marshal (BinaryTestLocal x: 7))))
        (check obj ? BinaryTestLocal?)
        (check (BinaryTestLocal-x obj) => 7)))
    (test-case "procedure defined in a module loaded from source"
      (check (unmarshal (marshal binary-test-local-proc)
                        (unmarshal-environment allow-procedure: (lambda (name) #t)))
             => binary-test-local-proc))))
