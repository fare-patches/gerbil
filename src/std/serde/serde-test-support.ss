;;; -*- Gerbil -*-
;;; © vyzo
;;; serde test support; loaded from source by tests, not compiled into the stdlib
(import :std/interface
	./interface
        ./scan
        ./scanner
        ./serialize
        ./deserialize)
(export #t)

(defclass A (b)
  transparent: #t)
(defclass B (x)
  transparent: #f)

(interface C
  (foo!))

(implement C A
  (foo!
   (lambda (self) self.b)))

(implement ObjectDeserializer
  (A
   (untaint!
    (lambda (self path)
      (untaint! self.b path))))
  (B
   (untaint!
    (lambda (self path)
      (when self.x
	(error "expected x to be #f"))
      (set! self.x 2)))))

;; named global procedure and non-procedure value, for procedure deserialization tests
(def (serde-test-proc x) x)
(def serde-test-value 42)
