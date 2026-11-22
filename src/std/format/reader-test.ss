;;; -*- Gerbil -*-
;;; © vyzo
;;; reader tests
(import :std/test
        :std/error
        :std/iter
	:std/interface
	:std/log/compress
	:std/serde/interface
	:std/serde/deserialize
        "../serde/serde-test-support"
	./api
	./io
	./reader)
(export reader-test reader-dag-test reader-default-test)

;; a class and a procedure defined in this test module itself: the module is loaded
;; from source by the expander, never registered with the runtime loader and never
;; compiled, so reading them back must use the already-bound global rather than load-module.
(defclass ReaderTestLocal (x)
  transparent: #t)
;; deserialized objects must be untainted explicitly
(defobject-untaint ReaderTestLocal)
(def (reader-test-local-proc x) x)

(def reader-test
  (test-suite "read format written objects"
    (test-case "read integers"
      (check (read-object-from-string "1234" (reader-environment))
	     => 1234)
      (check (read-object-from-string "123456789012345678901234567890" (reader-environment))
	     =>  123456789012345678901234567890)
      (check (read-object-from-string "#x1234ab" (reader-environment))
	     => #x1234ab)
      (check (read-object-from-string "#x012345ab" (reader-environment))
	     => #x12345ab)
      (check (read-object-from-string "#x12345ab" (reader-environment))
	     => #x12345ab)
      (check (read-object-from-string "#x1234AB" (reader-environment))
	     => #x1234ab)
      (check (read-object-from-string "#b1001" (reader-environment))
	     => #b1001)
      (check (read-object-from-string "#o1234" (reader-environment))
	     => #o1234))
    (test-case "read flonums"
      (check (read-object-from-string "1." (reader-environment))
	     => 1.)
      (check (read-object-from-string "1.1" (reader-environment))
	     => 1.1)
      (check (read-object-from-string "1.10000" (reader-environment))
	     => 1.1))
    (test-case "read ratnums"
      (check (read-object-from-string "1/3" (reader-environment))
	     => 1/3)
      (check (read-object-from-string "-1/3" (reader-environment))
	     => -1/3))
    (test-case "read cpxnums"
      (check (read-object-from-string "3+i" (reader-environment))
	     => 3+i)
      (check (read-object-from-string "3-i" (reader-environment))
	     => 3-i)
      (check (read-object-from-string "3+2i" (reader-environment))
	     => 3+2i)
      (check (read-object-from-string "3-2i" (reader-environment))
	     => 3-2i)
      (check (read-object-from-string "+i" (reader-environment))
	     => +i)
      (check (read-object-from-string "-i" (reader-environment))
	     => -i))
    (test-case "read special numbers"
      (check (read-object-from-string "+inf.0" (reader-environment))
	     => +inf.0)
      (check (read-object-from-string "-inf.0" (reader-environment))
	     => -inf.0)
      (check (read-object-from-string "+nan.0" (reader-environment))
	     ? nan?)
      (check (read-object-from-string "-nan.0" (reader-environment))
	     ? nan?))
    (test-case "read symbolic"
      (check (read-object-from-string "foo" (reader-environment))
	     => 'foo)
      (check (read-object-from-string "|foo:bar baz|" (reader-environment))
	     => '|foo:bar baz|)
      (check (read-object-from-string "foo:" (reader-environment))
	     => 'foo:)
      (check (read-object-from-string "|foo:bar baz|:" (reader-environment))
	     => '|foo:bar baz|:))
    (test-case "read lists"
      (check (read-object-from-string "(1 2 3)" (reader-environment))
	     => '(1 2 3))
      (check (read-object-from-string "(1 2 3 . 4)" (reader-environment))
	     => '(1 2 3 . 4))
      (let (x [1 . #f])
	(check (read-object-from-string "(1 . #f)" (reader-environment))
	       => x)
	(set-cdr! x x)
	(check (read-object-from-string "#0=(1 . #0#)" (reader-environment))
	       => x)
	(set-cdr! x [2 . x])
	(check (read-object-from-string "#0=(1 2 . #0#)" (reader-environment))
	       => x)
	(set-cdr! x [x . x])
	(check (read-object-from-string "#0=(1 #0# . #0#)" (reader-environment))
	       => x))
      (let ((x [1 . #f])
	    (y [#f . #f]))
	(set-cdr! x x)
	(set-cdr! y y)
	(set-car! y x)
	(check (read-object-from-string "#0=(#1=(1 . #1#) . #0#)" (reader-environment))
	       => y)))
    (test-case "read strings"
      (check (read-object-from-string "\"the quick brown fox\"" (reader-environment))
	     => "the quick brown fox")
      (check (read-object-from-string "\"the quick brown fox\\r\\n\"" (reader-environment))
	     => "the quick brown fox\r\n"))
    (test-case "read vectors"
      (check (read-object-from-string "#(a b c)" (reader-environment))
	     => '#(a b c))
      (let (x (vector #f 'b 'c))
	(vector-set! x 0 x)
	(check (read-object-from-string "#0=#(#0# b c)" (reader-environment))
	       => x))
      (check (read-object-from-string "#[a b c]" (reader-environment))
	     => (values 'a 'b 'c))
      (check (read-object-from-string "#&1" (reader-environment))
	     => '#&1)
      (check (read-object-from-string "#u8(0 1 2 3)" (reader-environment))
	     =>  '#u8(0 1 2 3))
      (check (read-object-from-string "#u16(0 1 2 3)" (reader-environment))
	     => '#u16(0 1 2 3))
      (check (read-object-from-string "#u32(0 1 2 3)" (reader-environment))
	     =>  '#u32(0 1 2 3))
      (check (read-object-from-string "#u64(0 1 2 3)" (reader-environment))
	     =>  '#u64(0 1 2 3))
      (check (read-object-from-string "#s8(0 1 2 3)" (reader-environment))
	     =>  '#s8(0 1 2 3))
      (check (read-object-from-string "#s16(0 1 2 3)" (reader-environment))
	     => '#s16(0 1 2 3))
      (check (read-object-from-string "#s32(0 1 2 3)" (reader-environment))
	     => '#s32(0 1 2 3))
      (check (read-object-from-string "#s64(0 1 2 3)" (reader-environment))
	     =>  '#s64(0 1 2 3))
      (check (read-object-from-string "#f32(0. 1. 2. 3.)" (reader-environment))
	     => '#f32(0.0 1.0 2.0 3.0))
      (check (read-object-from-string "#f64(0. 1. 2. 3.)" (reader-environment))
	     => '#f64(0.0 1.0 2.0 3.0)))
    (test-case "read objects"
      (let ()
	(def b (B x: 2))
	(def a (A b: b))
	(let (obj (read-object-from-string "#{std/serde/serde-test-support#A::t b: #{std/serde/serde-test-support#B::t}}" (reader-environment)))
	  (check obj ? A?)
	  (check (A-b obj) ? B?)
	  (check (B-x (A-b obj)) => 2)))
      (let ()
	(def c (A b: #f))
	(set! (A-b c) c)
	(let (obj (read-object-from-string "#0=#{std/serde/serde-test-support#A::t b: #0#}" (reader-environment)))
	  (check obj ? A?)
	  (check (A-b obj) => obj))))
    ;; A dot starts a dotted tail only when a delimiter follows it (R7RS §2.1, §7.1.2);
    ;; otherwise it starts a number or symbol, which the writer emits e.g. for 0.1 as ".1".
    (test-case "read leading-dot tokens"
      (def (read-string str) (read-object-from-string str (reader-environment)))
      (check-function read-string
        ".1" => .1
        "-.5" => -.5
        "(.1)" => '(.1)
        "(1 .1)" => '(1 .1)
        "(1 . .1)" => '(1 . .1)
        "(.1 . 2)" => '(.1 . 2)
        "[.25 .5]" => '(.25 .5)
        "(a ...)" => '(a ...)
        "(... a)" => '(... a))
      (check (A-b (read-string "#{std/serde/serde-test-support#A::t b: .5}")) => .5))
    (test-case "read interface instances"
      (let (obj (read-object-from-string "#{std/serde/serde-test-support#C::t object: #{std/serde/serde-test-support#A::t b: 1}}" (reader-environment)))
	(check obj ? C?)
	(check (C-foo! obj) => 1)))
    (test-case "read hashes"
      (let (obj (read-object-from-string "#{HashTable::t object: #:{hash-table::t ((b . 2) (a . 1))}}" (reader-environment)))
	(check obj ? HashTable?)
	(check (hash-length obj) => 2)
	(check (hash-ref obj 'a) => 1)
	(check (hash-ref obj 'b) => 2)))
    ;; A procedure is written as #{procedure name: <global-name>}; reading it resolves
    ;; the global binding, after allow-procedure: accepts the name, passed as a symbol.
    ;; Procedures equal? only when eq?, so => on procedures checks identity.
    (test-case "read procedures"
      (def (read-allowed str)
        (read-object-from-string str (reader-environment allow-procedure: (lambda (name) #t))))
      (def (round-trip obj) (read-allowed (format "%s" obj)))
      (check-function round-trip
        compress-gzip => compress-gzip
        serde-test-proc => serde-test-proc
        [compress-gzip serde-test-proc compress-gzip] => [compress-gzip serde-test-proc compress-gzip])
      (check-function read-allowed
        "#{procedure name: std/log/compress#compress-gzip}" => compress-gzip
        "#{procedure name: std/serde/serde-test-support#serde-test-proc}" => serde-test-proc
        "(#{procedure name: std/log/compress#compress-gzip} #{procedure name: std/log/compress#compress-gzip})"
        => [compress-gzip compress-gzip]))
    (test-case "read procedures inside objects"
      (def (read-allowed str)
        (read-object-from-string str (reader-environment allow-procedure: (lambda (name) #t))))
      (let (obj (read-allowed "#{std/serde/serde-test-support#A::t b: #{procedure name: std/serde/serde-test-support#serde-test-proc}}"))
        (check obj ? A?)
        (check (A-b obj) => serde-test-proc))
      (let (obj (read-allowed (format "%s" (A b: [serde-test-proc (A b: serde-test-proc)]))))
        (check (car (A-b obj)) => serde-test-proc)
        (check (A-b (cadr (A-b obj))) => serde-test-proc)))
    ;; regression: load-class/load-procedure must not require the module to be
    ;; known to the runtime loader when its globals are already bound
    (test-case "read class defined in a module loaded from source"
      (let (obj (read-object-from-string "#{std/format/reader-test#ReaderTestLocal::t x: 7}" (reader-environment)))
        (check obj ? ReaderTestLocal?)
        (check (ReaderTestLocal-x obj) => 7)))
    (test-case "read procedure defined in a module loaded from source"
      (check (read-object-from-string "#{procedure name: std/format/reader-test#reader-test-local-proc}"
                                      (reader-environment allow-procedure: (lambda (name) #t)))
             => reader-test-local-proc))
    (test-case "read procedures filter receives the name symbol"
      (def calls [])
      (def (read-recording allow? str)
        (read-object-from-string str
          (reader-environment allow-procedure: (lambda (name) (set! calls (cons name calls)) allow?))))
      (check-exception (read-recording #f "#{procedure name: std/log/compress#compress-gzip}")
                       ContractViolation?)
      (check calls => '(std/log/compress#compress-gzip))
      (set! calls [])
      (check (read-recording #t "#{procedure name: std/serde/serde-test-support#serde-test-proc}")
             => serde-test-proc)
      (check calls => '(std/serde/serde-test-support#serde-test-proc)))
    (test-case "reject procedures"
      ;; allow? #f reads in the default environment, which denies all procedures
      (def (rejected? allow? str)
        (def env (if allow? (reader-environment allow-procedure: allow?) (reader-environment)))
        (with-catch ContractViolation? (lambda () (read-object-from-string str env) #f)))
      (def (allow-all name) #t)
      (check-function rejected?
        #f "#{procedure name: std/log/compress#compress-gzip}" => #t
        #f (format "%s" serde-test-proc) => #t
        ;; allowed but unbound, bound to a non-procedure, or missing a name
        allow-all "#{procedure name: std/log/compress#no-such-proc}" => #t
        allow-all "#{procedure name: std/serde/serde-test-support#serde-test-value}" => #t
        allow-all "#{procedure}" => #t))
    ;; %s output is meant to be read back, so a procedure that cannot be read back
    ;; (no global name, or a name that does not denote it) fails to write;
    ;; %a and %q are not meant to be read back, and write it anyway.
    (test-case "write procedures without a global name"
      (def (make-inner n) (def (inner x) (+ x n)) inner)
      (def (unwritable? obj)
        (with-catch ContractViolation? (lambda () (format "%s" obj) #f)))
      (check-function unwritable?
        (lambda (x) x) => #t
        (make-inner 1) => #t
        [serde-test-proc (lambda (x) x)] => #t
        serde-test-proc => #f)
      (check (format "%a" (lambda (x) x)) => "#{procedure}")
      (check (format "%q" (lambda (x) x)) => "#{procedure}"))
      ))

(def reader-dag-test
  (test-suite "read dag format written objects"
    (test-case "read integers"
      (check (read-object-from-string "1234" (reader-environment dag: #t))
	     => 1234)
      (check (read-object-from-string "123456789012345678901234567890" (reader-environment dag: #t))
	     =>  123456789012345678901234567890)
      (check (read-object-from-string "#x1234ab" (reader-environment dag: #t))
	     => #x1234ab)
      (check (read-object-from-string "#x012345ab" (reader-environment dag: #t))
	     => #x12345ab)
      (check (read-object-from-string "#x12345ab" (reader-environment dag: #t))
	     => #x12345ab)
      (check (read-object-from-string "#x1234AB" (reader-environment dag: #t))
	     => #x1234ab)
      (check (read-object-from-string "#b1001" (reader-environment dag: #t))
	     => #b1001)
      (check (read-object-from-string "#o1234" (reader-environment dag: #t))
	     => #o1234))
    (test-case "read flonums"
      (check (read-object-from-string "1." (reader-environment dag: #t))
	     => 1.)
      (check (read-object-from-string "1.1" (reader-environment dag: #t))
	     => 1.1)
      (check (read-object-from-string "1.10000" (reader-environment dag: #t))
	     => 1.1))
    (test-case "read ratnums"
      (check (read-object-from-string "1/3" (reader-environment dag: #t))
	     => 1/3)
      (check (read-object-from-string "-1/3" (reader-environment dag: #t))
	     => -1/3))
    (test-case "read cpxnums"
      (check (read-object-from-string "3+i" (reader-environment dag: #t))
	     => 3+i)
      (check (read-object-from-string "3-i" (reader-environment dag: #t))
	     => 3-i)
      (check (read-object-from-string "3+2i" (reader-environment dag: #t))
	     => 3+2i)
      (check (read-object-from-string "3-2i" (reader-environment dag: #t))
	     => 3-2i)
      (check (read-object-from-string "+i" (reader-environment dag: #t))
	     => +i)
      (check (read-object-from-string "-i" (reader-environment dag: #t))
	     => -i))
    (test-case "read special numbers"
      (check (read-object-from-string "+inf.0" (reader-environment dag: #t))
	     => +inf.0)
      (check (read-object-from-string "-inf.0" (reader-environment dag: #t))
	     => -inf.0)
      (check (read-object-from-string "+nan.0" (reader-environment dag: #t))
	     ? nan?)
      (check (read-object-from-string "-nan.0" (reader-environment dag: #t))
	     ? nan?))
    (test-case "read symbolic"
      (check (read-object-from-string "foo" (reader-environment dag: #t))
	     => 'foo)
      (check (read-object-from-string "|foo:bar baz|" (reader-environment dag: #t))
	     => '|foo:bar baz|)
      (check (read-object-from-string "foo:" (reader-environment dag: #t))
	     => 'foo:)
      (check (read-object-from-string "|foo:bar baz|:" (reader-environment dag: #t))
	     => '|foo:bar baz|:))
    (test-case "read lists"
      (check (read-object-from-string "(1 2 3)" (reader-environment dag: #t))
	     => '(1 2 3))
      (check (read-object-from-string "(1 2 3 . 4)" (reader-environment dag: #t))
	     => '(1 2 3 . 4))
      (let (x [1 . #f])
	(check (read-object-from-string "(1 . #f)" (reader-environment dag: #t))
	       => x)
	(set-cdr! x x)
	(check-exception (read-object-from-string "#0=(1 . #0#)" (reader-environment dag: #t))
			 ContractViolation?)
	(set-cdr! x [2 . x])
	(check-exception (read-object-from-string "#0=(1 2 . #0#)" (reader-environment dag: #t))
			 ContractViolation?)
	(set-cdr! x [x . x])
	(check-exception (read-object-from-string "#0=(1 #0# . #0#)" (reader-environment dag: #t))
			 ContractViolation?))
      (let ((x [1 . #f])
	    (y [#f . #f]))
	(set-cdr! x x)
	(set-cdr! y y)
	(set-car! y x)
	(check-exception (read-object-from-string "#0=(#1=(1 . #1#) . #0#)" (reader-environment dag: #t))
			 ContractViolation?)))
    (test-case "read strings"
      (check (read-object-from-string "\"the quick brown fox\"" (reader-environment dag: #t))
	     => "the quick brown fox")
      (check (read-object-from-string "\"the quick brown fox\\r\\n\"" (reader-environment dag: #t))
	     => "the quick brown fox\r\n"))
    (test-case "read vectors"
      (check (read-object-from-string "#(a b c)" (reader-environment dag: #t))
	     => '#(a b c))
      (let (x (vector #f 'b 'c))
	(vector-set! x 0 x)
	(check-exception (read-object-from-string "#0=#(#0# b c)" (reader-environment dag: #t))
			 ContractViolation?)
      (check (read-object-from-string "#[a b c]" (reader-environment dag: #t))
	     => (values 'a 'b 'c))
      (check (read-object-from-string "#&1" (reader-environment dag: #t))
	     => '#&1)
      (check (read-object-from-string "#u8(0 1 2 3)" (reader-environment dag: #t))
	     =>  '#u8(0 1 2 3))
      (check (read-object-from-string "#u16(0 1 2 3)" (reader-environment dag: #t))
	     => '#u16(0 1 2 3))
      (check (read-object-from-string "#u32(0 1 2 3)" (reader-environment dag: #t))
	     =>  '#u32(0 1 2 3))
      (check (read-object-from-string "#u64(0 1 2 3)" (reader-environment dag: #t))
	     =>  '#u64(0 1 2 3))
      (check (read-object-from-string "#s8(0 1 2 3)" (reader-environment dag: #t))
	     =>  '#s8(0 1 2 3))
      (check (read-object-from-string "#s16(0 1 2 3)" (reader-environment dag: #t))
	     => '#s16(0 1 2 3))
      (check (read-object-from-string "#s32(0 1 2 3)" (reader-environment dag: #t))
	     => '#s32(0 1 2 3))
      (check (read-object-from-string "#s64(0 1 2 3)" (reader-environment dag: #t))
	     =>  '#s64(0 1 2 3))
      (check (read-object-from-string "#f32(0. 1. 2. 3.)" (reader-environment dag: #t))
	     => '#f32(0.0 1.0 2.0 3.0))
      (check (read-object-from-string "#f64(0. 1. 2. 3.)" (reader-environment dag: #t))
	     => '#f64(0.0 1.0 2.0 3.0)))
    (test-case "read objects"
      (let ()
	(def b (B x: 2))
	(def a (A b: b))
	(check-exception (read-object-from-string "#{std/serde/serde-test-support#A::t b: #{std/serde/serde-test-support#B::t}}" (reader-environment dag: #t))
			 ContractViolation?))
      (let ()
	(def c (A b: #f))
	(set! (A-b c) c)
	(check-exception (read-object-from-string "#0=#{std/serde/serde-test-support#A::t b: #0#}" (reader-environment dag: #t))
			 ContractViolation?))
    (test-case "read interface instances"
      (let (obj (read-object-from-string "#{std/serde/serde-test-support#C::t object: #{std/serde/serde-test-support#A::t b: 1}}" (reader-environment dag: #t)))
	(check obj ? C?)
	(check (C-foo! obj) => 1)))
    (test-case "read hashes"
      (let (obj (read-object-from-string "#{HashTable::t object: #:{hash-table::t ((b . 2) (a . 1))}}" (reader-environment dag: #t)))
	(check obj ? HashTable?)
	(check (hash-length obj) => 2)
	(check (hash-ref obj 'a) => 1)
	(check (hash-ref obj 'b) => 2)))
    ))))

(def reader-default-test
  (test-suite "reader default environment"
    (test-case "read cycles"
      (let (x [1 . #f])
	(check (read-object-from-string "(1 . #f)")
	       => x)
	(set-cdr! x x)
	(check (read-object-from-string "#0=(1 . #0#)")
	       => x)
	(set-cdr! x [2 . x])
	(check (read-object-from-string "#0=(1 2 . #0#)")
	       => x)
	(set-cdr! x [x . x])
	(check (read-object-from-string "#0=(1 #0# . #0#)")
	       => x)))))
