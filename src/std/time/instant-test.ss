;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/time/instant tests
;;;
;;; Instant follows TC39 Temporal.Instant: an exact integer count of nanoseconds since
;;; 1970-01-01T00:00:00Z, with arbitrary precision.
;;; Values ported from test262 are cached under doc-cache/temporal/cache/test262-instant-misc/.
;;; Codec checks compare Instants with equal?, so Instant must be a transparent struct
;;; whose only field is its epoch nanoseconds.
(import :std/test
        :std/error
        ./time
        ./precise
        ./instant)
(export instant-test)

(def instant-test
  (test-suite "test :std/time/instant"

    (test-case "Instant constructor requires an exact integer"
      (check-function Instant
        1.5 =>! ContractViolation?
        1/2 =>! ContractViolation?
        +nan.0 =>! ContractViolation?
        "0" =>! ContractViolation?
        #f =>! ContractViolation?))

    (test-case "epoch-nanoseconds codec"
      (check-codec epoch-nanoseconds->instant instant-epoch-nanoseconds
        0 <=> (epoch-seconds->instant 0)
        1 <=> (epoch-nanoseconds->instant 1)
        -1 <=> (epoch-nanoseconds->instant -1)
        1000000 <=> (epoch-milliseconds->instant 1)
        -1000000 <=> (epoch-milliseconds->instant -1)
        1000000000 <=> (epoch-seconds->instant 1)
        -1000000000 <=> (epoch-seconds->instant -1)
        ;; test262 fromEpochNanoseconds/basic.js
        217175010123456789 <=> (epoch-nanoseconds->instant 217175010123456789)
        -217175010876543211 <=> (epoch-nanoseconds->instant -217175010876543211)
        ;; RFC 6238 test times
        59000000000 <=> (epoch-seconds->instant 59)
        1111111109000000000 <=> (epoch-seconds->instant 1111111109)
        20000000000000000000 <=> (epoch-seconds->instant 20000000000)
        ;; test262 fromEpochNanoseconds/limits.js: ±nsMaxInstant are valid
        8640000000000000000000 <=> (epoch-seconds->instant 8640000000000)
        -8640000000000000000000 <=> (epoch-seconds->instant -8640000000000)))

    (test-case "epoch-nanoseconds round-trip beyond the Temporal range"
      (for-each
       (lambda (n) (check (instant-epoch-nanoseconds (epoch-nanoseconds->instant n)) => n))
       [(expt 10 40) (- (expt 10 40))]))

    (test-case "epoch-nanoseconds->instant rejects non-integers"
      (check-function epoch-nanoseconds->instant
        1.5 =>! ContractViolation?
        1/2 =>! ContractViolation?
        1.0 =>! ContractViolation?
        +inf.0 =>! ContractViolation?
        +nan.0 =>! ContractViolation?
        "0" =>! ContractViolation?
        #f =>! ContractViolation?))

    (test-case "epoch-milliseconds codec"
      (def (ns n) (epoch-nanoseconds->instant n))
      (check-codec epoch-milliseconds->instant instant-epoch-milliseconds
        0 <=> (ns 0)
        1 <=> (ns 1000000)
        -1 <=> (ns -1000000)
        ;; test262 fromEpochMilliseconds/basic.js
        217175010123 <=> (ns 217175010123000000)
        -217175010876 <=> (ns -217175010876000000)
        ;; RFC 6238 test times
        59000 <=> (ns 59000000000)
        1111111109000 <=> (ns 1111111109000000000)
        20000000000000 <=> (ns 20000000000000000000)
        ;; test262 fromEpochMilliseconds/limits.js: ±8.64e15 ms are valid
        8640000000000000 <=> (ns 8640000000000000000000)
        -8640000000000000 <=> (ns -8640000000000000000000)
        ;; instant-epoch-milliseconds floors, as Temporal's epochMilliseconds
        0 <= (ns 1)
        0 <= (ns 999999)
        1 <= (ns 1000001)
        -1 <= (ns -1)
        -1 <= (ns -999999)
        -2 <= (ns -1000001)
        ;; test262 prototype/epochMilliseconds/basic.js
        217175010123 <= (ns 217175010123456789)
        -217175010877 <= (ns -217175010876543211)))

    (test-case "epoch-milliseconds round-trip beyond the Temporal range"
      (for-each
       (lambda (n) (check (instant-epoch-milliseconds (epoch-milliseconds->instant n)) => n))
       [(expt 10 40) (- (expt 10 40))]))

    (test-case "epoch-milliseconds->instant rejects non-integers"
      ;; test262 fromEpochMilliseconds/non-integer.js: RangeError.
      ;; Unlike Temporal (JS Numbers), integral flonums are rejected too: exact integers only.
      (check-function epoch-milliseconds->instant
        1.3 =>! ContractViolation?
        -0.5 =>! ContractViolation?
        1/2 =>! ContractViolation?
        1.0 =>! ContractViolation?
        +inf.0 =>! ContractViolation?
        -inf.0 =>! ContractViolation?
        +nan.0 =>! ContractViolation?))

    (test-case "epoch-seconds codec"
      (def (ns n) (epoch-nanoseconds->instant n))
      (check-codec epoch-seconds->instant instant-epoch-seconds
        0 <=> (ns 0)
        1 <=> (ns 1000000000)
        -1 <=> (ns -1000000000)
        ;; RFC 6238 test times
        59 <=> (ns 59000000000)
        1111111109 <=> (ns 1111111109000000000)
        20000000000 <=> (ns 20000000000000000000)
        ;; ±8.64e12 s = ±nsMaxInstant
        8640000000000 <=> (ns 8640000000000000000000)
        -8640000000000 <=> (ns -8640000000000000000000)
        ;; instant-epoch-seconds floors
        0 <= (ns 1)
        0 <= (ns 999999999)
        1 <= (ns 1000000001)
        -1 <= (ns -1)
        -1 <= (ns -999999999)
        -2 <= (ns -1000000001)
        217175010 <= (ns 217175010123456789)
        -217175011 <= (ns -217175010876543211)))

    (test-case "epoch-seconds round-trip beyond the Temporal range"
      (for-each
       (lambda (n) (check (instant-epoch-seconds (epoch-seconds->instant n)) => n))
       [(expt 10 40) (- (expt 10 40))]))

    (test-case "epoch-seconds->instant rejects non-integers"
      (check-function epoch-seconds->instant
        1.5 =>! ContractViolation?
        1/2 =>! ContractViolation?
        1.0 =>! ContractViolation?
        +inf.0 =>! ContractViolation?
        +nan.0 =>! ContractViolation?))

    (test-case "Instant? predicate"
      (check-function Instant?
        (epoch-nanoseconds->instant 0) => #t
        (epoch-milliseconds->instant -1) => #t
        (epoch-seconds->instant 59) => #t
        (current-instant) => #t
        0 => #f
        #f => #f
        (current-time-precise) => #f))

    (test-case "instant=?"
      (check-function instant=?
        (epoch-seconds->instant 59) (epoch-milliseconds->instant 59000) => #t
        (epoch-milliseconds->instant 1111111109000)
        (epoch-nanoseconds->instant 1111111109000000000) => #t
        ;; test262 fromEpoch*/limits.js: ms and ns limits denote the same instants
        (epoch-milliseconds->instant -8640000000000000)
        (epoch-nanoseconds->instant -8640000000000000000000) => #t
        (epoch-seconds->instant 0) (epoch-nanoseconds->instant 1) => #f
        (epoch-seconds->instant -1) (epoch-nanoseconds->instant -999999999) => #f
        (epoch-milliseconds->instant 1) (epoch-nanoseconds->instant 1000001) => #f))

    (test-case "instant-compare"
      (def (cmp a b) (instant-compare (epoch-nanoseconds->instant a)
                                      (epoch-nanoseconds->instant b)))
      (check-function cmp
        0 0 => 0
        0 1 => -1
        1 0 => 1
        -1 0 => -1
        0 -1 => 1
        -1 -1 => 0
        217175010123456789 -217175010876543211 => 1
        -217175010876543211 217175010123456789 => -1
        -8640000000000000000000 8640000000000000000000 => -1
        8640000000000000000000 -8640000000000000000000 => 1
        8640000000000000000000 8640000000000000000000 => 0
        8640000000000000000000 8639999999999999999999 => 1)
      (check-function instant-compare
        (epoch-seconds->instant 59) (epoch-nanoseconds->instant 59000000000) => 0
        (epoch-seconds->instant 59) (epoch-milliseconds->instant 59001) => -1
        (epoch-milliseconds->instant -1) (epoch-nanoseconds->instant -1) => -1))

    (test-case "instant accessors reject non-instants"
      (check-function instant-epoch-nanoseconds
        0 =>! ContractViolation?
        (current-time-precise) =>! ContractViolation?)
      (check (instant-epoch-milliseconds 0) =>! ContractViolation?)
      (check (instant-epoch-seconds 0) =>! ContractViolation?)
      (check (instant-compare 0 (epoch-nanoseconds->instant 0)) =>! ContractViolation?)
      (check (instant=? (epoch-nanoseconds->instant 0) 0) =>! ContractViolation?)
      (check (instant->precise-time 0) =>! ContractViolation?))

    (test-case "current-instant"
      (def t0 (current-time-seconds))
      (def i (current-instant))
      (def t1 (current-time-seconds))
      (check (Instant? i) => #t)
      (check (instant-epoch-seconds i) ? (lambda (s) (<= t0 s t1)))
      ;; consecutive readings never go backwards (barring a wall-clock step)
      (check (instant-compare i (current-instant)) ? (lambda (c) (<= c 0))))

    (test-case "instant->precise-time"
      (def (ns->sec+nsec ns)
        (let (p (instant->precise-time (epoch-nanoseconds->instant ns)))
          [(PreciseTime-seconds p) (PreciseTime-nseconds p)]))
      (check (PreciseTime? (instant->precise-time (epoch-nanoseconds->instant 0))) => #t)
      (check-function ns->sec+nsec
        0 => [0 0]
        1 => [0 1]
        999999999 => [0 999999999]
        1000000000 => [1 0]
        ;; nanoseconds stay in [0, 1e9) for negative instants
        -1 => [-1 999999999]
        -999999999 => [-1 1]
        -1000000000 => [-1 0]
        -1000000001 => [-2 999999999]
        -1500000000 => [-2 500000000]
        217175010123456789 => [217175010 123456789]
        -217175010876543211 => [-217175011 123456789]
        59000000000 => [59 0]
        1111111109000000000 => [1111111109 0]
        20000000000000000000 => [20000000000 0]
        8640000000000000000000 => [8640000000000 0]
        -8640000000000000000000 => [-8640000000000 0]))

    (test-case "precise-time codec"
      (check (instant-epoch-nanoseconds (Instant (expt 10 40))) => (expt 10 40))
      (check (instant->precise-time (Instant (expt 10 40))) =>! ContractViolation?)
      (check (seconds+nseconds->precise-time 0 -1) =>! ContractViolation?)
      (check (seconds+nseconds->precise-time 0 1000000000) =>! ContractViolation?)
      (def (sec+nsec p) [(PreciseTime-seconds p) (PreciseTime-nseconds p)])
      (def (ns n) (epoch-nanoseconds->instant n))
      (def (encode i) (sec+nsec (instant->precise-time i)))
      (def (decode s+n)
        (precise-time->instant (apply seconds+nseconds->precise-time s+n)))
      (check-codec encode decode
        (ns 0) <=> [0 0]
        (ns -1) <=> [-1 999999999]
        (ns -1500000000) <=> [-2 500000000]
        (ns -217175010876543211) <=> [-217175011 123456789]
        (ns 8640000000000000000000) <=> [8640000000000 0]
        (ns -8640000000000000000000) <=> [-8640000000000 0])
      (let* ((p (current-time-precise))
             (i (precise-time->instant p))
             (q (instant->precise-time i)))
        (check (instant-epoch-nanoseconds i)
               => (+ (* (PreciseTime-seconds p) 1000000000) (PreciseTime-nseconds p)))
        (check (instant-epoch-seconds i) => (PreciseTime-seconds p))
        (check (sec+nsec q) => (sec+nsec p))
        (check (precise-time->instant q) => i)))

    (test-case "precise-time->instant rejects non-PreciseTime"
      (check-function precise-time->instant
        0 =>! ContractViolation?
        (epoch-nanoseconds->instant 0) =>! ContractViolation?
        (current-time-coarse) =>! ContractViolation?))))
