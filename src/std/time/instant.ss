;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Instant: an exact point on the POSIX time line, after TC39 Temporal.Instant.
;;; Temporal specification: https://tc39.es/proposal-temporal/
;;; test262 Temporal.Instant tests: https://github.com/tc39/test262/tree/main/test/built-ins/Temporal/Instant
;;; See instant.md for the documentation.
(import ./precise)
(export Instant
        Instant?
        epoch-nanoseconds->instant
        epoch-milliseconds->instant
        epoch-seconds->instant
        instant-epoch-nanoseconds
        instant-epoch-milliseconds
        instant-epoch-seconds
        current-instant
        instant-compare
        instant=?
        instant->precise-time
        precise-time->instant)

;; An exact integer count of nanoseconds since 1970-01-01T00:00:00Z on the POSIX
;; time scale (no leap seconds).
;; Transparent, so equal? compares instants and they print readably.
(defstruct Instant ((epoch-nanoseconds : :integer))
  transparent: #t
  acyclic: #t
  final: #t)

;; Returns the Instant `ns` nanoseconds after the epoch.
(def (epoch-nanoseconds->instant (ns : :integer))
  => Instant
  (Instant ns))

;; Returns the Instant `ms` milliseconds after the epoch.
;; Temporal.Instant.fromEpochMilliseconds, restricted to exact integers.
(def (epoch-milliseconds->instant (ms : :integer))
  => Instant
  (Instant (* ms 1000000)))

;; Returns the Instant `s` seconds after the epoch.
(def (epoch-seconds->instant (s : :integer))
  => Instant
  (Instant (* s 1000000000)))

;; Temporal.Instant.prototype.epochNanoseconds.
(def (instant-epoch-nanoseconds (i : Instant))
  => :integer
  i.epoch-nanoseconds)

;; Temporal.Instant.prototype.epochMilliseconds: floors toward negative infinity.
(def (instant-epoch-milliseconds (i : Instant))
  => :integer
  (floor-quotient i.epoch-nanoseconds 1000000))

;; Whole POSIX seconds, floored like instant-epoch-milliseconds.
(def (instant-epoch-seconds (i : Instant))
  => :integer
  (floor-quotient i.epoch-nanoseconds 1000000000))

;; Temporal.Now.instant: the realtime clock, read through current-time-precise.
(def (current-instant)
  => Instant
  (precise-time->instant (current-time-precise)))

;; Both comparisons use generic arithmetic because epoch counts can be bignums.
;; Temporal.Instant.compare: -1, 0 or 1 as `a` is before, at or after `b`.
(def (instant-compare (a : Instant)
                      (b : Instant))
  => :fixnum
  (let ((x a.epoch-nanoseconds)
        (y b.epoch-nanoseconds))
    (cond
     ((< x y) -1)
     ((> x y) 1)
     (else 0))))

;; Temporal.Instant.prototype.equals.
(def (instant=? (a : Instant)
                (b : Instant))
  => :boolean
  (= a.epoch-nanoseconds b.epoch-nanoseconds))

;; Returns a fresh PreciseTime for `i`, with tv_nsec in [0, 10^9) and tv_sec floored,
;; also for instants before the epoch.
(def (instant->precise-time (i : Instant))
  => PreciseTime
  (let-values (((sec nsec) (floor/ i.epoch-nanoseconds 1000000000)))
    (seconds+nseconds->precise-time sec nsec)))

;; Returns the Instant of `p`.
(def (precise-time->instant (p : PreciseTime))
  => Instant
  (let (ns (+ (* (PreciseTime-seconds p) 1000000000)
              (PreciseTime-nseconds p)))
    (Instant ns)))
