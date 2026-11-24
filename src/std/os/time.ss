;;; -*- Gerbil -*-
;;; © vyzo
;;; time related OS provided functionality
(import :std/error
        :std/ffi
        ./error)
(export #t)

(def (current-system-time-coarse) => timeval
  (let (tv (make-timeval))
    (do-syscall (__gettimeofday tv))
    tv))

(def (current-system-time-precise) => timespec
  (let (ts (make-timespec))
    (do-syscall (__clock_getrealtime ts))
    ts))

(C-ffi-macrology)
(C-include "<errno.h>"
           "<time.h>"
           "<sys/time.h>")

(def-C-struct timespec)
(def-C-struct timeval)

;; Construct a normalized timespec, rejecting values the platform cannot represent.
(def (seconds+nseconds->timespec (sec : :integer) (nsec : :integer))
  => timespec
  (unless (<= 0 nsec 999999999)
    (raise-bad-argument seconds+nseconds->timespec
                        "nanoseconds between 0 and 999999999" nanoseconds: nsec))
  (unless (<= -9223372036854775808 sec 9223372036854775807)
    (raise-bad-argument seconds+nseconds->timespec "seconds representable as int64" seconds: sec))
  (let (ts (make-timespec))
    (unless (___timespec-fill! (raw-c-struct-body ts) sec nsec)
      (raise-bad-argument seconds+nseconds->timespec "seconds representable as time_t" seconds: sec))
    ts))

(def-C-lambda (___timespec-fill! (ts : scheme-object) (sec : int64) (nsec : long))
  => bool
  "struct timespec *ts = ___U8VECTOR_AS(struct timespec*,___arg1);
   ts->tv_sec = (time_t)___arg2;
   ts->tv_nsec = ___arg3;
   ___result = ((___arg2 >= 0 || (time_t)-1 < (time_t)0) && (int64_t)ts->tv_sec == ___arg2);")

(def (timespec-tv_sec (ts : timespec))
  => :integer
  (___timespec-tv_sec ts.body))

(def-C-lambda (___timespec-tv_sec (ts : scheme-object))
  => int64
  "___result = ___U8VECTOR_AS(struct timespec*,___ARG1)->tv_sec;")

(def (timespec-tv_nsec (ts : timespec))
  => :integer
  (___timespec-tv_nsec ts.body))

(def-C-lambda (___timespec-tv_nsec (ts : scheme-object))
  => long
  "___result = ___U8VECTOR_AS(struct timespec*,___ARG1)->tv_nsec;")

(def (timeval-tv_sec (tv : timeval))
  => :integer
  (___timeval-tv_sec tv.body))

(def-C-lambda (___timeval-tv_sec (tv : scheme-object))
  => int64
  "___result = ___U8VECTOR_AS(struct timeval*,___ARG1)->tv_sec;")

(def (timeval-tv_usec (tv : timeval))
  => :integer
  (___timeval-tv_usec tv.body))

(def-C-lambda (___timeval-tv_usec (tv : scheme-object))
  => long
  "___result = ___U8VECTOR_AS(struct timeval*,___ARG1)->tv_usec;")

(def-C-syscall (__gettimeofday (result :- timeval))
  "gettimeofday(___arg1, NULL)")

(def-C-syscall (__clock_getrealtime (result :- timespec))
  "clock_gettime(CLOCK_REALTIME, ___arg1)")
