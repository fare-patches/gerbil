;;; -*- Gerbil -*-
;;; © vyzo
;;; date procedures using libc FFI
(import :std/error
        :std/ffi)
(export current-date string->date date->string seconds->date date->seconds Date (rename: tm? Date?)
        Date-sec Date-min Date-hour
        Date-mday Date-mon Date-year
        Date-wday Date-yday Date-isdst)

;; C preamble
(C-ffi-macrology)
(C-include "<time.h>")

;; struct tm from libc
(def-C-struct tm)

;; Gerbil type alias: Date is tm
(deftype Date tm)

;; field accessors for tm (exported with Date prefix)
(def-C-lambda (___tm-tm_sec (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_sec;")

(def-C-lambda (___tm-tm_min (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_min;")

(def-C-lambda (___tm-tm_hour (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_hour;")

(def-C-lambda (___tm-tm_mday (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_mday;")

(def-C-lambda (___tm-tm_mon (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_mon;")

(def-C-lambda (___tm-tm_year (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_year;")

(def-C-lambda (___tm-tm_wday (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_wday;")

(def-C-lambda (___tm-tm_yday (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_yday;")

(def-C-lambda (___tm-tm_isdst (tm : scheme-object)) => int
  "___result = ___U8VECTOR_AS(struct tm*,___ARG1)->tm_isdst;")

;; Scheme field accessors (use Date type annotation, delegate to tm accessors)
(def (Date-sec (d : Date))
  => :integer
  (___tm-tm_sec d.body))

(def (Date-min (d : Date))
  => :integer
  (___tm-tm_min d.body))

(def (Date-hour (d : Date))
  => :integer
  (___tm-tm_hour d.body))

(def (Date-mday (d : Date))
  => :integer
  (___tm-tm_mday d.body))

(def (Date-mon (d : Date))
  => :integer
  (___tm-tm_mon d.body))

(def (Date-year (d : Date))
  => :integer
  (___tm-tm_year d.body))

(def (Date-wday (d : Date))
  => :integer
  (___tm-tm_wday d.body))

(def (Date-yday (d : Date))
  => :integer
  (___tm-tm_yday d.body))

(def (Date-isdst (d : Date))
  => :integer
  (___tm-tm_isdst d.body))

;; C FFI primitives
;; time(0) -> time_t (long)
(def-C-lambda (___time) => long
  "___result = time(0);")

;; gmtime_r(time_t*, struct tm*) -> void
(def-C-lambda (___gmtime-r (t : long) (tm : scheme-object)) => void
  "gmtime_r((&___arg1), ((struct tm*)(U8_DATA(___arg2))));")

;; strftime(char* buf, size_t, char* fmt, struct tm*) -> size_t
(def-C-lambda (___strftime (buf : scheme-object) (len : long) (fmt : char-string) (tm : scheme-object)) => long
  "___result = strftime((char*)(U8_DATA(___arg1)), ___arg2, ___arg3, ((struct tm*)(U8_DATA(___arg4))));")

;; strptime(char* str, char* fmt, struct tm*) -> bytes consumed, or -1 on failure
(def-C-lambda (___strptime (str : scheme-object) (fmt : char-string) (tm : scheme-object)) => long
  "char *begin = (char*)(U8_DATA(___arg1)); char *end = strptime(begin, ___arg2, ((struct tm*)(U8_DATA(___arg3)))); ___result = end ? (long)(end - begin) : -1;")

;; timegm(struct tm*) -> time_t
(def-C-lambda (___timegm (tm : scheme-object)) => long
  "___result = timegm((struct tm*)(U8_DATA(___arg1)));")

;;; Public API

(def (current-date)
  => Date
  (using (date (tm) : Date)
    (___gmtime-r (___time) date.body)
    date))

(def (date->string (d : Date) (fmt : :string := "%Y-%m-%d %H:%M:%S"))
  => :string
  (let* ((buf (make-u8vector 256 0))
         (len (___strftime buf 256 fmt d.body)))
    (utf8->string buf 0 len)))

(def (string->date (str : :string) (fmt : :string := "%Y-%m-%d %H:%M:%S"))
  => Date
  (using (date (tm) : Date)
    ;; strptime requires a NUL-terminated byte string.
    (let* ((input (string->c-string str))
           (consumed (___strptime input fmt date.body)))
      (cond
       ((negative? consumed)
        (raise-bad-argument string->date "date string does not match format" str fmt))
       ((fx= consumed (fx1- (u8vector-length input)))
        date)
       (else
        (raise-bad-argument string->date "unparsed input at end of date string" str fmt))))))

(def (seconds->date (s : :integer))
  => Date
  (using (date (tm) : Date)
    (___gmtime-r s date.body)
    date))

(def (date->seconds (d : Date))
  => :integer
  (___timegm d.body))
