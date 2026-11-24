;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Parsing Temporal instant strings: LL(1) parsers for TC39 Temporal's TemporalInstantString,
;;; RFC 3339 date-times with Temporal's ISO 8601 deviations and RFC 9557 annotations.
;;; Temporal ISO 8601 / RFC 9557 grammar (§13.31):
;;;   https://tc39.es/proposal-temporal/#sec-temporal-iso8601grammar
;;; RFC 3339: https://www.rfc-editor.org/rfc/rfc3339
;;; RFC 9557: https://www.rfc-editor.org/rfc/rfc9557
;;; test262 Temporal.Instant.from tests:
;;;   https://github.com/tc39/test262/tree/main/test/built-ins/Temporal/Instant/from
;;; Howard Hinnant, chrono-Compatible Low-Level Date Algorithms (days_from_civil):
;;;   https://howardhinnant.github.io/date_algorithms.html
;;; See parse.md for the documentation.
(import :std/io
        (only-in :std/text/parser/base raise-parse-error)
        (only-in :std/text/parser/char-set
                 char-ascii-alphabetic?
                 char-ascii-lowercase?
                 char-ascii-numeric?
                 char-ascii-alphanumeric?)
        (only-in :std/text/parser/ll1 ll1-char*)
        (only-in :std/error raise-bad-argument)
        ./instant)
(export ll1-instant)

;; Every parser below follows a production of Temporal §13.31 and is named after it.
;; Each takes a BufferedReader positioned at the start of its production, consumes exactly
;; that production, and raises a ParseError (where: ll1-instant) at the first character
;; that cannot continue it, with that character (or #!eof) as the token irritant.

;; Temporal's nsMaxInstant: 10^8 days of 86400 seconds, in nanoseconds,
;; applies to the Temporal string representation.
(def instant-string-nanoseconds-limit 8640000000000000000000)

;; Consumes one ASCII decimal digit and returns its value;
;; `production` names the grammar production for the error message.
(def (ll1-decimal-digit (reader     : BufferedReader)
                        (production : :string))
  => :fixnum
  (let (c (reader.peek-char-utf8))
    (unless (char-ascii-numeric? c)
      (raise-parse-error ll1-instant (string-append production ": expected a digit") c))
    (reader.read-char-utf8)
    (fx- (char->integer c) 48)))

;; Consumes exactly n ASCII decimal digits and returns their value.
(def (ll1-decimal-digits (reader     : BufferedReader)
                         (n          : :fixnum)
                         (production : :string))
  => :integer
  (let loop ((i n) (r 0))
    (if (fx= i 0)
      r
      (loop (fx1- i) (+ (* 10 r) (ll1-decimal-digit reader production))))))

;; Consumes `char`, or raises a ParseError with `message`.
(def (ll1-expect-char (reader  : BufferedReader)
                      (char    : :char)
                      (message : :string))
  => :void
  (let (c (reader.peek-char-utf8))
    (unless (eqv? c char)
      (raise-parse-error ll1-instant message c))
    (reader.read-char-utf8)
    (void)))

;; Consumes an ASCIISign and returns 1 or -1. U+2212 MINUS SIGN is rejected, as in Temporal.
(def (ll1-ascii-sign (reader     : BufferedReader)
                     (production : :string))
  => :fixnum
  (let (c (reader.peek-char-utf8))
    (case c
      ((#\+) (reader.read-char-utf8) 1)
      ((#\-) (reader.read-char-utf8) -1)
      (else
       (raise-parse-error ll1-instant (string-append production ": expected + or -") c)))))

;; Consumes a two-digit field with a value within [lo, hi].
(def (ll1-two-digits-within (reader     : BufferedReader)
                            (lo         : :fixnum)
                            (hi         : :fixnum)
                            (production : :string))
  => :fixnum
  (let* ((d1 (ll1-decimal-digit reader production))
         (d2 (ll1-decimal-digit reader production))
         (n (fx+ (fx* 10 d1) d2)))
    (unless (fx<= lo n hi)
      (raise-parse-error ll1-instant (string-append production ": out of range") n))
    n))

;;; Dates

;; DateYear: four digits, or an ASCIISign and six digits (expanded year), except -000000.
(def (ll1-date-year (reader : BufferedReader))
  => :integer
  (let (c (reader.peek-char-utf8))
    (if (or (eqv? c #\+) (eqv? c #\-))
      (let* ((sign (ll1-ascii-sign reader "DateYear"))
             (year (ll1-decimal-digits reader 6 "DateYear")))
        (when (and (fx= sign -1) (zero? year))
          (raise-parse-error ll1-instant "DateYear: -000000 is not a valid year" "-000000"))
        (* sign year))
      (ll1-decimal-digits reader 4 "DateYear"))))

;; DateMonth: 01 through 12.
(def (ll1-date-month (reader : BufferedReader))
  => :fixnum
  (ll1-two-digits-within reader 1 12 "DateMonth"))

;; DateDay: 01 through 31; ll1-date checks it against the month.
(def (ll1-date-day (reader : BufferedReader))
  => :fixnum
  (ll1-two-digits-within reader 1 31 "DateDay"))

;; Whether `year` is a leap year of the proleptic Gregorian calendar.
(def (iso-leap-year? (year : :integer))
  => :boolean
  (and (zero? (modulo year 4))
       (or (not (zero? (modulo year 100)))
           (zero? (modulo year 400)))))

;; The number of days of `month` in `year` (Temporal ISODaysInMonth).
(def (iso-days-in-month (year  : :integer)
                        (month : :fixnum))
  => :fixnum
  (case month
    ((2) (if (iso-leap-year? year) 29 28))
    ((4 6 9 11) 30)
    (else 31)))

;; Date ::: DateSpec[+Extended] | DateSpec[~Extended], i.e. YYYY-MM-DD or YYYYMMDD,
;; with IsValidDate. Returns the year, month and day.
(def (ll1-date (reader : BufferedReader))
  => :values ; year month day
  (let* ((year (ll1-date-year reader))
         (extended? (and (eqv? (reader.peek-char-utf8) #\-)
                         (begin (reader.read-char-utf8) #t)))
         (month (ll1-date-month reader))
         (_ (when extended?
              (ll1-expect-char reader #\- "DateSpec: expected - in an extended date")))
         (day (ll1-date-day reader)))
    (unless (fx<= day (iso-days-in-month year month))
      (raise-parse-error ll1-instant "Date: no such day in this month" [year month day]))
    (values year month day)))

;; The number of days from 1970-01-01 to the given date of the proleptic Gregorian
;; calendar: Howard Hinnant's days_from_civil, in exact integer arithmetic.
(def (days-from-civil (year  : :integer)
                      (month : :fixnum)
                      (day   : :fixnum))
  => :integer
  (let* ((y (if (fx<= month 2) (- year 1) year))
         (era (floor-quotient y 400))
         (yoe (- y (* era 400)))                                 ; [0, 399]
         (mp (if (fx> month 2) (fx- month 3) (fx+ month 9)))     ; March = 0
         (doy (+ (quotient (+ (* 153 mp) 2) 5) (- day 1)))       ; [0, 365]
         (doe (+ (* yoe 365) (quotient yoe 4) (- (quotient yoe 100)) doy))) ; [0, 146096]
    (+ (* era 146097) doe -719468)))

;;; Times

;; Hour: 00 through 23.
(def (ll1-hour (reader     : BufferedReader)
               (production : :string))
  => :fixnum
  (ll1-two-digits-within reader 0 23 production))

;; MinuteSecond: 00 through 59.
(def (ll1-minute-second (reader     : BufferedReader)
                        (production : :string))
  => :fixnum
  (ll1-two-digits-within reader 0 59 production))

;; TimeSecond: MinuteSecond or 60 (a leap second).
(def (ll1-time-second (reader : BufferedReader))
  => :fixnum
  (ll1-two-digits-within reader 0 60 "TimeSecond"))

;; Whether c starts a TemporalDecimalFraction.
(def (decimal-separator? c)
  => :boolean
  (or (eqv? c #\.) (eqv? c #\,)))

;; TemporalDecimalFraction: . or , then 1 through 9 digits; returns nanoseconds.
(def (ll1-temporal-decimal-fraction (reader : BufferedReader))
  => :fixnum
  (reader.read-char-utf8) ; the decimal separator, peeked by the caller
  (let loop ((n (ll1-decimal-digit reader "TemporalDecimalFraction"))
             (scale 100000000))
    (let (c (reader.peek-char-utf8))
      (cond
       ((not (char-ascii-numeric? c))
        (fx* n scale))
       ((fx= scale 1)
        (raise-parse-error ll1-instant "TemporalDecimalFraction: more than 9 digits" c))
       (else
        (reader.read-char-utf8)
        (loop (fx+ (fx* 10 n) (fx- (char->integer c) 48)) (fxquotient scale 10)))))))

;; Optional TemporalDecimalFraction: nanoseconds, 0 when absent.
(def (ll1-temporal-decimal-fraction? (reader : BufferedReader))
  => :fixnum
  (if (decimal-separator? (reader.peek-char-utf8))
    (ll1-temporal-decimal-fraction reader)
    0))

;; Time ::: TimeSpec[+Extended] | TimeSpec[~Extended]: HH[:MM[:SS[.f]]] or HH[MM[SS[.f]]].
;; Only seconds may have a fraction. Returns hour, minute, second (60 kept) and nanosecond.
(def (ll1-time-spec (reader : BufferedReader))
  => :values ; hour minute second nanosecond
  (let* ((hour (ll1-hour reader "Hour"))
         (c (reader.peek-char-utf8))
         (extended? (eqv? c #\:)))
    (if (or extended? (char-ascii-numeric? c))
      (let* ((_ (when extended? (reader.read-char-utf8)))
             (minute (ll1-minute-second reader "MinuteSecond"))
             (c (reader.peek-char-utf8)))
        (if (if extended? (eqv? c #\:) (char-ascii-numeric? c))
          (let* ((_ (when extended? (reader.read-char-utf8)))
                 (second (ll1-time-second reader))
                 (nanosecond (ll1-temporal-decimal-fraction? reader)))
            (values hour minute second nanosecond))
          (values hour minute 0 0)))
      (values hour 0 0 0))))

;;; UTC offsets

;; UTCOffset[SubMinutePrecision]: ±HH, ±HH:MM, ±HHMM, and when sub-minute? also
;; ±HH:MM:SS[.f] and ±HHMMSS[.f]. Separators must be consistent.
;; Returns the offset east of UTC in nanoseconds.
(def (ll1-utc-offset (reader      : BufferedReader)
                     (sub-minute? : :boolean))
  => :integer
  (let* ((sign (ll1-ascii-sign reader "UTCOffset"))
         (hour (ll1-hour reader "UTCOffset"))
         (c (reader.peek-char-utf8))
         (extended? (eqv? c #\:)))
    (* sign
       (if (or extended? (char-ascii-numeric? c))
         (let* ((_ (when extended? (reader.read-char-utf8)))
                (minute (ll1-minute-second reader "UTCOffset"))
                (c (reader.peek-char-utf8)))
           (if (and sub-minute? (if extended? (eqv? c #\:) (char-ascii-numeric? c)))
             (let* ((_ (when extended? (reader.read-char-utf8)))
                    (second (ll1-minute-second reader "UTCOffset"))
                    (nanosecond (ll1-temporal-decimal-fraction? reader)))
               (+ (* (+ (* 3600 hour) (* 60 minute) second) 1000000000) nanosecond))
             (* (+ (* 3600 hour) (* 60 minute)) 1000000000)))
         (* 3600 hour 1000000000)))))

;; Whether c starts a DateTimeUTCOffset[+Z].
(def (date-time-utc-offset-start? c)
  => :boolean
  (and (memv c '(#\Z #\z #\+ #\-)) #t))

;; DateTimeUTCOffset[+Z]: UTCDesignator (Z or z) or UTCOffset[+SubMinutePrecision].
;; Returns the offset east of UTC in nanoseconds.
(def (ll1-date-time-utc-offset (reader : BufferedReader))
  => :integer
  (case (reader.peek-char-utf8)
    ((#\Z #\z) (reader.read-char-utf8) 0)
    (else (ll1-utc-offset reader #t))))

;;; Annotations

;; Characters of an AnnotationKey or a TimeZoneIANAName: TZChar, / and AKeyChar.
(def (annotation-name-char? c)
  => :boolean
  (or (char-ascii-alphanumeric? c)
      (and (memv c '(#\. #\_ #\- #\+ #\/)) #t)))

;; The longest run of annotation-name-char? characters, or #f if there is none.
;; Annotation keys and IANA names share a prefix, so ll1-annotations reads this run first
;; and then decides by the next character: = for an Annotation, ] for a TimeZoneAnnotation.
(def ll1-annotation-name (ll1-char* annotation-name-char?))

;; AnnotationKey: AKeyLeadingChar (lowercase or _) then AKeyChar* (lowercase, digit, _ or -).
(def (annotation-key? (name : :string))
  => :boolean
  (let (n (string-length name))
    (let loop ((i 0))
      (or (fx= i n)
          (let (c (string-ref name i))
            (and (or (char-ascii-lowercase? c)
                     (eqv? c #\_)
                     (and (fx> i 0) (or (char-ascii-numeric? c) (eqv? c #\-))))
                 (loop (fx1+ i))))))))

;; TimeZoneIANAName: TimeZoneIANANameComponents separated by /, each a TZLeadingChar
;; (alphabetic, . or _) followed by TZChars (also digits, - and +).
(def (time-zone-iana-name? (name : :string))
  => :boolean
  (let (n (string-length name))
    (let loop ((i 0) (leading? #t))
      (if (fx= i n)
        (not leading?)
        (let (c (string-ref name i))
          (cond
           ((eqv? c #\/)
            (and (not leading?) (loop (fx1+ i) #t)))
           ((or (char-ascii-alphabetic? c) (eqv? c #\.) (eqv? c #\_))
            (loop (fx1+ i) #f))
           ((or (char-ascii-numeric? c) (eqv? c #\-) (eqv? c #\+))
            (and (not leading?) (loop (fx1+ i) #f)))
           (else #f)))))))

;; AnnotationValue: AnnotationValueComponents (alphanumeric runs) separated by single -.
(def (ll1-annotation-value (reader : BufferedReader))
  => :string
  (call-with-output-string
   (lambda (out)
     (let loop ()
       (let (c (reader.peek-char-utf8))
         (unless (char-ascii-alphanumeric? c)
           (raise-parse-error ll1-instant "AnnotationValue: expected a letter or digit" c)))
       (while (char-ascii-alphanumeric? (reader.peek-char-utf8))
         (write-char (reader.read-char-utf8) out))
       (when (eqv? (reader.peek-char-utf8) #\-)
         (write-char (reader.read-char-utf8) out)
         (loop))))))

;; TimeZoneAnnotation? Annotations?, with ParseISODateTime's annotation rules:
;; - at most one time zone annotation, before any other annotation;
;; - the first u-ca annotation is the calendar; a later one is rejected
;;   if it or the first one is critical (!);
;; - other keys are ignored unless critical, in which case they are rejected.
;; Returns the time zone (an IANA name string, an offset in nanoseconds east of UTC,
;; or #f) and the calendar (a string or #f), neither of them validated against any database.
(def (ll1-annotations (reader : BufferedReader))
  => :values ; time-zone calendar
  (let loop ((first? #t) (time-zone #f) (calendar #f) (calendar-critical? #f))
    (if (not (eqv? (reader.peek-char-utf8) #\[))
      (values time-zone calendar)
      (let* ((_ (reader.read-char-utf8))
             (critical? (and (eqv? (reader.peek-char-utf8) #\!)
                             (begin (reader.read-char-utf8) #t)))
             (c (reader.peek-char-utf8)))
        (if (or (eqv? c #\+) (eqv? c #\-))
          ;; TimeZoneIdentifier ::: UTCOffset[~SubMinutePrecision]
          (let (offset (ll1-utc-offset reader #f))
            (unless first?
              (raise-parse-error ll1-instant "TimeZoneAnnotation: only one, before other annotations" c))
            (ll1-expect-char reader #\] "TimeZoneAnnotation: expected ]")
            (loop #f offset calendar calendar-critical?))
          (let ((name (ll1-annotation-name reader))
                (c (reader.peek-char-utf8)))
            (unless name
              (raise-parse-error ll1-instant "Annotation: expected a time zone or a key" c))
            (case c
              ((#\=)
               (unless (annotation-key? name)
                 (raise-parse-error ll1-instant "AnnotationKey: invalid key" name))
               (reader.read-char-utf8)
               (let (value (ll1-annotation-value reader))
                 (ll1-expect-char reader #\] "Annotation: expected ]")
                 (cond
                  ((not (equal? name "u-ca"))
                   (when critical?
                     (raise-parse-error ll1-instant "Annotation: unknown critical annotation" name))
                   (loop #f time-zone calendar calendar-critical?))
                  ((not calendar)
                   (loop #f time-zone value critical?))
                  ((or critical? calendar-critical?)
                   (raise-parse-error ll1-instant "Annotation: multiple calendars, one of them critical"
                                      value))
                  (else
                   (loop #f time-zone calendar calendar-critical?)))))
              ((#\])
               (unless first?
                 (raise-parse-error ll1-instant "TimeZoneAnnotation: only one, before other annotations"
                                    name))
               (unless (time-zone-iana-name? name)
                 (raise-parse-error ll1-instant "TimeZoneIANAName: invalid time zone name" name))
               (reader.read-char-utf8)
               (loop #f name calendar calendar-critical?))
              (else
               (raise-parse-error ll1-instant "Annotation: expected = or ]" c)))))))))

;;; Instants

;; Whether c is a DateTimeSeparator: T, t or space.
(def (date-time-separator? c)
  => :boolean
  (and (memv c '(#\T #\t #\space)) #t))

;; Parses a TemporalInstantString from `reader` and returns its Instant
;; (Temporal ToTemporalInstant on a string):
;;   Date DateTimeSeparator Time DateTimeUTCOffset[+Z] TimeZoneAnnotation? Annotations?
;; A leap second 60 is read as 59. The time zone and calendar annotations are ignored.
;; With default-offset: s (exact integer seconds east of UTC, |s| < 86400), a date-time
;; without a UTC offset, or a date without a time (meaning midnight), is read at offset s;
;; a time zone annotation still requires a UTC offset.
;; Raises ParseError on invalid syntax, invalid dates and instants beyond ±10^8 days.
;; Consumes no input past the instant; use (ll1 ll1-instant string) to parse a whole string.
(def (ll1-instant (reader : BufferedReader)
                  default-offset: (default-offset :? :integer := #f))
  => Instant
  (when default-offset
    (unless (< -86400 default-offset 86400)
      (raise-bad-argument ll1-instant "default-offset: seconds within ±86400" default-offset)))
  (let*-values
      (((year month day) (ll1-date reader))
       ((c) (reader.peek-char-utf8))
       ((hour minute second nanosecond offset)
        (cond
         ((date-time-separator? c)
          (reader.read-char-utf8)
          (let-values (((hour minute second nanosecond) (ll1-time-spec reader)))
            (values hour minute second nanosecond
                    (and (date-time-utc-offset-start? (reader.peek-char-utf8))
                         (ll1-date-time-utc-offset reader)))))
         ((and default-offset (or (eof-object? c) (eqv? c #\[)))
          (values 0 0 0 0 #f))
         (else
          (raise-parse-error ll1-instant "DateTimeSeparator: expected T, t or space" c)))))
    (unless (or offset default-offset)
      (raise-parse-error ll1-instant "DateTimeUTCOffset: expected Z or a UTC offset"
                         (reader.peek-char-utf8)))
    (let-values (((time-zone _calendar) (ll1-annotations reader)))
      (when (and time-zone (not offset))
        (raise-parse-error ll1-instant "TimeZoneAnnotation: requires an explicit UTC offset"
                           time-zone))
      (let* ((seconds (+ (* 86400 (days-from-civil year month day))
                         (* 3600 hour)
                         (* 60 minute)
                         (if (fx= second 60) 59 second)))
             (ns (- (+ (* seconds 1000000000) nanosecond)
                    (or offset (* default-offset 1000000000)))))
        (unless (<= (- instant-string-nanoseconds-limit) ns instant-string-nanoseconds-limit)
          (raise-parse-error ll1-instant "instant beyond ±10^8 days of the epoch" ns))
        ;; Numeric Instant constructors accept arbitrary precision.
        (Instant ns)))))
