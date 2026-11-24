;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/time/parse tests
;;;
;;; :std/time/parse ports TC39 Temporal's Instant string parsing
;;; (TemporalInstantString: RFC 3339 date-time + Temporal deviations + RFC 9557 annotations).
;;; Vectors are ported from test262, test/built-ins/Temporal/Instant/from, one test-case per file:
;;;   https://github.com/tc39/test262/tree/main/test/built-ins/Temporal/Instant/from
;;; Expected values are copied verbatim from test262's epochNanoseconds.
;;; Specifications:
;;;   Temporal §13.31 (ISO 8601 / RFC 9557 grammar): https://tc39.es/proposal-temporal/
;;;   RFC 3339: https://www.rfc-editor.org/rfc/rfc3339
;;;   RFC 9557: https://www.rfc-editor.org/rfc/rfc9557
;;; Extra vectors: oathtool(1) https://www.nongnu.org/oath-toolkit/oathtool.1.html example
;;; and RFC 6238 https://www.rfc-editor.org/rfc/rfc6238 Appendix B.
;;;
;;; Skipped test262 files (JS-only behavior, not string parsing): argument-instant.js,
;;; argument-object-tostring.js, argument-wrong-type.js, argument-zoneddatetime.js, builtin.js,
;;; length.js, name.js, not-a-constructor.js, prop-desc.js, subclassing-ignored.js,
;;; timezone-custom.js. Every string vector of the other files is ported.
;;; Note: argument-string-limits.js only asserts that its valid strings parse; we pin them to
;;; the Temporal range boundary ±8.64e21 ns (±10^8 days, nsMaxInstant), since each of them
;;; denotes exactly that boundary.
(import :std/test
        (only-in :std/text/parser/ll1 ll1)
        (only-in :std/text/parser/base parse-error?)
        (only-in ./date date->string string->date seconds->date date->seconds)
        ./instant
        ./parse)
(export parse-test)

;; Epoch nanoseconds of the Instant parsed from str, Temporal-strict.
(def (epoch-ns str)
  (instant-epoch-nanoseconds (ll1 ll1-instant str)))

;; Epoch nanoseconds of the Instant parsed from str, assuming offset seconds east of UTC
;; for date-times without a UTC offset.
(def (epoch-ns/offset offset str)
  (instant-epoch-nanoseconds (ll1 (cut ll1-instant <> default-offset: offset) str)))

(def parse-test
  (test-suite "test :std/time/parse"

    (test-case "test262 argument-string.js"
      (check-function epoch-ns
        "1976-11-18T15:23z" => 217178580000000000
        "1976-11-18T15:23:30.1Z" => 217178610100000000
        "1976-11-18T15:23:30.12Z" => 217178610120000000
        "1976-11-18T15:23:30.123Z" => 217178610123000000
        "1976-11-18T15:23:30.1234Z" => 217178610123400000
        "1976-11-18T15:23:30.12345Z" => 217178610123450000
        "1976-11-18T15:23:30.123456Z" => 217178610123456000
        "1976-11-18T15:23:30.1234567Z" => 217178610123456700
        "1976-11-18T15:23:30.12345678Z" => 217178610123456780
        "1976-11-18T15:23:30.123456789Z" => 217178610123456789
        "1976-11-18T15:23:30,12Z" => 217178610120000000
        "1976-11-18T15:23:30.12-02:00" => 217185810120000000
        "-009999-11-18T15:23:30.12Z" => -377677326989880000000
        "19761118T15:23:30.1+00:00" => 217178610100000000
        "1976-11-18T152330.1+00:00" => 217178610100000000
        "1976-11-18T15:23:30.1+0000" => 217178610100000000
        "1976-11-18T152330.1+0000" => 217178610100000000
        "19761118T15:23:30.1+0000" => 217178610100000000
        "19761118T152330.1+00:00" => 217178610100000000
        "+0019761118T15:23:30.1+00:00" => 217178610100000000
        "+001976-11-18T152330.1+00:00" => 217178610100000000
        "+001976-11-18T15:23:30.1+0000" => 217178610100000000
        "+001976-11-18T152330.1+0000" => 217178610100000000
        "+0019761118T15:23:30.1+0000" => 217178610100000000
        "+0019761118T152330.1+00:00" => 217178610100000000
        "+0019761118T152330.1+0000" => 217178610100000000
        "1976-11-18T15:23:30+00" => 217178610000000000
        "1976-11-18T15:23:30.123456789-00:00:00" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.0" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.00" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.0000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.00000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.000000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.0000000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.00000000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.000000000" => 217178610123456789
        "1976-11-18T15:23:30.123456789-00:00:00.1" => 217178610223456789
        "1976-11-18T15:23:30.123456789-00:00:00.01" => 217178610133456789
        "1976-11-18T15:23:30.123456789-00:00:00.001" => 217178610124456789
        "1976-11-18T15:23:30.123456789-00:00:00.0001" => 217178610123556789
        "1976-11-18T15:23:30.123456789-00:00:00.00001" => 217178610123466789
        "1976-11-18T15:23:30.123456789-00:00:00.000001" => 217178610123457789
        "1976-11-18T15:23:30.123456789-00:00:00.0000001" => 217178610123456889
        "1976-11-18T15:23:30.123456789-00:00:00.00000001" => 217178610123456799
        "1976-11-18T15:23:30.123456789-00:00:00.000000001" => 217178610123456790
        "1976-11-18T15:23:30.123456789-00:00:00.100000000" => 217178610223456789
        "1976-11-18T15:23:30.123456789-00:00:00.010000000" => 217178610133456789
        "1976-11-18T15:23:30.123456789-00:00:00.001000000" => 217178610124456789
        "1976-11-18T15:23:30.123456789-00:00:00.000100000" => 217178610123556789
        "1976-11-18T15:23:30.123456789-00:00:00.000010000" => 217178610123466789
        "1976-11-18T15:23:30.123456789-00:00:00.000001000" => 217178610123457789
        "1976-11-18T15:23:30.123456789-00:00:00.000000100" => 217178610123456889
        "1976-11-18T15:23:30.123456789-00:00:00.000000010" => 217178610123456799
        "1976-11-18T15Z" => 217177200000000000
        "1976-11-18T15:23:30.123456789Z[u-ca=discord]" => 217178610123456789
        "1976-11-18T15:23:30.123456789Z[+00]" => 217178610123456789
        "1976-11-18T15:23:30.123456789Z[-00]" => 217178610123456789
        "1976-11-18T15:23:30.123456789Z[-00:00]" => 217178610123456789
        "1976-11-18T15:23:30.123456789Z[+12]" => 217178610123456789
        "1976-11-18T15:23:30.123456789Z[NotATimeZone]" => 217178610123456789))

    (test-case "test262 basic.js"
      (def base 217178580000000000)
      (check-function epoch-ns
        "1976-11-18T15:23Z" => base
        "1976-11-18T15:23:30Z" => (+ base 30000000000)
        "1976-11-18T15:23:30.123Z" => (+ base 30123000000)
        "1976-11-18T15:23:30.123456Z" => (+ base 30123456000)
        "1976-11-18T15:23:30.123456789Z" => (+ base 30123456789)
        "1976-11-18T15:23-01:00" => (+ base 3600000000000)
        "1976-11-18T15:23+01:00" => (- base 3600000000000)))

    (test-case "test262 instant-string.js"
      (check-function epoch-ns
        "1970-01-01T00:00Z" => 0
        "1970-01-01T00:00+01:00" => -3600000000000
        "1970-01-01T00:00Z[Etc/Ignored]" => 0
        "1970-01-01T00:00+01:00[Etc/Ignored]" => -3600000000000
        "1970-01-01T00:00Z[u-ca=hebrew]" => 0
        "1970-01-01T00:00+01:00[u-ca=hebrew]" => -3600000000000
        "1970-01-01T00:00+01:00[Etc/Ignored][u-ca=hebrew]" => -3600000000000
        ;; Bare date-time, with or without an IANA annotation, is not an instant.
        "1970-01-01T00:00" =>! parse-error?
        "1970-01-01T00:00[UTC]" =>! parse-error?))

    (test-case "test262 instant-string-multiple-offsets.js"
      ;; The UTC offset comes from the offset part, not the annotation.
      (check (epoch-ns "1970-01-01T00:02:00.000000000+00:02[+01:30]") => 0))

    (test-case "test262 instant-string-sub-minute-offset.js"
      (check-function epoch-ns
        ;; A sub-minute UTC offset is accepted exactly...
        "1970-01-01T00:19:32.37+00:19:32.37" => 0
        ;; ...but time zone annotations cannot have sub-minute offsets.
        "2021-08-19T17:30-07:00:01[-07:00:01]" =>! parse-error?
        "2021-08-19T17:30-07:00:00[-07:00:00]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.1[-07:00:00.1]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0[-07:00:00.0]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.01[-07:00:00.01]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00[-07:00:00.00]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.001[-07:00:00.001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000[-07:00:00.000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0001[-07:00:00.0001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0000[-07:00:00.0000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00001[-07:00:00.00001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00000[-07:00:00.00000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000001[-07:00:00.000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000000[-07:00:00.000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0000001[-07:00:00.0000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0000000[-07:00:00.0000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00000001[-07:00:00.00000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00000000[-07:00:00.00000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000000001[-07:00:00.000000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000000000[-07:00:00.000000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:01[-070001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00[-070000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.1[-070000.1]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0[-070000.0]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.01[-070000.01]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00[-070000.00]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.001[-070000.001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000[-070000.000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0001[-070000.0001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0000[-070000.0000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00001[-070000.00001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00000[-070000.00000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000001[-070000.000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000000[-070000.000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0000001[-070000.0000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.0000000[-070000.0000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00000001[-070000.00000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.00000000[-070000.00000000]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000000001[-070000.000000001]" =>! parse-error?
        "2021-08-19T17:30-07:00:00.000000000[-070000.000000000]" =>! parse-error?))

    (test-case "test262 argument-string-invalid.js"
      (check-function epoch-ns
        ;; Invalid ISO strings.
        "" =>! parse-error?
        "invalid iso8601" =>! parse-error?
        "2020-01-00T00:00Z" =>! parse-error?
        "2020-01-32T00:00Z" =>! parse-error?
        "2020-02-30T00:00Z" =>! parse-error?
        "2021-02-29T00:00Z" =>! parse-error?
        "2020-00-01T00:00Z" =>! parse-error?
        "2020-13-01T00:00Z" =>! parse-error?
        "2020-01-01TZ" =>! parse-error?
        "2020-01-01T25:00:00Z" =>! parse-error?
        "2020-01-01T01:60:00Z" =>! parse-error?
        "2020-01-01T01:60:61Z" =>! parse-error?
        "2020-01-01T00:00Zjunk" =>! parse-error?
        "2020-01-01T00:00:00Zjunk" =>! parse-error?
        "2020-01-01T00:00:00.000000000Zjunk" =>! parse-error?
        "2020-01-01T00:00:00+00:00junk" =>! parse-error?
        "2020-01-01T00:00:00+00:00[UTC]junk" =>! parse-error?
        "2020-01-01T00:00:00+00:00[UTC][u-ca=iso8601]junk" =>! parse-error?
        "02020-01-01T00:00Z" =>! parse-error?
        "2020-001-01T00:00Z" =>! parse-error?
        "2020-01-001T00:00Z" =>! parse-error?
        "2020-01-01T001Z" =>! parse-error?
        "2020-01-01T01:001Z" =>! parse-error?
        "2020-01-01T01:01:001Z" =>! parse-error?
        "2020-01-01T00:00-24:00" =>! parse-error?
        "2020-01-01T00:00+24:00" =>! parse-error?
        ;; Valid ISO 8601, but forms not supported in Temporal.
        "2020-W01-1T00:00Z" =>! parse-error?
        "2020-001T00:00Z" =>! parse-error?
        "+0002020-01-01T00:00Z" =>! parse-error?
        ;; Valid in other contexts, but insufficient information for an Instant.
        "2020-01" =>! parse-error?
        "+002020-01" =>! parse-error?
        "01-01" =>! parse-error?
        "2020-W01" =>! parse-error?
        "P1Y" =>! parse-error?
        "-P12Y" =>! parse-error?
        "2020-01-01" =>! parse-error?
        "2020-01-01T00" =>! parse-error?
        "2020-01-01T00:00" =>! parse-error?
        "2020-01-01T00:00:00" =>! parse-error?
        "2020-01-01T00:00:00.000000000" =>! parse-error?
        ;; Valid, but outside the supported range.
        "-999999-01-01T00:00Z" =>! parse-error?
        "+999999-01-01T00:00Z" =>! parse-error?
        ;; The hour:minute and minute:second separators (or lack thereof) must match.
        "2025-01-01T00:00:00+00:0000" =>! parse-error?))

    (test-case "test262 argument-string-limits.js"
      (check-function epoch-ns
        "-271821-04-20T00:00Z" => -8640000000000000000000
        "-271821-04-19T23:00-01:00" => -8640000000000000000000
        "-271821-04-19T00:00:00.000000001-23:59:59.999999999" => -8640000000000000000000
        "+275760-09-13T00:00Z" => 8640000000000000000000
        "+275760-09-13T01:00+01:00" => 8640000000000000000000
        "+275760-09-13T23:59:59.999999999+23:59:59.999999999" => 8640000000000000000000
        ;; Outside the representable range of Instant.
        "-271821-04-19T23:59:59.999999999Z" =>! parse-error?
        "-271821-04-19T23:00-00:59:59.999999999" =>! parse-error?
        "-271821-04-19T00:00:00-23:59:59.999999999" =>! parse-error?
        "+275760-09-13T00:00:00.000000001Z" =>! parse-error?
        "+275760-09-13T01:00+00:59:59.999999999" =>! parse-error?
        "+275760-09-14T00:00+23:59:59.999999999" =>! parse-error?))

    (test-case "test262 argument-string-minus-sign.js"
      ;; U+2212 MINUS SIGN is not accepted in place of "-".
      (check-function epoch-ns
        "1976-11-18T15:23:30.12\x2212;02:00" =>! parse-error?
        "\x2212;009999-11-18T15:23:30.12" =>! parse-error?))

    (test-case "test262 argument-string-time-separators.js"
      (check-function epoch-ns
        "1970-01-01T00:00Z" => 0
        "1970-01-01t00:00Z" => 0
        "1970-01-01 00:00Z" => 0))

    (test-case "test262 argument-string-too-many-decimals.js"
      ;; No more than 9 decimal places.
      (check-function epoch-ns
        "1970-01-01T00:00:00.1234567891Z" =>! parse-error?
        "1970-01-01T00:00:00.1234567890Z" =>! parse-error?
        "1970-01-01T00+00:00:00.1234567891" =>! parse-error?
        "1970-01-01T00+00:00:00.1234567890" =>! parse-error?))

    (test-case "test262 argument-string-date-with-utc-offset.js"
      (check-function epoch-ns
        ;; A UTC offset with a time is valid.
        "1970-01-01T00Z" => 0
        "1970-01-01T00Z[UTC]" => 0
        "1970-01-01T00Z[!UTC]" => 0
        "1970-01-01T00Z[Europe/Vienna]" => 0
        "1970-01-01T00+00" => 0
        "1970-01-01T00+00:00" => 0
        "1970-01-01T00+00:00:00,0" => 0
        "1970-01-01T00+00:00:00.000000000" => 0
        "1970-01-01T00+0000" => 0
        "1970-01-01T00+000000,0" => 0
        "1970-01-01T00+000000.000000000" => 0
        "1970-01-01T00+00:00[UTC]" => 0
        "1970-01-01T00+00:00[!UTC]" => 0
        "1969-12-31T16-08[America/Vancouver]" => 0
        "1969-12-31T16-08:00[America/Vancouver]" => 0
        "1969-12-31T16-08:00:00,0[America/Vancouver]" => 0
        "1969-12-31T16-08:00:00.000000000[America/Vancouver]" => 0
        "1969-12-31T16-0800[America/Vancouver]" => 0
        "1969-12-31T16-080000,0[America/Vancouver]" => 0
        "1969-12-31T16-080000.000000000[America/Vancouver]" => 0
        ;; A UTC offset without a time is not valid for an Instant.
        "2022-09-15Z" =>! parse-error?
        "2022-09-15Z[UTC]" =>! parse-error?
        "2022-09-15Z[Europe/Vienna]" =>! parse-error?
        "2022-09-15+00:00" =>! parse-error?
        "2022-09-15+00:00[UTC]" =>! parse-error?
        "2022-09-15-02:30" =>! parse-error?
        "2022-09-15-02:30[America/St_Johns]" =>! parse-error?))

    (test-case "dot components in time zone annotations"
      (check-function epoch-ns
        "1970-01-01T00:00Z[.]" => 0
        "1970-01-01T00:00Z[America/..]" => 0
        "1970-01-01T01:00+01:00[./Region]" => 0
        "1970-01-01T00:00Z[America//Region]" =>! parse-error?))

    (test-case "test262 argument-string-time-zone-annotation.js"
      ;; The time zone annotation is ignored.
      (check-function epoch-ns
        "1970-01-01T00:00Z[Asia/Kolkata]" => 0
        "1970-01-01T00:00Z[!Europe/Vienna]" => 0
        "1970-01-01T00:00Z[+00:00]" => 0
        "1970-01-01T00:00Z[!-02:30]" => 0
        "1970-01-01T00:00+00:00[UTC]" => 0
        "1970-01-01T00:00+00:00[!Africa/Abidjan]" => 0
        "1970-01-01T00:00+00:00[-08:00]" => 0
        "1970-01-01T00:00+00:00[!+01:00]" => 0))

    (test-case "test262 argument-string-calendar-annotation.js"
      ;; The calendar annotation is ignored, even unknown or critical.
      (check-function epoch-ns
        "1970-01-01T00:00Z[u-ca=iso8601]" => 0
        "1970-01-01T00:00Z[UTC][u-ca=gregory]" => 0
        "1970-01-01T00:00Z[!u-ca=hebrew]" => 0
        "1970-01-01T00:00Z[UTC][!u-ca=chinese]" => 0
        "1970-01-01T00:00Z[u-ca=discord]" => 0
        "1970-01-01T00:00Z[!u-ca=discord]" => 0
        "1970-01-01T00:00Z[u-ca=iso8601][u-ca=discord]" => 0))

    (test-case "test262 argument-string-calendar-annotation-invalid-key.js"
      ;; Annotation keys must be lowercase.
      (check-function epoch-ns
        "1970-01-01T00:00Z[U-CA=iso8601]" =>! parse-error?
        "1970-01-01T00:00Z[u-CA=iso8601]" =>! parse-error?
        "1970-01-01T00:00Z[FOO=bar]" =>! parse-error?))

    (test-case "test262 argument-string-multiple-calendar.js"
      ;; More than one calendar annotation is rejected if any is critical.
      (check-function epoch-ns
        "1970-01-01T00:00Z[u-ca=iso8601][!u-ca=iso8601]" =>! parse-error?
        "1970-01-01T00:00Z[!u-ca=iso8601][u-ca=iso8601]" =>! parse-error?
        "1970-01-01T00:00Z[UTC][u-ca=iso8601][!u-ca=iso8601]" =>! parse-error?
        "1970-01-01T00:00Z[u-ca=iso8601][foo=bar][!u-ca=iso8601]" =>! parse-error?))

    (test-case "test262 argument-string-multiple-time-zone.js"
      ;; More than one time zone annotation is rejected.
      (check-function epoch-ns
        "1970-01-01T00:00Z[UTC][UTC]" =>! parse-error?
        "1970-01-01T00:00Z[!UTC][UTC]" =>! parse-error?
        "1970-01-01T00:00Z[UTC][!UTC]" =>! parse-error?
        "1970-01-01T00:00Z[UTC][u-ca=iso8601][UTC]" =>! parse-error?
        "1970-01-01T00:00Z[UTC][foo=bar][UTC]" =>! parse-error?))

    (test-case "test262 argument-string-unknown-annotation.js"
      ;; Unknown non-critical annotations are ignored.
      (check-function epoch-ns
        "1970-01-01T00:00Z[foo=bar]" => 0
        "1970-01-01T00:00Z[UTC][foo=bar]" => 0
        "1970-01-01T00:00Z[u-ca=iso8601][foo=bar]" => 0
        "1970-01-01T00:00Z[UTC][foo=bar][u-ca=iso8601]" => 0
        "1970-01-01T00:00Z[foo=bar][_foo-bar0=Ignore-This-999999999999]" => 0))

    (test-case "test262 argument-string-critical-unknown-annotation.js"
      ;; Unknown critical annotations are rejected.
      (check-function epoch-ns
        "1970-01-01T00:00Z[!foo=bar]" =>! parse-error?
        "1970-01-01T00:00Z[UTC][!foo=bar]" =>! parse-error?
        "1970-01-01T00:00Z[u-ca=iso8601][!foo=bar]" =>! parse-error?
        "1970-01-01T00:00Z[UTC][!foo=bar][u-ca=iso8601]" =>! parse-error?
        "1970-01-01T00:00Z[foo=bar][!_foo-bar0=Dont-Ignore-This-99999999999]" =>! parse-error?))

    (test-case "test262 leap-second.js"
      ;; A leap second is valid, and is treated as second 59.
      (check (epoch-ns "2016-12-31T23:59:60Z") => 1483228799000000000))

    (test-case "test262 year-zero.js"
      ;; Minus zero is rejected as an extended year.
      (check-function epoch-ns
        "-000000-03-30T00:45Z" =>! parse-error?
        "-000000-03-30T01:45+01:00" =>! parse-error?
        "-000000-03-30T01:45:00+00:00[UTC]" =>! parse-error?))

    (test-case "test262 no-fractional-minutes-hours.js"
      ;; Only seconds may have a fraction.
      (check-function epoch-ns
        "2025-04-03T05:07.123[UTC]" =>! parse-error?
        "2025-04-03T12.5[UTC]" =>! parse-error?))

    (test-case "OTP vectors"
      (check-function epoch-ns
        ;; oathtool(1) example.
        "2008-04-23T17:42:17Z" => 1208972537000000000
        ;; RFC 6238 Appendix B: T = 1234567890.
        "2009-02-13T23:31:30Z" => 1234567890000000000))

    (test-case "leftovers"
      ;; ll1 rejects anything left unparsed, and nothing may precede the date.
      (check-function epoch-ns
        "1970-01-01T00:00Z " =>! parse-error?
        "1970-01-01T00:00Z\n" =>! parse-error?
        " 1970-01-01T00:00Z" =>! parse-error?
        "1970-01-01T00:00ZZ" =>! parse-error?
        "1970-01-01T00:00+00:00Z" =>! parse-error?
        "1970-01-01T00:00Z[UTC" =>! parse-error?
        "1970-01-01T00:00Z[]" =>! parse-error?
        "1970-01-01T00:00Z[UTC] " =>! parse-error?
        "1970-01-01T00:00Z[u-ca=iso8601]x" =>! parse-error?))

    (test-case "default-offset: zone-less date-times"
      (check-function epoch-ns/offset
        0 "2020-01-01T00:00" => 1577836800000000000
        3600 "2020-01-01T00:00" => 1577833200000000000
        -18000 "2020-01-01T00:00" => 1577854800000000000
        0 "1970-01-01T00:00" => 0
        3600 "1970-01-01T00:00" => -3600000000000
        -18000 "1970-01-01T00:00" => 18000000000000
        0 "1970-01-01T00" => 0
        0 "1970-01-01T00:00:00" => 0
        0 "1970-01-01T00:00:00.5" => 500000000
        0 "1970-01-01 00:00:00,5" => 500000000
        0 "19700101T000000" => 0
        3600 "1976-11-18T15:23:30.123456789" => 217175010123456789
        0 "2016-12-31T23:59:60" => 1483228799000000000
        0 "1970-01-01T00:00[u-ca=iso8601]" => 0
        ;; Ambiguity: a date without time under default-offset: is midnight at that offset.
        0 "2020-01-01" => 1577836800000000000
        3600 "2020-01-01" => 1577833200000000000
        -18000 "2020-01-01" => 1577854800000000000
        0 "20200101" => 1577836800000000000))

    (test-case "default-offset: explicit offsets win"
      ;; Strings with a UTC offset ignore default-offset:.
      (check-function epoch-ns/offset
        3600 "1970-01-01T00:00Z" => 0
        -18000 "1970-01-01T00:00Z" => 0
        -18000 "1970-01-01T00:00+01:00" => -3600000000000
        3600 "1970-01-01T00:00-00:00" => 0
        0 "1976-11-18T15:23-01:00" => 217182180000000000
        3600 "1976-11-18T15:23:30.12-02:00" => 217185810120000000
        -18000 "1970-01-01T00:00Z[Europe/Vienna]" => 0))

    (test-case "default-offset: still invalid"
      (check-function epoch-ns/offset
        0 "" =>! parse-error?
        0 "2020-01" =>! parse-error?
        0 "2020-01-01T" =>! parse-error?
        0 "2020-02-30T00:00" =>! parse-error?
        0 "2020-01-01T25:00" =>! parse-error?
        0 "2020-01-01T00:00junk" =>! parse-error?
        0 "2020-01-01 " =>! parse-error?
        0 "2025-04-03T12.5" =>! parse-error?
        0 "1970-01-01T00:00:00.1234567890" =>! parse-error?
        ;; A date with an offset but no time stays invalid.
        0 "2022-09-15Z" =>! parse-error?
        3600 "2022-09-15+00:00" =>! parse-error?
        ;; The range limit applies after the default offset.
        0 "+275760-09-13T00:00:00.000000001" =>! parse-error?
        3600 "-271821-04-20T00:00" =>! parse-error?
        ;; A time zone annotation without a UTC offset is rejected even with default-offset:.
        ;; A zone annotation requires an explicit offset even with default-offset:.
        0 "2020-01-01T00:00[Europe/Paris]" =>! parse-error?
        0 "2020-01-01T00:00[UTC]" =>! parse-error?
        3600 "2020-01-01T00:00[!Europe/Vienna]" =>! parse-error?
        0 "2020-01-01T00:00[+01:00]" =>! parse-error?
        -18000 "2020-01-01T00:00[America/New_York][u-ca=iso8601]" =>! parse-error?
        0 "2020-01-01[Europe/Paris]" =>! parse-error?))

    ;; Comparison with the legacy libc-based :std/time/date (strftime / strptime + timegm).
    ;; Each codec encodes POSIX seconds with strftime in one format; each format is decoded
    ;; both by legacy strptime and by ll1-instant, which must agree on these vectors.
    ;; Only POSIX-specified conversions (%Y %m %d %H %M %S %z %F %T) and agreeing cases are
    ;; used: libc-specific leniency (leap-second rollover, date normalization) is not tested.
    (test-case "comparative: %Y-%m-%dT%H:%M:%SZ"
      (def fmt "%Y-%m-%dT%H:%M:%SZ")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "1970-01-01T00:00:00Z"
            -1 <=> "1969-12-31T23:59:59Z"
            59 <=> "1970-01-01T00:00:59Z"
            86400 <=> "1970-01-02T00:00:00Z"
            217178610 <=> "1976-11-18T15:23:30Z"
            1111111109 <=> "2005-03-18T01:58:29Z"
            1208972537 <=> "2008-04-23T17:42:17Z"
            1234567890 <=> "2009-02-13T23:31:30Z"
            1483228799 <=> "2016-12-31T23:59:59Z"
            1700000000 <=> "2023-11-14T22:13:20Z"
            20000000000 <=> "2603-10-11T11:33:20Z"))
        [legacy-decode temporal-decode]))

    (test-case "comparative: %Y-%m-%d %H:%M:%SZ"
      (def fmt "%Y-%m-%d %H:%M:%SZ")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "1970-01-01 00:00:00Z"
            -1 <=> "1969-12-31 23:59:59Z"
            217178610 <=> "1976-11-18 15:23:30Z"
            1208972537 <=> "2008-04-23 17:42:17Z"
            1234567890 <=> "2009-02-13 23:31:30Z"
            20000000000 <=> "2603-10-11 11:33:20Z"))
        [legacy-decode temporal-decode]))

    (test-case "comparative: %Y%m%dT%H%M%SZ (basic format)"
      (def fmt "%Y%m%dT%H%M%SZ")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "19700101T000000Z"
            -1 <=> "19691231T235959Z"
            217178610 <=> "19761118T152330Z"
            1208972537 <=> "20080423T174217Z"
            1234567890 <=> "20090213T233130Z"
            20000000000 <=> "26031011T113320Z"))
        [legacy-decode temporal-decode]))

    (test-case "comparative: %FT%T+00:00"
      (def fmt "%FT%T+00:00")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "1970-01-01T00:00:00+00:00"
            -1 <=> "1969-12-31T23:59:59+00:00"
            217178610 <=> "1976-11-18T15:23:30+00:00"
            1208972537 <=> "2008-04-23T17:42:17+00:00"
            1234567890 <=> "2009-02-13T23:31:30+00:00"
            20000000000 <=> "2603-10-11T11:33:20+00:00"))
        [legacy-decode temporal-decode]))

    (test-case "comparative: %Y-%m-%dT%H:%M:%S%z"
      (def fmt "%Y-%m-%dT%H:%M:%S%z")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "1970-01-01T00:00:00+0000"
            -1 <=> "1969-12-31T23:59:59+0000"
            217178610 <=> "1976-11-18T15:23:30+0000"
            1208972537 <=> "2008-04-23T17:42:17+0000"
            1234567890 <=> "2009-02-13T23:31:30+0000"
            20000000000 <=> "2603-10-11T11:33:20+0000"))
        [legacy-decode temporal-decode]))

    (test-case "comparative: %Y-%m-%dT%H:%MZ (minute precision)"
      (def fmt "%Y-%m-%dT%H:%MZ")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "1970-01-01T00:00Z"
            -60 <=> "1969-12-31T23:59Z"
            217178580 <=> "1976-11-18T15:23Z"
            1234567860 <=> "2009-02-13T23:31Z"
            ;; Encoding truncates to the minute.
            59 => "1970-01-01T00:00Z"
            -1 => "1969-12-31T23:59Z"
            1234567890 => "2009-02-13T23:31Z"))
        [legacy-decode temporal-decode]))

    (test-case "comparative: %Y-%m-%dT%H:%M:%S (zone-less, default-offset: 0)"
      ;; Legacy strptime + timegm assumes UTC; Temporal needs default-offset: 0 for that.
      (def fmt "%Y-%m-%dT%H:%M:%S")
      (def (encode s) (date->string (seconds->date s) fmt))
      (def (legacy-decode str) (date->seconds (string->date str fmt)))
      (def (temporal-decode str) (floor-quotient (epoch-ns/offset 0 str) 1000000000))
      (for-each
        (lambda (decode)
          (check-codec encode decode
            0 <=> "1970-01-01T00:00:00"
            -1 <=> "1969-12-31T23:59:59"
            217178610 <=> "1976-11-18T15:23:30"
            1208972537 <=> "2008-04-23T17:42:17"
            1234567890 <=> "2009-02-13T23:31:30"
            20000000000 <=> "2603-10-11T11:33:20"))
        [legacy-decode temporal-decode]))))
