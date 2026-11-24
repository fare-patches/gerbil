;;; -*- Gerbil -*-
;;; © vyzo
;;; tests for std/time/date
(import :std/test
        :std/error
        ./date)
(export date-test)

(def date-test
  (test-suite "test :std/time/date"

    (test-case "test current-date roundtrip"
      (let (d1 (current-date))
        (def str (date->string d1))
        (def d2 (string->date str))
        (check (Date-sec d1) => (Date-sec d2))
        (check (Date-min d1) => (Date-min d2))
        (check (Date-hour d1) => (Date-hour d2))
        (check (Date-mday d1) => (Date-mday d2))
        (check (Date-mon d1) => (Date-mon d2))
        (check (Date-year d1) => (Date-year d2))))

    (test-case "test seconds->date roundtrip"
      (def timestamp 1700000000) ;; Tue, 14 Nov 2023 22:13:20 UTC
      (def d (seconds->date timestamp))
      (def str (date->string d))
      (check str => "2023-11-14 22:13:20")
      (check (date->seconds d) => timestamp))

    (test-case "test date->string with known timestamp and formats"
      (def timestamp 1680000000) ;; Tue, 28 Mar 2023 10:40:00 UTC
      (def d (seconds->date timestamp))
      (check (date->string d "%Y-%m-%d") => "2023-03-28")
      (check (date->string d "%H:%M:%S") => "10:40:00")
      (check (date->string d "%Y-%m-%d %H:%M:%S") => "2023-03-28 10:40:00")
      (check (date->string d "%A, %B %d") => "Tuesday, March 28"))

    (test-case "string->date checks the entire UTF-8 input"
      (check-function string->date
        "2023-11-14" "%Y-%m-%d %H:%M:%S" =>! ContractViolation?
        (string-append "2023-11-14" (string #\nul) "extra") "%Y-%m-%d" =>! ContractViolation?
        "2023-11-14é" "%Y-%m-%d" =>! ContractViolation?))

    (test-case "test string->date parse failures"
      (check-exception (string->date "not a date") ContractViolation?)
      (check-exception
       (string->date "2023-11-14 trailing" "%Y-%m-%d")
       ContractViolation?))))
