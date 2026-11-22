;;; -*- Gerbil -*-
;;; log record formatting tests
(import :std/test
        :std/io
        :std/list/walist
        :std/time/precise
        ./interface
        ./level
        ./format)
(export format-test)

(def (format-record record)
  (let (writer (open-buffered-writer #f))
    (format-log-line writer record)
    (get-memory-output-string-utf8 writer)))

(def format-test
  (test-suite "log record formatting"
    ;; log data is for display, not read back: a procedure without a global name,
    ;; e.g. an exception irritant, must not make the logger raise
    (test-case "format-log-line on data with an anonymous procedure"
      (let (line (format-record
                  (Record (current-time-coarse) INFO "/std/log/format-test" "msg"
                          (walist [(cons irritant: (lambda (x) x)) (cons note: "hi")]))))
        (check (string-contains line "#{procedure") ? number?)
        ;; data strings stay quoted; the message is displayed
        (check (string-contains line "\"hi\"") ? number?)
        (check (string-contains line "\"msg\"") => #f)))))
