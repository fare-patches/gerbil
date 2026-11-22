;;; -*- Gerbil -*-
;;; © vyzo
;;; log record formatting
(import :std/time/precise
        :std/io
        :std/format
        ./interface
        ./level)
(export #t)

;; the data is written for debugging (%q), not to be read back: strings stay
;; quoted, and objects that cannot be read back, e.g. closures, do not raise.
(def (format-log-line (writer : BufferedWriter) (record : Record))
  (fprintf writer "%d.%d %a %a %a %q\n"
          (CoarseTime-seconds record.ts)
          (CoarseTime-useconds record.ts)
          (log-level->string record.level)
          record.source
          record.msg
          record.data.alist))
