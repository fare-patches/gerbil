;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/io
        ./ast
        ./parse
        ./html)
(export (import: ./ast)
        string->djot
        read-djot
        djot->sxml
        djot->html
        write-djot-html)

(def (read-djot (input : :t)
                source-locations: (locations? : :boolean := #f))
  => djot-document
  (with-buffered-reader (reader input)
    (string->djot (utf8->string (read-all-from-reader (Reader reader)))
                  source-locations: locations?)))

;;; The SXML printer uses Gambit ports; buffer its output before adapting to std/io.
(def (write-djot-html (output   : :t)
                      (document : djot-document)) => :t
  (with-buffered-writer (writer output)
    (writer.write-string-utf8 (djot->html document))))
