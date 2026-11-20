;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/io
        (only-in ../html/writer html->u8vector)
        ./ast
        ./parse
        ./html)
(export (import: ./ast)
        string->djot
        read-djot
        djot->html-fragment
        djot->html
        write-djot-html)

(def (read-djot (input : :t)
                source-locations: (locations? : :boolean := #f))
  => djot-document
  (with-buffered-reader (reader input)
    (string->djot (utf8->string (read-all-from-reader (Reader reader)))
                  source-locations: locations?)))

;;; The document is written to memory first, so a rendering error writes
;;; nothing.
(def (write-djot-html (output   : :t)
                      (document : djot-document)) => :t
  (let (bytes (html->u8vector (djot->html-fragment document)))
    (with-buffered-writer (writer output)
      (writer.write bytes))))
