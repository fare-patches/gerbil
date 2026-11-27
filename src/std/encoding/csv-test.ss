;;; -*- Gerbil -*-
;;; (C) fare at tunes.org
;;; :std/encoding/csv unit test

(export csv-test)

(import
  :std/interface
  :std/io
  :std/error
  :std/misc/ports
  :std/string/misc
  :std/test
  :std/encoding/csv)

(def (normalize-crlf input)
  (string-concatenate
   (map (lambda (line) (string-append (string-trim-eol line) "\n"))
        (call-with-input-string input read-all-as-lines))))

(def (csv->lines csv)
  (read-csv csv))

(def (lines->csv lines)
  (normalize-crlf (write-csv 'string lines)))

(defrules test-read ()
  ((_ csv expected)
   (check-equal? (csv->lines csv) expected)))

(defrules test-write ()
  ((_ lists expected)
   (check-equal? (lines->csv lists) expected)))

(defrules test-both ()
  ((_ csv lists)
   (begin (test-read csv lists) (test-write lists csv))))

(defrules test-read-write ()
  ((_ csv lists csv-again)
   (begin (test-read csv lists) (test-write lists csv-again))))

(defrules test-both-lf ()
  ((_ csv lists)
   (begin (test-read csv lists) (test-write lists (string-append csv +lf+)))))

(defstruct counting-writer (writes))

(defmethod {write counting-writer}
  (lambda (self bytes start end)
    (set! (counting-writer-writes self) (1+ (counting-writer-writes self)))
    (fx- end start))
  interface: Writer)

(defmethod {close counting-writer} void interface: Closer)
(@implement Writer counting-writer)

(def csv-test
  (test-suite "test :std/encoding/csv"
    (test-case "test-empty-fields"
      (test-both
       "1,2,3
,2,3
1,,3
1,2,
"
       '(("1" "2" "3")
         ("" "2" "3")
         ("1" "" "3")
         ("1" "2" ""))))
    (test-case "test-happy-ending"
      (test-both-lf
       "one,two,three,"
       '(("one" "two" "three" "")))
      (test-read-write
       "one,two,three   "
       '(("one" "two" "three"))
       "one,two,three
")
      (test-read-write
       "   "
       '(())
       +lf+)
      (test-both
       ""
       '()))
    (test-case "writer dialects"
      (def qq (struct-copy creativyst-csv-options))
      (def slash (struct-copy creativyst-csv-options))
      (csv-options-unquoted-quotequote?-set! qq #t)
      (csv-options-separator-set! slash #\/)
      (def (emit row opts) (write-csv 'string (list row) opts))
      (def (round-trip row opts) (read-csv (emit row opts) opts))
      (check-equal? (write-csv 'string '(() ("") (#f) ("" ""))) "\r\n\"\"\r\n\"\"\r\n,\r\n")
      (check-equal? (round-trip '(1/2 "x/y") slash) '(("1/2" "x/y")))
      (check-equal? (emit '("\"") qq) "\"\"\r\n")
      (check-equal? (round-trip '("\"\"x" "") qq) '(("\"\"x" "")))
      (check-exception (emit '("") qq) IOError?)
      (check-exception (emit '("\",x") qq) IOError?)
      (check-exception (emit '("\" ") qq) IOError?)
      (csv-options-loose-quote?-set! qq #t)
      (check-equal? (emit '("\"\"") qq) "\"\"\"\"\r\n")
      (check-equal? (emit '("\"\"a\", ") qq) "\"\"\"\"\"a\"\", \"\r\n")
      (check-equal? (round-trip '("\",x" "\" ") qq) '(("\",x" "\" ")))
      (check-exception (emit '("Faré") strict-rfc4180-csv-options) IOError?)
      (check-exception (emit '("\t") strict-rfc4180-csv-options) IOError?)
      (check-exception (read-csv "a\nb" strict-rfc4180-csv-options) IOError?)
      (check-equal? (round-trip '("a\nb") strict-rfc4180-csv-options) '(("a\nb"))))
    (test-case "bulk writer buffers across records"
      (def sink (make-counting-writer 0))
      (write-csv sink (make-list 100 '("a")))
      (check-equal? (counting-writer-writes sink) 1))
    (test-case "record endings cannot delimit fields"
      (def (check-collision preset set-delimiter! delimiter row)
        (def opts (struct-copy preset))
        (def sink (open-output-u8vector))
        (def (invalid? e) (string-prefix? "Assertion failed" (error-message e)))
        (set-delimiter! opts delimiter)
        (check-exception (write-csv-line sink row opts) invalid?)
        (check-exception (write-csv sink (list row) opts) invalid?)
        (check-equal? (get-output-u8vector sink) #u8())
        (check-exception (read-csv "" opts) invalid?)
        (check-exception (read-csv-line "" opts) invalid?))
      (for-each
       (lambda (opts)
         (check-collision opts csv-options-separator-set! #\newline '("" "b"))
         (check-collision opts csv-options-quote-set! #\newline '("a,b")))
       (list creativyst-csv-options strict-rfc4180-csv-options))
      (check-collision rfc4180-csv-options csv-options-separator-set! #\return '("" "b"))
      (check-collision rfc4180-csv-options csv-options-quote-set! #\return '("a,b")))
    (test-case "option validation"
      (def opts (struct-copy creativyst-csv-options))
      (def (invalid? e) (string-prefix? "Assertion failed" (error-message e)))
      (def (check-invalid)
        (check-exception (read-csv-line "" opts) invalid?)
        (check-exception (read-csv "" opts) invalid?)
        (check-exception (write-csv-line 'string [] opts) invalid?)
        (check-exception (write-csv 'string [] opts) invalid?))
      (csv-options-allow-binary?-set! opts 'invalid)
      (check-invalid)
      (csv-options-allow-binary?-set! opts #t)
      (csv-options-quote-set! opts #\,)
      (check-invalid)
      (csv-options-quote-set! opts #\")
      (csv-options-accept-cr?-set! opts #f)
      (csv-options-accept-lf?-set! opts #f)
      (csv-options-accept-crlf?-set! opts #f)
      (check-invalid))
    (test-case "space or tab as quote"
      (def opts (struct-copy creativyst-csv-options))
      (def rows '(("") ("a,b" "c")))
      (for-each (lambda (q)
                  (csv-options-quote-set! opts q)
                  (check-equal? (read-csv (write-csv 'string rows opts) opts) rows))
                '(#\space #\tab)))
    (test-case "parameters"
      (def setters
        (hash (separator csv-options-separator-set!)
              (quote csv-options-quote-set!)
              (unquoted-quotequote? csv-options-unquoted-quotequote?-set!)
              (loose-quote? csv-options-loose-quote?-set!)
              (allow-binary? csv-options-allow-binary?-set!)
              (eol csv-options-eol-set!)
              (accept-lf? csv-options-accept-lf?-set!)
              (accept-cr? csv-options-accept-cr?-set!)
              (accept-crlf? csv-options-accept-crlf?-set!)
              (skip-whitespace? csv-options-skip-whitespace?-set!)))
      (def (csv<-str s) (read-csv s))
      (def (str<-csv c) (write-csv 'string c))
      (def (lines<-str s) (map string-trim-eol (call-with-input-string s read-all-as-lines)))
      (def str "\"a,b c\"\n;\"e,f;g\",h\ri',j;'k,l\nm,n;o,p")
      (def (param-test str str2 csv . options)
        (write [TESTING: str str2 csv . options]) (newline)
        (def opts (struct-copy creativyst-csv-options))
        (for-each (match <> ([slot val] ((hash-get setters slot) opts val))) options)
        (parameterize ((current-csv-options opts))
          (let/cc return
            (cond
             ((string? csv)
              (check-exception (csv<-str str) (lambda (e) (equal? (error-message e) csv))) (return))
             ((list? csv)
              (check-equal? (csv<-str str) csv))
             ((not csv)
              (set! csv (csv<-str str))))
            (check-equal? (str<-csv csv) (or str2 str))
            (when str2 (check-equal? (csv<-str str2) csv)))))
      (def (param-tests str . l) (for-each (cut apply param-test str <>) l))
      (def (T l) (for-each (cut apply param-tests <>) l))
      (T '(("a,b;c\r\n"
            (#f (("a" "b;c")))
            (#f (("a,b" "c")) (separator #\;))
            ("a,b;c\n" (("a" "b;c")) (eol "\n")))
           ("\"a,b\"\r'c,d'\r\"e f\""
            ("\"a,b\"\r\n'c,d'\r\ne f\r\n" (("a,b") ("'c" "d'") ("e f")))
            ("\"a,b\"\r\n'c,d'\r\n\"e f\"\r\n" (("\"a" "b\"") ("c,d") ("\"e f\"")) (quote #\')))
           ("foo''bar"
            (#f "unexpected quote in middle of field" (quote #\'))
            ("'foo''bar'\r\n" (("foo'bar")) (quote #\') (unquoted-quotequote? #t))
            ("foobar\r\n" (("foobar")) (quote #\') (loose-quote? #t))
            ("'foo''bar'\r\n" (("foo'bar")) (quote #\') (unquoted-quotequote? #t))
            ("'foo''bar'\r\n" (("foo'bar")) (quote #\') (loose-quote? #t) (unquoted-quotequote? #t)))
           ("f'o'o"
            (#f "unexpected quote in middle of field" (quote #\'))
            (#f "unexpected quote in middle of field" (quote #\') (unquoted-quotequote? #t))
            ("foo\r\n" (("foo")) (quote #\') (loose-quote? #t)))
           ("'a\n'"
            ("'a\r\n'\r\n" (("'a") ("'")))
            ("'a\n'\r\n" (("a\n")) (quote #\')))
           ("Faré"
            ("\"Faré\"\r\n" (("Faré")))
            ("Faré\r\n" "binary data not allowed" (allow-binary? #f)))
           ("foo\nbar\r\nbaz\r"
            ("foo\r\nbar\r\nbaz\r\n" (("foo") ("bar") ("baz")))
            ("foo\nbar\nbaz\n" (("foo") ("bar") ("baz")) (eol "\n"))
            ("foo\n\"bar\r\"\n\"baz\r\"\n" (("foo") ("bar\r") ("baz\r")) (eol "\n") (accept-cr? #f) (accept-crlf? #f))
            (#f "Carriage-Return without Linefeed!" (eol "\n") (accept-cr? #f))
            ("\"foo\nbar\"\r\"\nbaz\"\r" (("foo\nbar") ("\nbaz")) (eol "\r") (accept-lf? #f) (accept-crlf? #f)))
           ("  foo  , "
            ("foo,\r\n" (("foo" "")))
            ("\"  foo  \",\" \"\r\n" (("  foo  " " ")) (skip-whitespace? #f))
           ))))))
