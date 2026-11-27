;;; -*- Gerbil -*-
;;;; CSV support, ported from Common Lisp's fare-csv
;;; © fare at tunes.org
;;
;; CSV is intrinsically an underspecified lossy format,
;; and even popular PC applications lose heavily
;; (i.e. no quoting convention at all, not even a pascal-like one)
;; when text fields contain the quote character. Ouch.
;;
;; This spec seems to explain popular usage, is refered by docs below.
;; http://www.creativyst.com/Doc/Articles/CSV/CSV01.htm
;;
;; This one says about the same:
;; http://edoceo.com/utilitas/csv-file-format
;;
;; There's now an RFC that tries to standardize CSV:
;; http://www.rfc-editor.org/rfc/rfc4180.txt
;;
;; Here's what Perl hackers think CSV is:
;; http://search.cpan.org/~hmbrand/Text-CSV_XS-0.59/CSV_XS.pm
;;
;;        (read-csv source)            ; all lines from any source
;;        (read-csv-line source)       ; one line from any source
;;        (write-csv writer lines)     ; all lines to any sink
;;        (write-csv-line writer fields) ; one line to any sink
;;
;; source/sink accepts anything with-buffered-reader/writer accepts:
;;   BufferedReader/Writer, port, u8vector, string (as content), #f (memory), etc.

(export
  current-csv-options csv-options make-csv-options
  csv-options-separator csv-options-separator-set!
  csv-options-quote csv-options-quote-set!
  csv-options-unquoted-quotequote? csv-options-unquoted-quotequote?-set!
  csv-options-loose-quote? csv-options-loose-quote?-set!
  csv-options-allow-binary? csv-options-allow-binary?-set!
  csv-options-eol csv-options-eol-set!
  csv-options-accept-lf? csv-options-accept-lf?-set!
  csv-options-accept-cr? csv-options-accept-cr?-set!
  csv-options-accept-crlf? csv-options-accept-crlf?-set!
  csv-options-skip-whitespace? csv-options-skip-whitespace?-set!
  creativyst-csv-options rfc4180-csv-options strict-rfc4180-csv-options
  call-with-creativyst-csv-syntax call-with-rfc4180-csv-syntax call-with-strict-rfc4180-csv-syntax
  with-creativyst-csv-syntax with-rfc4180-csv-syntax with-strict-rfc4180-csv-syntax
  read-csv-line read-csv write-csv-line write-csv
  )

(import
  :std/error
  :std/assert
  :std/io
  :std/list/list
  :std/list/list-builder
  :std/string/misc)

;;; constants
(def +line-endings+
  [+cr+ +lf+ +crlf+])

(def +strict-line-endings+
  [+crlf+ +lf+])

; -----------------------------------------------------------------------------
;;; Parameters
(defstruct csv-options
  (separator ;; char ;; Separator between CSV fields, usually #\, as in the name; sometimes #\tab.
   quote ;; char ;; delimiter of string data; pascal-like quoted as double itself in a string.
   unquoted-quotequote? ;; bool ;; does a pair of quotes represent a quote outside of quotes?
                                ;; M$, RFC says no, csv.3tcl says yes
   loose-quote? ;; bool ;; can quotes appear anywhere in a field?
   allow-binary? ;; bool ;; do we accept non-ascii data?
   eol ;; string ;; what eol value do we output?
   accept-lf? ;; bool ;; is lf valid line-ending on input?
   accept-cr? ;; bool ;; is cr valid line-ending on input?
   accept-crlf? ;; bool ;; is crlf valid line-ending on input?
   skip-whitespace?) ;; bool ;; shall we skip unquoted whitespace around separators?
  transparent: #t)

(def rfc4180-csv-options
  (make-csv-options #\, #\" #f #f #t +lf+ #t #f #t #f))
(def strict-rfc4180-csv-options
  (make-csv-options #\, #\" #f #f #f +crlf+ #f #f #t #f))
(def creativyst-csv-options
  (make-csv-options #\, #\" #f #f #t +crlf+ #t #t #t #t))

(def current-csv-options (make-parameter creativyst-csv-options))

(def (call-with-rfc4180-csv-syntax thunk)
  (parameterize ((current-csv-options rfc4180-csv-options)) (thunk)))
(defrule (with-rfc4180-csv-syntax () body ...)
  (call-with-rfc4180-csv-syntax (lambda () body ...)))

(def (call-with-strict-rfc4180-csv-syntax thunk)
  (parameterize ((current-csv-options strict-rfc4180-csv-options)) (thunk)))
(defrule (with-strict-rfc4180-csv-syntax () body ...)
  (call-with-strict-rfc4180-csv-syntax (lambda () body ...)))

(def (call-with-creativyst-csv-syntax thunk)
  (parameterize ((current-csv-options creativyst-csv-options)) (thunk)))
(defrule (with-creativyst-csv-syntax () body ...)
  (call-with-creativyst-csv-syntax (lambda () body ...)))

(def (valid-eol? x)
  (member x +line-endings+))

;;; Non-hygienic helper macros for concise access to the ambient csv-options binding.
;;; These work correctly when def/opt, {v}, and w/opt are used directly in source —
;;; not when wrapped by other macros (which would give each call site different marks).

;; (def/opt (f args...) body...) → def with (csv-options (current-csv-options)) appended.
(defrule (def/opt (f args ...) body ...)
  (with-id ((csv-options f "csv-options"))
    (def (f args ... (csv-options (current-csv-options)))
      body ...)))

;; {field} → (csv-options-field csv-options) inside a def/opt body.
(defrule {v}
  (with-id ((csv-options v "csv-options")
             (accessor    v "csv-options-" v))
    (accessor csv-options)))

;; (w/opt f args...) → (f args... csv-options) inside a def/opt body.
(defrule (w/opt f args ...)
  (with-id ((csv-options f "csv-options"))
    (f args ... csv-options)))

(def/opt (validate-csv-options)
  (assert! (char? {separator}))
  (assert! (char? {quote}))
  (assert! (not (equal? {separator} {quote})))
  (assert! (boolean? {unquoted-quotequote?}))
  (assert! (boolean? {loose-quote?}))
  (assert! (boolean? {allow-binary?}))
  (assert! (valid-eol? {eol}))
  (assert! (not (member (string-ref {eol} 0) [{separator} {quote}])))
  (assert! (boolean? {accept-lf?}))
  (assert! (boolean? {accept-cr?}))
  (assert! (boolean? {accept-crlf?}))
  (assert! (or {accept-cr?} {accept-lf?} {accept-crlf?}))
  (let (delimiters [{separator} {quote}])
    (when (or {accept-cr?} {accept-crlf?})
      (assert! (not (memv #\return delimiters))))
    (when (or {accept-lf?} {accept-crlf?})
      (assert! (not (memv #\newline delimiters)))))
  (assert! (boolean? {skip-whitespace?})))

; -----------------------------------------------------------------------------
;;; The parser

(def (char-ascii-text? c)
  (let ((i (char->integer c)))
    (or (<= #x20 i #x7E) (= i 10) (= i 13))))

(def (accept pred (reader :- BufferedReader))
  (let (c (reader.peek-char-utf8))
    (and (not (eof-object? c)) (pred c) (reader.read-char-utf8))))

(def (accept= c (reader :- BufferedReader))
  (and (eqv? c (reader.peek-char-utf8)) (reader.read-char-utf8)))

(def (accept-eof (reader :- BufferedReader))
  (eof-object? (reader.peek-char-utf8)))

(def/opt (char-csv-space? c)
  (and (or (eqv? c #\space) (eqv? c #\tab))
       (not (eqv? c {separator})) (not (eqv? c {quote}))))

;; Read one line from SOURCE in CSV format, using the current syntax parameters.
;; SOURCE is anything with-buffered-reader accepts.
;; Return a list of strings, one for each field in the line.
;; Entries are read as strings;
;; it is up to you to interpret the strings as whatever you want.
(def/opt (read-csv-line source)
  (w/opt validate-csv-options)
  (w/opt read-csv-record source))

(def/opt (read-csv-record source)
  (with-buffered-reader (reader source)
    (def ss (open-output-string))
    (def fields '())
    (def (accept-eol (reader :- BufferedReader))
      (or (and (eqv? (reader.peek-char-utf8) #\newline)
               (cond ({accept-lf?} (reader.read-char-utf8) #t)
                     ((and {accept-crlf?} (not {accept-cr?}))
                      (raise-io-error accept-eol "Linefeed without Carriage-Return!"))
                     (else #f)))
          (and (or {accept-cr?} {accept-crlf?})
               (and (accept= #\return reader)
                    (or (and {accept-crlf?} (accept= #\newline reader))
                        {accept-cr?}
                        (raise-io-error accept-eol "Carriage-Return without Linefeed!"))))))
    (def (accept-space reader)
      (accept (lambda (c) (w/opt char-csv-space? c)) reader))
    (def (accept-spaces reader)
      (with-list-builder (c) (let loop () (let ((x (accept-space reader))) (when x (c x) (loop))))))
    (def (accept-fields)
      (when {skip-whitespace?} (accept-spaces reader))
      (if (and (null? fields) (or (accept-eol reader) (accept-eof reader)))
        (done)
        (accept-field-start)))
    (def (accept-field-start)
      (cond
       ((accept= {separator} reader)
        (add "") (accept-fields))
       ((accept= {quote} reader)
        (cond
         ((and {unquoted-quotequote?} (accept= {quote} reader))
          (add-char {quote})
          (accept-field-unquoted))
         (else
          (accept-field-quoted))))
       (else
        (accept-field-unquoted))))
    (def (accept-field-quoted)
      (cond
       ((accept-eof reader)
        (raise-io-error read-csv-line "unexpected eof in quotes"))
       ((accept= {quote} reader)
        (cond
         ((accept= {quote} reader)
          (quoted-field-char {quote}))
         ({loose-quote?}
          (accept-field-unquoted))
         (else
          (add (current-string))
          (end-of-field))))
       (else
        (quoted-field-char (reader.read-char-utf8)))))
    (def (quoted-field-char c)
      (add-char c)
      (accept-field-quoted))
    (def (accept-field-unquoted)
      (if {skip-whitespace?}
        (let ((spaces (accept-spaces reader)))
          (cond
           ((accept= {separator} reader)
            (add (current-string))
            (accept-fields))
           ((or (accept-eol reader) (accept-eof reader))
            (add (current-string))
            (done))
           (else
            (for-each add-char spaces)
            (accept-field-unquoted-no-skip))))
        (accept-field-unquoted-no-skip)))
    (def (accept-field-unquoted-no-skip)
      (cond
       ((accept= {separator} reader)
        (add (current-string))
        (accept-fields))
       ((or (accept-eol reader) (accept-eof reader))
        (add (current-string))
        (done))
       ((accept= {quote} reader)
        (cond
         ((and {unquoted-quotequote?} (accept= {quote} reader))
          (add-char {quote}) (accept-field-unquoted))
         ({loose-quote?}
          (accept-field-quoted))
         (else
          (raise-io-error read-csv-line "unexpected quote in middle of field"))))
       (else
        (add-char (reader.read-char-utf8))
        (accept-field-unquoted))))
    (def (end-of-field)
      (when {skip-whitespace?} (accept-spaces reader))
      (cond
       ((or (accept-eol reader) (accept-eof reader))
        (done))
       ((accept= {separator} reader)
        (accept-fields))
       (else
        (raise-io-error read-csv-line "end of field expected"))))
    (def (add x)
      (push! x fields))
    (def (add-char c)
      (unless (or {allow-binary?} (char-ascii-text? c))
        (raise-io-error read-csv-line "binary data not allowed" c))
      (write-char c ss))
    (def (current-string)
      (get-output-string ss))
    (def (done)
      (reverse! fields))
    (accept-fields)))

;; Read all lines from SOURCE in CSV format, using the current syntax parameters.
;; SOURCE is anything with-buffered-reader accepts.
;; Return a list of list of strings, one entry per line, one string per field.
;; with-buffered-reader passes an already-open BufferedReader through without re-allocating,
;; so (w/opt read-csv-record reader) below incurs no extra allocation.
(def/opt (read-csv source)
  (w/opt validate-csv-options)
  (with-buffered-reader (reader source)
    (call-with-list-builder
      (lambda (c _)
        (until (accept-eof reader)
          (c (w/opt read-csv-record reader)))))))

; -----------------------------------------------------------------------------
;;; The writer

(def/opt (char-needs-quoting? x)
  (or (eqv? x {quote})
      (eqv? x {separator})
      (eqv? x #\newline)
      (eqv? x #\return)
      (not (char-ascii-text? x))))

(def/opt (string-needs-quoting? x)
  (and (not (string-null? x))
       (or (w/opt char-csv-space? (string-ref x 0))
           (w/opt char-csv-space? (string-ref x (1- (string-length x))))
           (string-any (lambda (c) (w/opt char-needs-quoting? c)) x))
       #t))

;; Write one line of FIELDS to WRITER in CSV format, using the current syntax parameters.
;; WRITER is anything with-buffered-writer accepts.
(def/opt (write-csv-line writer fields)
  (w/opt validate-csv-options)
  (with-buffered-writer (wr writer)
    (w/opt write-csv-record wr fields)))

(def/opt (write-csv-record (wr :- BufferedWriter) fields)
  (let loop ((fields fields) (first? #t))
    (match fields
      ([first . rest]
       (w/opt write-csv-field wr first (and first? (null? rest)))
       (unless (null? rest)
         (wr.write-char-utf8 {separator}))
       (loop rest #f))
      ([] (wr.write-string-utf8 {eol})))))

;; Write all LINES to WRITER in CSV format, using the current syntax parameters.
;; WRITER is anything with-buffered-writer accepts.
(def/opt (write-csv writer lines)
  (w/opt validate-csv-options)
  (with-buffered-writer (wr writer)
    (for-each (lambda (fields) (w/opt write-csv-record wr fields)) lines)))

(def/opt (write-csv-field (writer :- BufferedWriter) field singleton?)
  (def text
    (match field
      ((? not) "")
      ((? number?) (number->string field))
      ((? string?) field)
      ((? symbol?) (symbol->string field))
      (else (error "invalid CSV field" field))))
  (unless (or {allow-binary?} (string-every char-ascii-text? text))
    (raise-io-error write-csv-line "binary data not allowed" text))
  (cond
   ((string-null? text)
    (when singleton?
      (when {unquoted-quotequote?}
        (raise-io-error write-csv-line "singleton empty field has no spelling in this CSV syntax"))
      (w/opt write-quoted-string writer text)))
   ((and {unquoted-quotequote?} (char=? (string-ref text 0) {quote}))
    ;; The reader consumes initial quote pairs before it can enter a quoted field.
    (if (and {loose-quote?} (not (string-every {quote} text)))
      (w/opt write-quoted-string writer text)
      (begin
        (when (or (string-any {separator} text)
                  (and {skip-whitespace?}
                       (w/opt char-csv-space? (string-ref text (1- (string-length text)))))
                  (and (string-any #\return text) (or {accept-cr?} {accept-crlf?}))
                  (and (string-any #\newline text)
                       (or {accept-lf?} (and {accept-crlf?} (not {accept-cr?})))))
          (raise-io-error write-csv-line "field has no spelling in this CSV syntax" text))
        (w/opt write-escaped-string writer text))))
   ((w/opt string-needs-quoting? text) (w/opt write-quoted-string writer text))
   (else (writer.write-string-utf8 text))))

(def/opt (write-escaped-string (writer :- BufferedWriter) string)
  (string-for-each
   (lambda (c)
     (when (char=? c {quote}) (writer.write-char-utf8 c))
     (writer.write-char-utf8 c))
   string))

(def/opt (write-quoted-string (writer :- BufferedWriter) string)
  (writer.write-char-utf8 {quote})
  (w/opt write-escaped-string writer string)
  (writer.write-char-utf8 {quote}))
