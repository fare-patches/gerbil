;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/encoding/utf8 unit test

(export utf8-test)
(import :std/error
        :std/test
        ./utf8)

;;; "aé€😀": one character of each UTF-8 length.
(def sample
  (list->string (map integer->char [#x61 #xe9 #x20ac #x1f600])))
(def sample-bytes
  #u8(#x61 #xc3 #xa9 #xe2 #x82 #xac #xf0 #x9f #x98 #x80))

;;; The offset of the UTF8Error that thunk raises, or #f.
(def (error-offset thunk)
  (with-catch (lambda (e) (and (utf8-error? e) (UTF8Error-offset e)))
              (lambda () (thunk) #f)))

;;; The where of the UTF8Error that thunk raises, or #f.
(def (error-where thunk)
  (with-catch (lambda (e) (and (utf8-error? e) (Error-where e)))
              (lambda () (thunk) #f)))

(def (lone-surrogate-string . codes)
  (list->string (map ##integer->char codes)))

(def utf8-test
  (test-suite "test :std/encoding/utf8"
    (test-case "encode and decode every sequence length"
      (check (utf8-encode sample) => sample-bytes)
      (check (utf8-decode sample-bytes) => sample)
      (check (utf8-encode sample) => (string->utf8 sample))
      (check (utf8-decode sample-bytes) => (utf8->string sample-bytes))
      (check (utf8-decoded-length sample-bytes) => 4)
      (check (string-utf8-length sample) => 10)
      (check (utf8-encode "") => #u8())
      (check (utf8-decode #u8()) => "")
      (check (utf8-encode "plain ASCII text") => (string->utf8 "plain ASCII text"))
      (check (utf8-decode (string->utf8 "plain ASCII text")) => "plain ASCII text")
      (for-each (lambda (code)
                  (let (str (string (integer->char code)))
                    (check (utf8-encode str) => (string->utf8 str))
                    (check (utf8-decode (string->utf8 str)) => str)))
                [0 #x7f #x80 #x7ff #x800 #xd7ff #xe000 #xfffd #xfffe #xffff #x10000 #x10ffff]))

    (test-case "start and end select a range"
      (check (utf8-encode sample 1 3) => #u8(#xc3 #xa9 #xe2 #x82 #xac))
      (check (utf8-encode sample 2) => #u8(#xe2 #x82 #xac #xf0 #x9f #x98 #x80))
      (check (utf8-decode sample-bytes 1 6) => (substring sample 1 3))
      (check (utf8-decode sample-bytes 6) => (substring sample 3 4))
      (check (utf8-decoded-length sample-bytes 1 6) => 2)
      (check-exception (utf8-encode sample 3 2) contract-violation-error?)
      (check-exception (utf8-decode sample-bytes 0 11) contract-violation-error?))

    (test-case "a lone surrogate raises at its string index"
      (check (error-offset (cut utf8-encode (lone-surrogate-string #x61 #xd800 #x62))) => 1)
      (check (error-offset (cut utf8-encode (lone-surrogate-string #x20ac #x61 #xdfff))) => 2)
      (check (error-offset (cut utf8-encode (lone-surrogate-string #x61 #x62 #xdc00) 1)) => 2)
      (check (utf8-encode (lone-surrogate-string #x61 #xd800 #x62) 2) => #u8(#x62))
      (check-exception (utf8-encode (lone-surrogate-string #xd800)) io-error?))

    (test-case "ill-formed UTF-8 raises at the first byte of its sequence"
      (for-each (lambda (case)
                  (let ((bytes (car case))
                        (offset (cadr case)))
                    (check (cons bytes (error-offset (cut utf8-decode bytes)))
                           => (cons bytes offset))
                    (check (cons bytes (error-offset (cut utf8-decoded-length bytes)))
                           => (cons bytes offset))))
                [[#u8(#x61 #x80) 1]                   ; lone continuation byte
                 [#u8(#x61 #xc0 #x80) 1]              ; overlong NUL
                 [#u8(#xc1 #xbf) 0]                   ; overlong
                 [#u8(#x61 #x62 #xe0 #x80 #x80) 2]    ; overlong three bytes
                 [#u8(#xed #xa0 #x80) 0]              ; encoded surrogate
                 [#u8(#xed #xbf #xbf) 0]
                 [#u8(#xf0 #x8f #xbf #xbf) 0]         ; overlong four bytes
                 [#u8(#xf4 #x90 #x80 #x80) 0]         ; above U+10FFFF
                 [#u8(#x61 #xf5 #x80 #x80 #x80) 1]
                 [#u8(#xff) 0]
                 [#u8(#xc3 #xa9 #xe2 #x82) 2]         ; truncated at the end
                 [#u8(#xe2 #x82 #x61) 0]              ; truncated by ASCII
                 [#u8(#xf0 #x9f #x98) 0]])
      ;; the end of the range truncates a sequence; offsets index bytes
      (check (error-offset (cut utf8-decode sample-bytes 0 5)) => 3)
      (check (error-offset (cut utf8-decode sample-bytes 4)) => 4)
      (check (error-offset (cut utf8-decode sample-bytes 3 9)) => 6)
      (check-exception (utf8-decode #u8(#x80)) io-error?)
      (check (error-where (cut utf8-decode #u8(#x80))) => 'utf8-decode)
      (check (error-where (cut utf8-decoded-length #u8(#x80))) => 'utf8-decoded-length))

    (test-case "unchecked encoding with a sentinel tail, raising at surrogates"
      (check (&utf8-encode sample 0 4 1) => (u8vector-append sample-bytes #u8(0)))
      (check (&utf8-encode "abc" 0 3 2) => #u8(97 98 99 0 0))
      (check (&utf8-encode sample 1 3 0) => #u8(#xc3 #xa9 #xe2 #x82 #xac))
      (check (error-offset (cut &utf8-encode (lone-surrogate-string #x61 #xe9 #xdbff) 0 3 1))
             => 2)
      (check (error-offset (cut &utf8-encode (lone-surrogate-string #x61 #xd800) 0 2 1))
             => 1))

    (test-case "unchecked validation and decoding"
      (let (buf (u8vector-append sample-bytes #u8(0)))
        (check (map (cut &utf8-sequence-length buf <>) [1 3 6]) => [2 3 4])
        (check (&utf8-sequence-length #u8(#xe2 #x82 0) 0) => 0)
        (check (map (cut &utf8-code-at buf <>) [0 1 3 6]) => [#x61 #xe9 #x20ac #x1f600])
        (check (&utf8-count-continuations buf 0 10) => 6)
        (check (&utf8-decode buf 0 10 4) => sample)
        (check (&utf8-decode buf 1 6 2) => (substring sample 1 3))
        (check (&utf8-decode (string->utf8 "hello, world") 7 12 5) => "world")
        (let (out (make-u8vector 4 0))
          (check (&put-utf8! out 0 #x1f600) => 4)
          (check out => #u8(#xf0 #x9f #x98 #x80))
          (check (&put-utf8! out 1 #xe9) => 3))))))
