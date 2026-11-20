;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; UTF-8 conversions without intermediate ports: checked conversions that
;;; raise UTF8Error at the exact offset of invalid input, and the unchecked
;;; primitives under them, for scanners and serializers that establish their
;;; own bounds. See utf8.md.
(import :std/error
        (only-in :std/string/utf8 string-utf8-length))
(export utf8-encode
        utf8-decode
        utf8-decoded-length
        string-utf8-length
        UTF8Error
        UTF8Error?
        utf8-error?
        UTF8Error-offset
        &put-utf8!
        &utf8-encode
        &utf8-sequence-length
        &utf8-code-at
        &utf8-check-run
        &utf8-count-continuations
        &utf8-decode)
(declare (not safe))

;;; Invalid input at offset: the index in the u8vector of an ill-formed
;;; sequence, or in the string of a lone surrogate.
(deferror-class (UTF8Error IOError) (offset) utf8-error?)

;;; encoding

;;; Stores the UTF-8 encoding of code point c at buf[j]; evaluates to the
;;; index after it. buf must have room for 4 bytes at j. When on-surrogate
;;; is not #f, it is evaluated for a surrogate c and must escape; only
;;; three-byte code points pay for the test.
(defsyntax (encode-code! stx)
  (syntax-case stx ()
    ((_ buf j c on-surrogate)
     (with-syntax ((three (if (stx-e #'on-surrogate)
                            #'(if (bmp-surrogate-code? x) on-surrogate x)
                            #'x)))
       #'(let ((k j) (x c))
           (defrule (tail v shift)
             (fxior #x80 (fxand (fxarithmetic-shift-right v shift) #x3f)))
           (cond
            ((fx< x #x80)
             (##u8vector-set! buf k x)
             (fx+ k 1))
            ((fx< x #x800)
             (##u8vector-set! buf k (fxior #xc0 (fxarithmetic-shift-right x 6)))
             (##u8vector-set! buf (fx+ k 1) (tail x 0))
             (fx+ k 2))
            ((fx< x #x10000)
             (let (y three)
               (##u8vector-set! buf k (fxior #xe0 (fxarithmetic-shift-right y 12)))
               (##u8vector-set! buf (fx+ k 1) (tail y 6))
               (##u8vector-set! buf (fx+ k 2) (tail y 0)))
             (fx+ k 3))
            (else
             (##u8vector-set! buf k (fxior #xf0 (fxarithmetic-shift-right x 18)))
             (##u8vector-set! buf (fx+ k 1) (tail x 12))
             (##u8vector-set! buf (fx+ k 2) (tail x 6))
             (##u8vector-set! buf (fx+ k 3) (tail x 0))
             (fx+ k 4))))))))

;;; True when c, below #x10000, is a surrogate: one test, on the
;;; three-byte path only.
(defrule (bmp-surrogate-code? c)
  (fx= (fxand c #xf800) #xd800))

;;; Stores the UTF-8 encoding of code point c, not a surrogate, at buf[j];
;;; returns the index after it. Unchecked: buf must have room for 4 bytes
;;; at j.
(definline (&put-utf8! (buf :- :u8vector)
                       (j   :- :fixnum)
                       (c   :- :fixnum))
  => :fixnum
  (encode-code! buf j c #f))

;;; Copies the ASCII prefix of str[start, end) to buf from 0, four
;;; characters at a time; returns the index in str of the first non-ASCII
;;; character, or end.
(def (ascii-prefix! (str   :- :string)
                    (start :- :fixnum)
                    (end   :- :fixnum)
                    (buf   :- :u8vector))
  => :fixnum
  (defrule (code i) (##char->integer (##string-ref str i)))
  (def (one i)
    (if (and (fx< i end) (fx< (code i) #x80))
      (begin
        (##u8vector-set! buf (fx- i start) (code i))
        (four (fx+ i 1)))
      i))
  (def (four i)
    (if (fx<= (fx+ i 4) end)
      (let ((c0 (code i))
            (c1 (code (fx+ i 1)))
            (c2 (code (fx+ i 2)))
            (c3 (code (fx+ i 3)))
            (j (fx- i start)))
        (if (fx< (fxior c0 c1 c2 c3) #x80)
          (begin
            (##u8vector-set! buf j c0)
            (##u8vector-set! buf (fx+ j 1) c1)
            (##u8vector-set! buf (fx+ j 2) c2)
            (##u8vector-set! buf (fx+ j 3) c3)
            (four (fx+ i 4)))
          (one i)))
      (one i)))
  (four start))

;;; The UTF-8 encoding of str[start, end) followed by tail 0 bytes (a
;;; scanner's sentinel), as a fresh u8vector. A lone surrogate raises
;;; UTF8Error at its index. Unchecked: 0 <= start <= end <=
;;; (string-length str), tail >= 0. ASCII text is encoded in one pass: the
;;; rest is sized at the first non-ASCII character. The trailing fills
;;; write the scanner's zero sentinel. Sizing exactly beats allocating 4
;;; bytes per character and shrinking, which took 2.2 times the cpu time
;;; reading HTML fragments (:std/text/markup's markup-benchmark.ss mode
;;; html-read-fragments, SIZE 100, ITERATIONS 2000) and 15% more cycles
;;; reading nested elements (mode html-read-nested-divs, SIZE 500,
;;; ITERATIONS 400).
(def (&utf8-encode (str   :- :string)
                   (start :- :fixnum)
                   (end   :- :fixnum)
                   (tail  :- :fixnum))
  => :u8vector
  (let* ((ascii (##make-u8vector (fx+ (fx- end start) tail)))
         (k (ascii-prefix! str start end ascii)))
    (if (fx= k end)
      (begin
        (subu8vector-fill! ascii (fx- end start) (##u8vector-length ascii) 0)
        ascii)
      (let* ((prefix (fx- k start))
             (buf (##make-u8vector (fx+ (fx+ prefix (##string->utf8-length str k end)) tail))))
        (##subu8vector-move! ascii 0 prefix buf 0)
        (let loop ((i k) (j prefix))
          (if (fx< i end)
            (loop (fx+ i 1)
                  (encode-code! buf j (##char->integer (##string-ref str i))
                                (begin (raise-lone-surrogate i) #xfffd)))
            (subu8vector-fill! buf j (##u8vector-length buf) 0)))
        buf))))

(def (raise-lone-surrogate (i :- :fixnum)) => :void
  (raise (UTF8Error "lone surrogate"
                    offset: i
                    where: 'utf8-encode
                    irritants: ['offset i])))

;;; The UTF-8 encoding of str[start, end). Raises UTF8Error at the index of
;;; a lone surrogate, which UTF-8 cannot encode.
(def (utf8-encode (str   : :string)
                  (start :~ (in-range-inclusive? 0 (string-length str))
                         :- :fixnum := 0)
                  (end   :~ (in-range-inclusive? start (string-length str))
                         :- :fixnum := (string-length str)))
  => :u8vector
  (&utf8-encode str start end 0))

;;; validation

(defrule (continuation? b)
  (fx= (fxand b #xc0) #x80))

;;; Length of the well-formed UTF-8 sequence (Unicode Table 3-7) whose
;;; first byte (byte k) is >= #x80, or 0; (byte i) reads the byte at i.
;;; Reads a byte only after the previous one proved to be a continuation
;;; byte.
(defrule (sequence-length byte k)
  (let (b0 (byte k))
    (cond
     ((fx< b0 #xc2) 0)
     ((fx< b0 #xe0)
      (if (continuation? (byte (fx+ k 1))) 2 0))
     ((fx< b0 #xf0)
      (let (b1 (byte (fx+ k 1)))
        (if (and (continuation? b1)
                 (cond
                  ((fx= b0 #xe0) (fx>= b1 #xa0))
                  ((fx= b0 #xed) (fx< b1 #xa0))
                  (else #t))
                 (continuation? (byte (fx+ k 2))))
          3
          0)))
     ((fx< b0 #xf5)
      (let (b1 (byte (fx+ k 1)))
        (if (and (continuation? b1)
                 (cond
                  ((fx= b0 #xf0) (fx>= b1 #x90))
                  ((fx= b0 #xf4) (fx< b1 #x90))
                  (else #t))
                 (continuation? (byte (fx+ k 2)))
                 (continuation? (byte (fx+ k 3))))
          4
          0)))
     (else 0))))

;;; Length of the well-formed UTF-8 sequence at bytes[k], whose first byte
;;; is >= #x80, or 0 when it is ill-formed. Unchecked, and reads past the
;;; sequence until a byte proves not to be a continuation byte: bytes must
;;; end with a byte below #x80 after k, as a scanner's 0 sentinel does.
(definline (&utf8-sequence-length (bytes :- :u8vector)
                                  (k     :- :fixnum))
  => :fixnum
  (defrule (byte i) (##u8vector-ref bytes i))
  (sequence-length byte k))

;;; Count of characters in bytes[start, end), whose UTF-8 it checks; raises
;;; UTF8Error at the index of the first ill-formed sequence.
(def (utf8-decoded-length (bytes : :u8vector)
                          (start :~ (in-range-inclusive? 0 (u8vector-length bytes))
                                 :- :fixnum := 0)
                          (end   :~ (in-range-inclusive? start (u8vector-length bytes))
                                 :- :fixnum := (u8vector-length bytes)))
  => :fixnum
  (decoded-length bytes start end 'utf8-decoded-length))

;;; Checks the UTF-8 sequences from bytes[k] up to the next byte below #x80
;;; or end, then evaluates (resume i n) at that index i, n being count plus
;;; their continuation bytes; at the first ill-formed sequence i, evaluates
;;; (fail i) instead. Reads no byte at or past end. A macro, for scanning
;;; loops: fail and resume are forms of the caller's.
(defrule (&utf8-check-run bytes-expr k-expr end-expr count fail resume)
  (let ((bytes bytes-expr)
        (end end-expr))
    (defrule (byte i)
      (let (m i)
        (if (fx< m end) (##u8vector-ref bytes m) 0)))
    (let run ((i k-expr) (n count))
      (if (or (fx>= i end) (fx< (##u8vector-ref bytes i) #x80))
        (resume i n)
        (let (len (sequence-length byte i))
          (if (fx= len 0)
            (fail i)
            (run (fx+ i len) (fx+ n (fx- len 1)))))))))

;;; utf8-decoded-length, raising for where.
(def (decoded-length (bytes :- :u8vector)
                     (start :- :fixnum)
                     (end   :- :fixnum)
                     (where :- :symbol))
  => :fixnum
  (defrule (invalid k)
    (raise (UTF8Error "invalid UTF-8"
                      offset: k
                      where: where
                      irritants: ['offset k])))
  (let loop ((k start) (continuations 0))
    (cond
     ((fx>= k end)
      (fx- (fx- end start) continuations))
     ((fx< (##u8vector-ref bytes k) #x80)
      (loop (fx+ k 1) continuations))
     (else
      (&utf8-check-run bytes k end continuations invalid loop)))))

;;; decoding

;;; Runs body with c bound to the code point of the well-formed sequence at
;;; bytes[i] and len to its length; inline, for the decoding loop.
(defrule (with-code-point (c len) bytes i body ...)
  (let* ((b bytes)
         (k i)
         (b0 (##u8vector-ref b k)))
    (defrule (tail m shift)
      (fxarithmetic-shift-left (fxand (##u8vector-ref b (fx+ k m)) #x3f) shift))
    (cond
     ((fx< b0 #x80)
      (let ((c b0) (len 1)) body ...))
     ((fx< b0 #xe0)
      (let ((c (fxior (fxarithmetic-shift-left (fxand b0 #x1f) 6)
                      (tail 1 0)))
            (len 2))
        body ...))
     ((fx< b0 #xf0)
      (let ((c (fxior (fxarithmetic-shift-left (fxand b0 #x0f) 12)
                      (tail 1 6)
                      (tail 2 0)))
            (len 3))
        body ...))
     (else
      (let ((c (fxior (fxarithmetic-shift-left (fxand b0 #x07) 18)
                      (tail 1 12)
                      (tail 2 6)
                      (tail 3 0)))
            (len 4))
        body ...)))))

;;; The code point of the well-formed sequence at bytes[k]. Unchecked.
(definline (&utf8-code-at (bytes :- :u8vector)
                          (k     :- :fixnum))
  => :fixnum
  (:- (with-code-point (c len) bytes k c) :fixnum))

;;; Count of UTF-8 continuation bytes in bytes[start, end). Unchecked.
(definline (&utf8-count-continuations (bytes :- :u8vector)
                                      (start :- :fixnum)
                                      (end   :- :fixnum))
  => :fixnum
  (:- (let loop ((k start) (n 0))
        (if (fx< k end)
          (loop (fx+ k 1) (if (continuation? (##u8vector-ref bytes k)) (fx+ n 1) n))
          n))
      :fixnum))

;;; The string of the well-formed UTF-8 bytes[start, end) holding n
;;; characters: (- end start) less its continuation bytes. Unchecked. ASCII
;;; (n = end - start) is copied four bytes at a time. Inline: as a
;;; procedure (def), it took 6% more instructions and 19% more cycles
;;; reading XML (:std/text/markup's markup-benchmark.ss mode xml-read-text,
;;; SIZE 1000, ITERATIONS 700).
(definline (&utf8-decode (bytes :- :u8vector)
                         (start :- :fixnum)
                         (end   :- :fixnum)
                         (n     :- :fixnum))
  => :string
  (let (str (##make-string n))
    (if (fx= n (fx- end start))
      (let loop ((k 0))
        (defrule (copy! k)
          (##string-set! str k (##integer->char (##u8vector-ref bytes (fx+ start k)))))
        (cond
         ((fx<= (fx+ k 4) n)
          (copy! k)
          (copy! (fx+ k 1))
          (copy! (fx+ k 2))
          (copy! (fx+ k 3))
          (loop (fx+ k 4)))
         ((fx< k n)
          (copy! k)
          (loop (fx+ k 1)))))
      (let loop ((i start) (j 0))
        (when (fx< j n)
          (with-code-point (c len) bytes i
            (##string-set! str j (##integer->char c))
            (loop (fx+ i len) (fx+ j 1))))))
    str))

;;; The string of the UTF-8 bytes[start, end). Raises UTF8Error at the
;;; index of the first ill-formed sequence.
(def (utf8-decode (bytes : :u8vector)
                  (start :~ (in-range-inclusive? 0 (u8vector-length bytes))
                         :- :fixnum := 0)
                  (end   :~ (in-range-inclusive? start (u8vector-length bytes))
                         :- :fixnum := (u8vector-length bytes)))
  => :string
  (&utf8-decode bytes start end (decoded-length bytes start end 'utf8-decode)))
