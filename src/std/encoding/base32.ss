;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; RFC 4648 Base32 encoding and decoding.
;;; RFC 4648 §6: https://www.rfc-editor.org/rfc/rfc4648#section-6
;;; Human-entered keys may omit padding and include grouping separators.

(import :std/error)
(export base32-encode
        base32-decode
        base32-decode-lenient)

;; Encode bytes with optional padding and lowercase alphabet; see base32.md.
(def (base32-encode (bytes : :u8vector)
                    padding: (padding? : :boolean := #t)
                    lowercase: (lowercase? : :boolean := #f))
  => :string
  (let* ((len (u8vector-length bytes))
         ;; Generic arithmetic avoids overflow before checking the output size.
         (size (if padding?
                 (* 8 (quotient (+ len 4) 5))
                 (quotient (+ (* len 8) 4) 5)))
         (alphabet (if lowercase?
                     "abcdefghijklmnopqrstuvwxyz234567"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")))
    (unless (fixnum? size)
      (raise-contract-violation base32-encode "Base32 output length exceeds fixnum range"
                                length: len output-length: size))
    (let (out (make-string size #\=))
      ;; Flush before reading another byte: at most four pending bits plus eight.
      (let loop ((i 0) (j 0) (bits 0) (acc 0))
        (cond
         ((fx>= bits 5)
          (let (rest (fx- bits 5))
            (string-set! out j (string-ref alphabet (fxarithmetic-shift-right acc rest)))
            (loop i (fx1+ j) rest
                  (fxand acc (fx1- (fxarithmetic-shift-left 1 rest))))))
         ((fx< i len)
          (loop (fx1+ i) j (fx+ bits 8)
                (fxior (fxarithmetic-shift-left acc 8) (u8vector-ref bytes i))))
         (else
          (when (fx> bits 0)
            (string-set! out j
                         (string-ref alphabet (fxarithmetic-shift-left acc (fx- 5 bits)))))
          out))))))

;; Map a Base32 character of either case to its 5-bit value, or -1 if outside the alphabet.
(def (base32-char-value (char : :char))
  => :fixnum
  (let (code (char->integer char))
    (cond
     ((and (fx>= code 65) (fx<= code 90)) (fx- code 65))
     ((and (fx>= code 97) (fx<= code 122)) (fx- code 97))
     ((and (fx>= code 50) (fx<= code 55)) (fx- code 24))
     (else -1))))

;; Keep the public decoder identifier at the error site. The lenient scan has
;; already validated every separator before end, just past the last data symbol.
(defrule (decode-base32-data who input data-count stop remainder separators?)
  ;; Divide before multiplying so the exact allocation fits a fixnum.
  (let* ((str input)
         (count data-count)
         (end stop)
         (residue remainder)
         (out (make-u8vector (fx+ (fx* (fxquotient count 8) 5)
                                  (fxquotient (fx* residue 5) 8)))))
    (let loop ((i 0) (j 0) (bits 0) (acc 0))
      (cond
       ((fx< i end)
        (let (value (base32-char-value (string-ref str i)))
          (cond
           ((fx< value 0)
            (if separators?
              (loop (fx1+ i) j bits acc)
              (raise-contract-violation who "Invalid Base32 character"
                                        index: i length: (string-length str) char: (string-ref str i))))
           (else
            ;; At most seven pending bits plus five, so emit at most one byte.
            (let ((bits (fx+ bits 5))
                  (acc (fxior (fxarithmetic-shift-left acc 5) value)))
              (if (fx< bits 8)
                (loop (fx1+ i) j bits acc)
                (let (rest (fx- bits 8))
                  (u8vector-set! out j (fxarithmetic-shift-right acc rest))
                  (loop (fx1+ i) (fx1+ j) rest
                        (fxand acc (fx1- (fxarithmetic-shift-left 1 rest)))))))))))
       ((fxzero? acc) out)
       (else
        (raise-contract-violation who "Nonzero Base32 unused pad bits"
                                  index: (fx1- end) length: (string-length str)
                                  char: (string-ref str (fx1- end))))))))

;; Decode either letter case, enforcing canonical lengths, padding and pad bits.
(def (base32-decode (str : :string)
                    no-padding: (no-padding? : :boolean := #f))
  => :u8vector
  (let* ((len (string-length str))
         (end (let strip ((i len))
                (if (and (fx> i 0) (char=? (string-ref str (fx1- i)) #\=))
                  (strip (fx1- i))
                  i)))
         (residue (fxmodulo end 8))
         (padding (fx- len end)))
    (when (memv residue '(1 3 6))
      (raise-contract-violation base32-decode "Impossible Base32 data length"
                                length: len data-length: end))
    (unless (if (fxzero? padding)
              (or no-padding? (fxzero? residue))
              (and (fx> residue 0) (fx= padding (fx- 8 residue))))
      (raise-contract-violation base32-decode "Incorrect Base32 padding"
                                index: end length: len padding: padding))
    (decode-base32-data base32-decode str end end residue #f)))

;; Ignore grouping separators and allow omitted padding. Report positions
;; in the original string, including for padding and unused-bit errors.
(def (base32-decode-lenient (str : :string))
  => :u8vector
  (let (len (string-length str))
    ;; Validating pre-pass: count data characters and find the end of the last one.
    (let-values (((count end padding first-pad)
                  (let scan ((i 0) (count 0) (end 0) (padding 0) (first-pad #f))
                    (if (fx< i len)
                      (let (char (string-ref str i))
                        (case char
                          ((#\space #\tab #\newline #\return #\-)
                           (scan (fx1+ i) count end padding first-pad))
                          ((#\=)
                           (scan (fx1+ i) count end (fx1+ padding) (or first-pad i)))
                          (else
                           (cond
                            ((fx< (base32-char-value char) 0)
                             (raise-contract-violation base32-decode-lenient
                                                       "Invalid Base32 character"
                                                       index: i length: len char: char))
                            (first-pad
                             (raise-contract-violation base32-decode-lenient
                                                       "Base32 data after padding"
                                                       index: i length: len char: char))
                            (else
                             (scan (fx1+ i) (fx1+ count) (fx1+ i) 0 #f))))))
                      (values count end padding first-pad)))))
      (let (residue (fxmodulo count 8))
        (when (memv residue '(1 3 6))
          (raise-contract-violation base32-decode-lenient "Impossible Base32 data length"
                                    length: len data-length: count))
        (when (and first-pad
                   (or (fxzero? residue) (not (fx= padding (fx- 8 residue)))))
          (raise-contract-violation base32-decode-lenient "Incorrect Base32 padding"
                                    index: first-pad length: len padding: padding))
        (decode-base32-data base32-decode-lenient str count end residue #t)))))
