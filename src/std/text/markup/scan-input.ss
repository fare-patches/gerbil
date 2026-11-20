;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Scan input buffers: a document as UTF-8 bytes followed by a 0 sentinel,
;;; which every scanning loop of the XML and HTML scanners stops at, and the
;;; byte and vector helpers the scanners, the HTML tree builder and the
;;; HTML emitter share.
;;; Unchecked internals of :std/text/markup; ./input reads sources into them.
;;; Kept apart from ./input, which imports :std/io: the TAL reader reaches
;;; this module at syntax time, and the stdlib build cannot evaluate :std/io
;;; there.
(import (only-in :std/encoding/utf8 &put-utf8! &utf8-encode &utf8-count-continuations utf8-error?)
        (only-in :std/text/parser/char-set codepoint-surrogate?))
(export u8vector->scan-input
        string->scan-input
        latin1->utf8
        scan-input-offset
        ascii
        match-ascii?
        bytes=?
        after-cr
        ascii-fold-code
        fnv-basis
        fnv
        make-byte-table
        skip-plain
        vector-grow)
(declare (not safe))

;;; Copies bytes[start, end) into a fresh scan input buffer.
(def (u8vector->scan-input (bytes :- :u8vector)
                           (start :- :fixnum)
                           (end   :- :fixnum)) => :u8vector
  (let (buf (##make-u8vector (fx+ (fx- end start) 1) 0))
    (##subu8vector-move! bytes start end buf 0)
    buf))

;;; UTF-8 encodes str into a scan input buffer. A string can hold lone
;;; surrogates (Gambit's port decoders return them for encoded surrogates),
;;; which UTF-8 cannot: they become U+FFFD, as the HTML standard's input
;;; stream reads them. They are rare, so a string that holds one is encoded
;;; twice.
(def (string->scan-input (str :- :string)) => :u8vector
  (defrule (encode str)
    (&utf8-encode str 0 (##string-length str) 1))
  (def (replace-surrogate c)
    (if (codepoint-surrogate? (char->integer c)) (integer->char #xfffd) c))
  (with-catch
   (lambda (e)
     (if (utf8-error? e)
       (encode (string-map replace-surrogate str))
       (raise e)))
   (lambda () (encode str))))

;;; Transcodes ISO-8859-1 buf[0, end) into a scan input buffer.
(def (latin1->utf8 (buf :- :u8vector)
                   (end :- :fixnum)) => :u8vector
  (let* ((high (let loop ((i 0) (n 0))
                 (if (fx< i end)
                   (loop (fx+ i 1) (if (fx>= (##u8vector-ref buf i) #x80) (fx+ n 1) n))
                   n)))
         (out (##make-u8vector (fx+ end high 1) 0)))
    (let loop ((i 0) (j 0))
      (when (fx< i end)
        (loop (fx+ i 1) (&put-utf8! out j (##u8vector-ref buf i)))))
    out))

;;; Offset in the caller's input of index i into the scan input buf, input in
;;; [0, end): i itself for byte input; for input that was mapped (encoded from
;;; a string or transcoded from ISO-8859-1), one per character before i.
(def (scan-input-offset (buf     :- :u8vector)
                        (end     :- :fixnum)
                        (mapped? :- :boolean)
                        (i       :- :fixnum)) => :fixnum
  (if mapped?
    (let (e (fxmin i end))
      (fx- e (&utf8-count-continuations buf 0 e)))
    i))

;;; byte helpers

;;; The code of a character literal, at expansion time: (ascii #\<) is 60.
(defsyntax (ascii stx)
  (syntax-case stx ()
    ((_ c)
     (char? (stx-e #'c))
     (with-syntax ((code (char->integer (stx-e #'c))))
       #'code))))

;;; True when buf holds the ASCII literal str at i. Expands to one byte
;;; compare per character, in order, so a scanner never reads past a
;;; mismatching byte (such as its 0 sentinel).
(defsyntax (match-ascii? stx)
  (syntax-case stx ()
    ((_ buf i str)
     (stx-string? #'str)
     (with-syntax (((code ...) (map char->integer (string->list (stx-e #'str))))
                   ((offset ...) (iota (string-length (stx-e #'str)))))
       #'(and (fx= (##u8vector-ref buf (fx+ i offset)) code) ...)))))

;;; True when a[as, as + n) and b[bs, bs + n) hold the same bytes. Inline,
;;; as ../output output-append! is.
(definline (bytes=? (a  :- :u8vector)
                    (as :- :fixnum)
                    (b  :- :u8vector)
                    (bs :- :fixnum)
                    (n  :- :fixnum)) => :boolean
  (:- (let loop ((k 0))
        (cond
         ((fx>= k n) #t)
         ((fx= (##u8vector-ref a (fx+ as k)) (##u8vector-ref b (fx+ bs k))) (loop (fx+ k 1)))
         (else #f)))
      :boolean))

;;; Index after the line end at j (CR, or CR LF).
(definline (after-cr (buf :- :u8vector)
                     (j   :- :fixnum)) => :fixnum
  (if (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\newline)) (fx+ j 2) (fx+ j 1)))

;;; The code c with ASCII upper case folded to lower case.
(definline (ascii-fold-code (c :- :fixnum)) => :fixnum
  (if (and (fx>= c (ascii #\A)) (fx<= c (ascii #\Z))) (fx+ c 32) c))

;;; The scanners' name hash: FNV-1a, 32 bits, byte by byte from fnv-basis.
(defconst fnv-basis 2166136261)

(definline (fnv (h :- :fixnum)
                (b :- :fixnum)) => :fixnum
  (fxand (fx* (fxxor h b) 16777619) #xffffffff))

(def (make-byte-table (classify :- :procedure)) => :u8vector
  (let (table (make-u8vector 256 0))
    (let loop ((b 0))
      (when (fx< b 256)
        (u8vector-set! table b (classify b))
        (loop (fx+ b 1))))
    table))

;;; Index of the first byte at or after j whose class in table is not 0
;;; (plain): tests 4 bytes per iteration, then single bytes. A byte is read
;;; only after the previous one proved to be plain, so never past a sentinel
;;; whose class is not plain.
(defrule (skip-plain buf table j)
  (let skip ((k j))
    (if (and (fx= (##u8vector-ref table (##u8vector-ref buf k)) 0)
             (fx= (##u8vector-ref table (##u8vector-ref buf (fx+ k 1))) 0)
             (fx= (##u8vector-ref table (##u8vector-ref buf (fx+ k 2))) 0)
             (fx= (##u8vector-ref table (##u8vector-ref buf (fx+ k 3))) 0))
      (skip (fx+ k 4))
      (let one ((k k))
        (if (fx= (##u8vector-ref table (##u8vector-ref buf k)) 0)
          (one (fx+ k 1))
          k)))))

;;; A copy of vec[0, fill) in a new vector of at least need slots, twice
;;; vec's length if that is more; the other slots are #f.
(def (vector-grow (vec  :- :vector)
                  (fill :- :fixnum)
                  (need :- :fixnum)) => :vector
  (let (new (make-vector (fxmax need (fx* 2 (##vector-length vec))) #f))
    (subvector-move! vec 0 fill new 0)
    new))
