;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Byte output: the escaping and emission the XML, HTML, TAL and Djot
;;; writers and the scanners' scratch buffers share, writing UTF-8 straight
;;; into a stdio output buffer (:std/io/bio basic-output-buffer): a memory
;;; buffer, or the buffer of a BufferedWriter over a sink. Room is made by
;;; bio-output-reserve!, which grows a memory buffer and drains any other.
;;; Also the memory buffers they use, and the decoding of one as a string.
;;; Unchecked internals of :std/text/markup.
;;;
;;; The TAL reader and compiler load this module at expansion time, where
;;; the stdlib build cannot evaluate C code: it imports only the parts of
;;; :std/io/bio that are free of it.
(import :std/error
        :std/io/bio/types
        (only-in :std/io/bio/output bio-output-reserve!)
        (only-in :std/io/bio/cache default-buffer-size)
        (only-in :std/encoding/utf8 &put-utf8! &utf8-count-continuations &utf8-decode))
(export make-memory-output
        memory-output-string
        output-reserve!
        output-append!
        escape-none
        escape-amp
        escape-lt
        escape-gt
        escape-cr
        escape-quot
        escape-tab
        escape-lf
        escape-apos
        escape-invalid
        for-each-name-slice
        define-string-emitter
        emit-ascii!)
(declare (not safe))

;;; Escaping expands a character to at most 6 bytes (&quot;); strings and
;;; names are emitted in slices whose worst case fits a buffer of stdio's
;;; default size, so that a BufferedWriter's buffer only drains for them.
(def max-expansion 6)
(def slice-chars (fxquotient default-buffer-size max-expansion))

;;; A memory buffer whose first buffer has size bytes. The writers start at
;;; 4096: starting at 1 KB took 1% more instructions and 4% more cycles
;;; writing 2.6 KB of HTML (markup-benchmark.ss mode html-write-elements,
;;; SIZE 20, ITERATIONS 3000), but 7% fewer instructions and 9% fewer cycles
;;; writing documents of 250 bytes (mode xml-write-namespaces, SIZE 100,
;;; ITERATIONS 700).
(def (make-memory-output (size :- :fixnum := 4096)) => memory-output-buffer
  (make-memory-output-buffer (make-u8vector size) #f #f 0))

;;; The UTF-8 written into out, as a string, decoded from out's buffer:
;;; get-memory-output-string-utf8, which validates the UTF-8 and closes the
;;; buffer, took 12% more instructions and 15% to 35% more cycles writing
;;; documents of 250 bytes (markup-benchmark.ss mode xml-write-namespaces,
;;; SIZE 100, ITERATIONS 700).
(def (memory-output-string (out :- memory-output-buffer)) => :string
  (let ((buf out.buf)
        (end out.whi))
    (&utf8-decode buf 0 end (fx- end (&utf8-count-continuations buf 0 end)))))

;;; The buffer of out with room for n more bytes at out.whi, valid until the
;;; next reservation. A macro: the test runs once per emitted string, in
;;; each emitting module.
(defrule (output-reserve! out-expr n-expr)
  (let ((o out-expr)
        (n n-expr))
    (using (o :- basic-output-buffer)
      (if (fx<= n (fx- (##u8vector-length o.buf) o.whi))
        o.buf
        (bio-output-reserve! o n)))))

;;; Appends bytes[s, e) to out. Inline, and skipping empty spans, which the
;;; scanners append often: a procedure without the test, with bytes=? of
;;; ./scan-input a procedure too, took 21% more instructions and 32% more
;;; cycles reading XML (markup-benchmark.ss mode xml-read-text, SIZE 1000,
;;; ITERATIONS 700).
(definline (output-append! (out   :- basic-output-buffer)
                           (bytes :- :u8vector)
                           (s     :- :fixnum)
                           (e     :- :fixnum)) => :void
  (when (fx< s e)
    (let (buf (output-reserve! out (fx- e s)))
      (##subu8vector-move! bytes s e buf out.whi)
      (set! out.whi (fx+ out.whi (fx- e s))))))

;;; escaping

;;; Escape tables for characters below #x80: escape-none is written as is,
;;; escape-invalid is not representable, anything else indexes escape-bytes.
(defconst escape-none 0)
(defconst escape-amp 1)                 ; &amp;
(defconst escape-lt 2)                  ; &lt;
(defconst escape-gt 3)                  ; &gt;
(defconst escape-cr 4)                  ; &#13;
(defconst escape-quot 5)                ; &quot;
(defconst escape-tab 6)                 ; &#9;
(defconst escape-lf 7)                  ; &#10;
(defconst escape-apos 8)                ; &#39;
(defconst escape-invalid 255)

(def escape-bytes
  (vector #f
          (string->utf8 "&amp;")
          (string->utf8 "&lt;")
          (string->utf8 "&gt;")
          (string->utf8 "&#13;")
          (string->utf8 "&quot;")
          (string->utf8 "&#9;")
          (string->utf8 "&#10;")
          (string->utf8 "&#39;")))

;;; Runs body over each slice [s, e) of the string str of at most slice-chars
;;; characters, with buf holding room for bytes-per-char bytes per character.
(defrule (for-each-slice (out str bytes-per-char) (buf s e) body ...)
  (let (n (##string-length str))
    (let slice ((s 0))
      (when (fx< s n)
        (let* ((e (fxmin n (fx+ s slice-chars)))
               (buf (output-reserve! out (fx* bytes-per-char (fx- e s)))))
          body ...
          (slice e))))))

;;; for-each-slice for names, which are almost always one slice: no loop then.
(defrule (for-each-name-slice (out str) (buf s e) body ...)
  (let (n (##string-length str))
    (if (fx<= n slice-chars)
      (let* ((s 0)
             (e n)
             (buf (output-reserve! out (fx* 4 n))))
        body ...)
      (for-each-slice (out str 4) (buf s e) body ...))))

;;; Defines (name out str table), which writes str UTF-8 encoded, escaping
;;; per table, and raises for where on escape-invalid characters and on code
;;; points of at least #x80 for which (invalid-code? c) holds.
(defrule (define-string-emitter (name where expectation) invalid-code?)
  (def (name (out   :- basic-output-buffer)
             (str   :- :string)
             (table :- :u8vector)) => :void
    (for-each-slice (out str max-expansion) (buf s e)
      (defrule (code k) (##char->integer (##string-ref str k)))
      (defrule (plain? c) (fx= (##u8vector-ref table c) escape-none))
      ;; one character, escaped or encoded
      (def (one i pos)
        (let (c (code i))
          (cond
           ((fx< c #x80)
            (let (k (##u8vector-ref table c))
              (cond
               ((fx= k escape-none)
                (##u8vector-set! buf pos c)
                (loop (fx+ i 1) (fx+ pos 1)))
               ((fx= k escape-invalid)
                (raise-bad-argument where expectation c))
               (else
                (let* ((escape (##vector-ref escape-bytes k))
                       (len (##u8vector-length escape)))
                  (##subu8vector-move! escape 0 len buf pos)
                  (loop (fx+ i 1) (fx+ pos len)))))))
           ((invalid-code? c)
            (raise-bad-argument where expectation c))
           (else
            (loop (fx+ i 1) (&put-utf8! buf pos c))))))
      ;; four ASCII characters that need no escape, or else one
      (def (loop i pos)
        (cond
         ((fx<= (fx+ i 4) e)
          (let ((c0 (code i))
                (c1 (code (fx+ i 1)))
                (c2 (code (fx+ i 2)))
                (c3 (code (fx+ i 3))))
            (if (and (fx< (fxior c0 c1 c2 c3) #x80)
                     (plain? c0) (plain? c1) (plain? c2) (plain? c3))
              (begin
                (##u8vector-set! buf pos c0)
                (##u8vector-set! buf (fx+ pos 1) c1)
                (##u8vector-set! buf (fx+ pos 2) c2)
                (##u8vector-set! buf (fx+ pos 3) c3)
                (loop (fx+ i 4) (fx+ pos 4)))
              (one i pos))))
         ((fx< i e) (one i pos))
         (else (set! out.whi pos))))
      (loop s out.whi))))

;;; Writes the bytes of an ASCII string literal.
(defsyntax (emit-ascii! stx)
  (syntax-case stx ()
    ((_ out str)
     (stx-string? #'str)
     (with-syntax (((code ...) (map char->integer (string->list (stx-e #'str))))
                   ((offset ...) (iota (string-length (stx-e #'str))))
                   (n (string-length (stx-e #'str))))
       #'(using (o out :- basic-output-buffer)
           (let* ((buf (output-reserve! o n))
                  (pos o.whi))
             (##u8vector-set! buf (fx+ pos offset) code) ...
             (set! o.whi (fx+ pos n))))))))
