;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; TAL runtime: the output port, the error handler, tal:write, and the
;;; procedures and macros define-TAL expansions call. Internal to
;;; :std/text/markup/tal, which exports only the public names.
;;;
;;; A template call renders into one byte buffer (a stdio memory buffer)
;;; and writes it to current-tal-output-port at the end; a template called
;;; while another renders to the same port joins its buffer. During a
;;; render current-tal-output-port is a fresh u8vector port, the spill port:
;;; bytes user code writes to it directly are moved into the buffer after
;;; every user expression (tal-user), so they keep their place; tal:write
;;; and joined templates write to the buffer.
;;; A statement that fails is discarded by cutting the buffer back to where
;;; the statement started (tal-scope) and dropping the spill port's bytes.
(import :std/error
        :std/iter/interface
        (only-in :std/iter iter)
        :std/io/bio/types
        ../output
        (only-in ../html/emitter
                 emit-html-string! html-escape-string
                 attribute-escapes html-escape-escapes literal-escapes verbatim-escapes)
        (only-in ../html/rules raw-text-ends? noscript-data-ok?))
(export current-tal-output-port
        current-tal:on-error
        tal:write
        ;; for define-TAL expansions
        tal-render-template
        tal-scope
        tal-on-error-scope
        tal-user
        tal-emit-bytes!
        tal-emit-text!
        tal-emit-as-is!
        tal-emit-raw!
        tal-emit-raw-text!
        tal-emit-as-is-raw-text!
        tal-emit-attribute!
        make-TALSwitch
        current-tal-switch
        tal-case?
        tal-case-else?
        make-tal-repeat
        tal-repeat-next!
        tal-repeat-item
        repeat-index
        repeat-number
        repeat-even?
        repeat-odd?
        repeat-start?
        repeat-end?
        repeat-letter
        repeat-Letter
        repeat-roman
        repeat-Roman)
;;; The port templates write to.
(def current-tal-output-port (make-parameter (current-output-port)))

;;; A render in progress: its buffer, its spill port, and the number of
;;; tal:on-error statements it is inside, which make failing statements
;;; raise to them instead of calling current-tal:on-error.
(defstruct TALRender
  ((out            :- memory-output-buffer)
   (spill          :- :u8vector-port)
   (on-error-depth :- :fixnum))
  final: #t)

(def current-tal-render (make-parameter #f))

;;; Moves the bytes user code wrote to the spill port into the buffer.
(def (tal-drain! (r :- TALRender)) => :void
  (let (bytes (get-output-u8vector r.spill))
    (unless (fx= (u8vector-length bytes) 0)
      (tal-emit-bytes! r bytes))))

;;; A memory buffer whose first buffer is small enough to be a movable
;;; object: Gambit allocates larger ones outside the heap, which costs more
;;; than the copies of growing a small one. Rendering a small page through
;;; a 4096-byte first buffer spent 3.8 µs per render collecting garbage
;;; against 0.8 µs with this one, 18,620 kernel cycles against 56 and 32%
;;; more user cycles, but only 4% more instructions (markup-benchmark.ss
;;; mode tal-small-page, SIZE 1, ITERATIONS 30000).
(def (make-render-buffer) => memory-output-buffer
  (make-memory-output 1024))

;;; Calls (body r) with r the render of the current port: a new one
;;; written to the port when body returns (or raises), or the render this
;;; call is nested in.
(def (tal-render-template (body :- :procedure)) => :void
  (let (port (current-tal-output-port))
    (using (r (current-tal-render) :? TALRender)
      (if (and r (eq? port r.spill))
        (begin
          (tal-drain! r)
          (body r))
        (let (spill (open-output-u8vector))
          (using (r (make-TALRender (make-render-buffer) spill 0) :- TALRender)
            (try
             (parameterize ((current-tal-output-port spill)
                            (current-tal-render r))
               (body r))
             (finally
              (tal-drain! r)
              (write-subu8vector r.out.buf 0 r.out.whi port)))))))
    (void)))

;;; user expressions

;;; The value of the user expression expr, after moving what it wrote to
;;; the spill port into the buffer.
(defrule (tal-user r expr)
  (let (value expr)
    (tal-drain! r)
    value))

;;; error scopes

;;; Runs body ... as one statement: when it raises, its output is
;;; discarded and the error goes to the innermost enclosing tal:on-error,
;;; or else to current-tal:on-error.
(defrule (tal-scope r body ...)
  (using (render r :- TALRender)
    (let (mark render.out.whi)
      (try
       body ...
       (catch (e) (tal-recover! render mark e))))))

(def (tal-discard! (r    :- TALRender)
                   (mark :- :fixnum)) => :void
  (set! r.out.whi mark)
  (get-output-u8vector r.spill)
  (void))

(def (tal-recover! (r    :- TALRender)
                   (mark :- :fixnum)
                   (e    :- :t)) => :void
  (tal-discard! r mark)
  (if (fx> r.on-error-depth 0)
    (raise e)
    (begin
      ((current-tal:on-error) e)
      (tal-drain! r))))

;;; A tal:on-error statement: runs body; when it raises, discards its
;;; output and runs handler with err bound to the exception.
(defrule (tal-on-error-scope r err body handler)
  (using (render r :- TALRender)
    (let ((mark render.out.whi)
          (depth render.on-error-depth))
      (set! render.on-error-depth (fx+ depth 1))
      (try
       body
       (set! render.on-error-depth depth)
       (catch (e)
         (set! render.on-error-depth depth)
         (tal-discard! render mark)
         (let (err e) handler))))))

;;; output

(def (tal-emit-bytes! (r     :- TALRender)
                      (bytes :- :u8vector)) => :void
  (output-append! r.out bytes 0 (u8vector-length bytes)))

;;; The text of a value: strings as they are, numbers and symbols as
;;; written, anything else as display writes it.
(def (value-string (value :- :t)) => :string
  (cond
   ((string? value) value)
   ((fixnum? value) (number->string value))
   ((symbol? value) (symbol->string value))
   (else (call-with-output-string "" (lambda (port) (display value port))))))

;;; Text content: escaped as html-escape escapes it; #f writes nothing.
(def (tal-emit-text! (r     :- TALRender)
                     (value :- :t)) => :void
  (when value
    (emit-html-string! r.out (value-string value) html-escape-escapes)))

;;; as-is: content: unescaped; #f writes nothing, a u8vector its bytes.
(def (tal-emit-as-is! (r     :- TALRender)
                      (value :- :t)) => :void
  (cond
   ((not value) (void))
   ((u8vector? value) (tal-emit-bytes! r value))
   (else (emit-html-string! r.out (value-string value) verbatim-escapes))))

;;; raw: content: as as-is:, but #f, #!void and default: write nothing.
(def (tal-emit-raw! (r     :- TALRender)
                    (value :- :t)) => :void
  (unless (or (eq? value #!void) (eq? value default:))
    (tal-emit-as-is! r value)))

;;; Text content of a raw text element local (script?: a script element;
;;; noscript?: inside a noscript element): written literally, and raises
;;; unless the element still ends at its end tag after it, and the noscript
;;; element, which a scripting parser reads as raw text, at its own. The
;;; text must not be modified during the call (see
;;; :std/text/markup/xml/types).
(def (tal-emit-raw-text! (r         :- TALRender)
                         (local     :- :string)
                         (script?   :- :boolean)
                         (noscript? :- :boolean)
                         (value     :- :t)) => :void
  (when value
    (let (text (value-string value))
      (unless (raw-text-ends? local script? text)
        (error (string-append "text would end <" local "> early") text))
      (when (and noscript? (not (noscript-data-ok? text)))
        (error "text would end <noscript> early" text))
      (emit-html-string! r.out text literal-escapes))))

;;; as-is: content of a raw text element: checked as tal-emit-raw-text!
;;; checks text, as write-html checks HTMLRaw there; a u8vector is decoded
;;; as UTF-8 first.
(def (tal-emit-as-is-raw-text! (r         :- TALRender)
                               (local     :- :string)
                               (script?   :- :boolean)
                               (noscript? :- :boolean)
                               (value     :- :t)) => :void
  (tal-emit-raw-text! r local script? noscript? (if (u8vector? value) (utf8->string value) value)))

;;; A tal:attributes value: prefix holds the bytes of ' name="'; default
;;; those of the template's attribute, or #f. #f omits the attribute,
;;; default: keeps the template's, #t writes name="".
(def (tal-emit-attribute! (r       :- TALRender)
                          (prefix  :- :u8vector)
                          (default :? :u8vector)
                          (value   :- :t)) => :void
  (cond
   ((not value) (void))
   ((eq? value default:)
    (when default
      (tal-emit-bytes! r default)))
   (else
    (tal-emit-bytes! r prefix)
    (unless (eq? value #t)
      (emit-html-string! r.out (value-string value) attribute-escapes))
    (emit-ascii! r.out "\""))))

;;; tal:write

;;; Writes thing to current-tal-output-port: a u8vector as bytes, a string
;;; as UTF-8, anything else as display writes it. Returns "".
(def (tal:write (thing : :t)) => :string
  (let (port (current-tal-output-port))
    (using (r (current-tal-render) :? TALRender)
      (if (and r (eq? port r.spill))
        (begin
          (tal-drain! r)
          (if (u8vector? thing)
            (tal-emit-bytes! r thing)
            (emit-html-string! r.out (value-string thing) verbatim-escapes)))
        (cond
         ((u8vector? thing) (write-u8vector thing port))
         ((string? thing) (write-u8vector (string->utf8 thing) port))
         (else (display thing port)))))
    ""))

;;; errors

(extern namespace: #f RuntimeException-exception)

(def (tal-error-message (e : :t)) => :string
  (cond
   ((RuntimeException? e)
    (tal-error-message (RuntimeException-exception e)))
   ((error-message e))
   (else
    (call-with-output-string
     "" (lambda (port)
          (parameterize ((current-error-port port))
            (display-exception e)))))))

;;; Handles an error of a statement outside every tal:on-error: by default
;;; writes "ERROR: " and the error message, escaped.
(def current-tal:on-error
  (make-parameter
   (lambda (e)
     (tal:write (html-escape-string (string-append "ERROR: " (tal-error-message e)))))))

;;; tal:switch and tal:case

(defstruct TALSwitch
  ((value    :- :t)
   (matched? :- :boolean))
  final: #t)

(def current-tal-switch (make-parameter #f))

;;; True for the first tal:case of the current tal:switch whose value is
;;; equal? to value.
(def (tal-case? (value : :t)) => :boolean
  (using (switch (current-tal-switch) :? TALSwitch)
    (and switch
         (not switch.matched?)
         (equal? switch.value value)
         (begin (set! switch.matched? #t) #t))))

;;; tal:case="else:": true unless a case of the current switch matched.
(def (tal-case-else?) => :boolean
  (using (switch (current-tal-switch) :? TALSwitch)
    (and switch
         (not switch.matched?)
         (begin (set! switch.matched? #t) #t))))

;;; tal:repeat

(defconst repeat-list 0)
(defconst repeat-vector 1)
(defconst repeat-string 2)
(defconst repeat-iterator 3)

;;; The iteration of a tal:repeat over a list, vector, string, or anything
;;; :std/iter iterates. The repeat-<method> procedures below are the
;;; methods of the repeat variable, repeat/<name>.<method>. Lists, vectors
;;; and strings are walked directly: an :std/iter iterator for every
;;; sequence (a string as its list, as :std/iter has no string iterator)
;;; took 13% more instructions and 15% more cycles rendering 100 tal:repeat
;;; lists of 3 items (markup-benchmark.ss mode tal-repeat, SIZE 100,
;;; ITERATIONS 2000).
(defstruct TALRepeat
  ((kind  :- :fixnum)
   (rest  :- :t)       ; list: items after the current one; else the sequence
   (count :- :fixnum)  ; vector, string: length
   (next  :- :t)       ; iterator: the item after the current one, or #!eof
   (item  :- :t)
   (index :- :fixnum))
  final: #t)

(def (make-tal-repeat (seq : :t)) => TALRepeat
  (cond
   ((or (pair? seq) (null? seq)) (make-TALRepeat repeat-list seq 0 #f #f -1))
   ((vector? seq) (make-TALRepeat repeat-vector seq (vector-length seq) #f #f -1))
   ((string? seq) (make-TALRepeat repeat-string seq (string-length seq) #f #f -1))
   (else
    (let (it (iter seq))
      (make-TALRepeat repeat-iterator it 0 (Iterator-next! it) #f -1)))))

;;; Moves to the next item; #f when there is none.
(def (tal-repeat-next! (r :- TALRepeat)) => :boolean
  (let ((kind r.kind)
        (index (fx+ r.index 1)))
    (cond
     ((fx= kind repeat-list)
      (let (rest r.rest)
        (and (pair? rest)
             (begin
               (set! r.item (car rest))
               (set! r.rest (cdr rest))
               (set! r.index index)
               #t))))
     ((fx< index r.count)
      (set! r.item (if (fx= kind repeat-vector)
                     (using (vec r.rest :- :vector)
                       (vector-ref vec index))
                     (using (str r.rest :- :string)
                       (string-ref str index))))
      (set! r.index index)
      #t)
     ((fx= kind repeat-iterator)
      (using (it r.rest :- Iterator)
        (let (item r.next)
          (and (not (eof-object? item))
               (begin
                 (set! r.item item)
                 (set! r.next (it.next!))
                 (set! r.index index)
                 #t)))))
     (else #f))))

(def (tal-repeat-item (r :- TALRepeat)) => :t
  r.item)

(def (repeat-end? (r :- TALRepeat)) => :boolean
  (let (kind r.kind)
    (cond
     ((fx= kind repeat-list) (null? r.rest))
     ((fx= kind repeat-iterator) (eof-object? r.next))
     (else (fx= (fx+ r.index 1) r.count)))))

;;; n >= 1 as letters: 1 a, 26 z, 27 aa, ...
(def (integer->letters (n    :- :fixnum)
                       (base :- :char)) => :string
  (let loop ((n n) (chars '()))
    (if (fx<= n 0)
      (list->string chars)
      (let (n (fx- n 1))
        (loop (fxquotient n 26)
              (cons (integer->char (fx+ (char->integer base) (fxremainder n 26))) chars))))))

(def roman-digits
  '(("M" . 1000) ("CM" . 900) ("D" . 500) ("CD" . 400) ("C" . 100) ("XC" . 90)
    ("L" . 50) ("XL" . 40) ("X" . 10) ("IX" . 9) ("V" . 5) ("IV" . 4) ("I" . 1)))

(def (integer->roman (n :- :fixnum)) => :string
  (let loop ((n n) (digits roman-digits) (parts '()))
    (cond
     ((or (fx<= n 0) (null? digits)) (string-concatenate (reverse parts)))
     ((fx>= n (cdar digits)) (loop (fx- n (cdar digits)) digits (cons (caar digits) parts)))
     (else (loop n (cdr digits) parts)))))

(def (repeat-index (r :- TALRepeat)) => :fixnum
  r.index)

(def (repeat-number (r :- TALRepeat)) => :fixnum
  (fx+ r.index 1))

(def (repeat-even? (r :- TALRepeat)) => :boolean
  (fxeven? r.index))

(def (repeat-odd? (r :- TALRepeat)) => :boolean
  (fxodd? r.index))

(def (repeat-start? (r :- TALRepeat)) => :boolean
  (fx= r.index 0))

(def (repeat-letter (r :- TALRepeat)) => :string
  (integer->letters (fx+ r.index 1) #\a))

(def (repeat-Letter (r :- TALRepeat)) => :string
  (integer->letters (fx+ r.index 1) #\A))

(def (repeat-roman (r :- TALRepeat)) => :string
  (string-downcase (integer->roman (fx+ r.index 1))))

(def (repeat-Roman (r :- TALRepeat)) => :string
  (integer->roman (fx+ r.index 1)))
