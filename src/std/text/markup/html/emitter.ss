;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML emitter: serializes typed HTML trees as UTF-8 into a stdio output
;;; buffer (../output), as the WHATWG HTML fragment serialization algorithm
;;; does, and rejects what the HTML parser would not read back as written.
;;; Unchecked internals of :std/text/markup/html/writer.
;;;
;;; Nodes are immutable (../xml/types): slots are trusted at their declared
;;; types.
(import :std/error
        (only-in :std/encoding/utf8 &put-utf8!)
        (only-in :std/text/parser/char-set codepoint-surrogate?)
        ../xml/node
        (only-in ../scan-input ascii vector-grow)
        :std/io/bio/types
        ../output
        ./node
        ./rules)
(export (struct-out HTMLEmitter)
        make-html-emitter
        emit-html!
        html-escape-string
        ;; the element serialization steps and checks, for :std/text/markup/tal
        with-start-tag
        start-tag-info
        emit-tag-name!
        emit-attribute!
        emit-element-children!
        emit-element-end-tag!
        emit-html-string!
        emit-node!
        column-element?
        ignored-none
        ignored-frameset
        ignored-column-group
        attribute-escapes
        html-escape-escapes
        literal-escapes
        verbatim-escapes)
(declare (not safe))

(defstruct HTMLEmitter
  ((out        :- basic-output-buffer)
   (scripting? :- :boolean)  ; noscript content is raw text
   (noscript   :- :fixnum)   ; open noscript elements, when not scripting?
   (ended?     :- :boolean)  ; a plaintext element was written: nothing may follow
   (ignored    :- :fixnum)   ; ignored-*: where the tree builder ignores start tags
   (html-read? :- :boolean)  ; foreign elements here are read as HTML in an HTML context
   (attributes :- :vector))  ; the start tag's attributes (collect-attributes!)
  final: #t)

;;; Where the tree builder ignores most start tags, so that the text of a raw
;;; text element would be read as markup: in or after a frameset (all but
;;; frameset, frame and noframes), and in a template after a col child
;;; (column group mode: all but col and template).
(defconst ignored-none 0)
(defconst ignored-frameset 1)
(defconst ignored-column-group 2)

;;; An emitter at the top level, writing to out.
(def (make-html-emitter (out        :- basic-output-buffer)
                        (scripting? :- :boolean)) => HTMLEmitter
  (make-HTMLEmitter out scripting? 0 #f ignored-none #f (vector)))

;;; escaping

;;; Escape tables (characters below #x80, see ../output): text escapes
;;; & < >, attribute values also ", literal data nothing. NUL is invalid in
;;; all three: the parser drops it or reads it as U+FFFD. Verbatim data (raw
;;; markup, processing instruction data, which keeps NUL) has no invalid
;;; character.
(def (make-html-escape-table (escapes :- :list)
                             (nul     :- :fixnum)) => :u8vector
  (let (table (make-u8vector 128 escape-none))
    (u8vector-set! table 0 nul)
    (for-each (lambda (escape)
                (u8vector-set! table (char->integer (car escape)) (cdr escape)))
              escapes)
    table))

(def text-escapes
  (make-html-escape-table [(cons #\& escape-amp) (cons #\< escape-lt) (cons #\> escape-gt)]
                          escape-invalid))
(def attribute-escapes
  (make-html-escape-table [(cons #\& escape-amp) (cons #\< escape-lt) (cons #\> escape-gt)
                           (cons #\" escape-quot)]
                          escape-invalid))
(def literal-escapes (make-html-escape-table '() escape-invalid))
;;; html-escape's: & < > " ' as &amp; &lt; &gt; &quot; &#39;, for
;;; :std/text/markup/tal's dynamic text.
(def html-escape-escapes
  (make-html-escape-table [(cons #\& escape-amp) (cons #\< escape-lt) (cons #\> escape-gt)
                           (cons #\" escape-quot) (cons #\' escape-apos)]
                          escape-invalid))
(def verbatim-escapes (make-html-escape-table '() escape-none))

;;; (emit-html-string! out str table): surrogates have no UTF-8 encoding.
(define-string-emitter (emit-html-string! write-html "character the HTML parser reads back")
  codepoint-surrogate?)

;;; names

;;; Classes of name characters below #x80.
(defconst tag-invalid 0)         ; whitespace, /, >, NUL
(defconst tag-other 1)
(defconst tag-lower 2)           ; a-z
(defconst tag-upper 3)           ; A-Z
(defconst tag-equals 4)          ; =

(def tag-char-classes
  (let (table (make-u8vector 128 tag-other))
    (for-each (lambda (c) (u8vector-set! table c tag-invalid))
              [0 9 10 12 13 32 (ascii #\/) (ascii #\>)])
    (let loop ((c (ascii #\a)))
      (when (fx<= c (ascii #\z))
        (u8vector-set! table c tag-lower)
        (u8vector-set! table (fx- c 32) tag-upper)
        (loop (fx+ c 1))))
    (u8vector-set! table (ascii #\=) tag-equals)
    table))

;;; Writes the name str of a start or end tag: an ASCII letter, then no
;;; whitespace, /, > or NUL; no ASCII upper case unless upper? (SVG names
;;; whose case the tree builder adjusts).
(def (emit-tag-name! (out    :- basic-output-buffer)
                     (str    :- :string)
                     (upper? :- :boolean)) => :void
  (defrule (bad) (raise-bad-argument write-html "HTML tag name" str))
  (when (fx= (string-length str) 0)
    (bad))
  (for-each-name-slice (out str) (buf s e)
    (let loop ((i s) (pos out.whi))
      (if (fx< i e)
        (let (c (##char->integer (##string-ref str i)))
          (if (fx< c #x80)
            (let (k (##u8vector-ref tag-char-classes c))
              (unless (cond
                       ((fx= k tag-lower) #t)
                       ((fx= k tag-upper) upper?)
                       (else (and (fx> i 0) (not (fx= k tag-invalid)))))
                (bad))
              (##u8vector-set! buf pos c)
              (loop (fx+ i 1) (fx+ pos 1)))
            (begin
              (when (or (fx= i 0) (codepoint-surrogate? c))
                (bad))
              (loop (fx+ i 1) (&put-utf8! buf pos c)))))
        (set! out.whi pos)))))

;;; Writes an attribute name as the tokenizer reads it back: no whitespace,
;;; /, > or NUL, = only first, and no ASCII upper case unless foreign? (on
;;; SVG and MathML elements, whose names collect-attributes! checks): the
;;; HTML part of written-attribute-name's rule (./rules), made here as the
;;; name is written, which costs less than a pass of its own.
(def (emit-attribute-name! (out      :- basic-output-buffer)
                           (str      :- :string)
                           (foreign? :- :boolean)) => :void
  (defrule (bad) (raise-bad-argument write-html "HTML attribute name" str))
  (when (fx= (string-length str) 0)
    (bad))
  (for-each-name-slice (out str) (buf s e)
    (let loop ((i s) (pos out.whi))
      (if (fx< i e)
        (let (c (##char->integer (##string-ref str i)))
          (if (fx< c #x80)
            (let (k (##u8vector-ref tag-char-classes c))
              (when (or (fx= k tag-invalid)
                        (and (fx= k tag-equals) (fx> i 0))
                        (and (fx= k tag-upper) (not foreign?)))
                (bad))
              (##u8vector-set! buf pos c)
              (loop (fx+ i 1) (fx+ pos 1)))
            (begin
              (when (codepoint-surrogate? c)
                (bad))
              (loop (fx+ i 1) (&put-utf8! buf pos c)))))
        (set! out.whi pos)))))

;;; checked attributes

;;; h.attributes holds two slots per attribute of the start tag being
;;; written: its written name and its value.
(defrule (attribute-name slots k) (##vector-ref slots (fx* 2 k)))
(defrule (attribute-value slots k) (##vector-ref slots (fx+ (fx* 2 k) 1)))

;;; The name an attribute named name (an XMLName) of an element in
;;; namespace uri is written with (written-attribute-name, ./rules), or
;;; raises; on HTML elements, emit-attribute-name! rejects upper case.
(defrule (checked-written-name uri name)
  (using (n name :- XMLName)
    (or (written-attribute-name uri n.uri n.local n.prefix #t)
        (raise-bad-argument write-html
                            (if (and (fx= (string-length n.uri) 0) (fx= (string-length n.prefix) 0))
                              "foreign attribute name the tree builder keeps"
                              "attribute in no namespace, or a namespaced attribute of an SVG or MathML element")
                            n))))

;;; Checks the attribute list attrs of an element in namespace uri, copies
;;; the written name and value of each into h.attributes, checks that no
;;; two names are the same and returns the attribute count.
(def (collect-attributes! (h     :- HTMLEmitter)
                          (uri   :- :string)
                          (attrs :- :list)) => :fixnum
  (let loop ((rest attrs) (k 0))
    (if (pair? rest)
      (using (attr (##car rest) :- XMLAttribute)
        (let* ((written (checked-written-name uri attr.name))
               (base (fx* 2 k))
               (slots (let (slots h.attributes)
                        (if (fx< base (##vector-length slots))
                          slots
                          (grow-attribute-slots! h)))))
          (##vector-set! slots base written)
          (##vector-set! slots (fx+ base 1) attr.value)
          (loop (##cdr rest) (fx+ k 1))))
      (begin
        (when (fx> k 1)
          (check-distinct-attributes! h.attributes k))
        k))))

;;; Doubles h.attributes.
(def (grow-attribute-slots! (h :- HTMLEmitter)) => :vector
  (let* ((slots h.attributes)
         (new (vector-grow slots (##vector-length slots) 32)))
    (set! h.attributes new)
    new))

;;; The tokenizer keeps the first of two attributes with the same name. The
;;; written names are as the parser reads them back (no ASCII upper case but
;;; in the adjusted SVG and MathML spellings), so they compare exactly; up to
;;; pairwise-attribute-limit pairwise in place, more through find-duplicate.
;;; find-duplicate for all of them took 18% more instructions and 27% more
;;; cycles writing HTML (markup-benchmark.ss mode html-write-elements, SIZE
;;; 1000, ITERATIONS 300).
(def (check-distinct-attributes! (slots :- :vector)
                                 (count :- :fixnum)) => :void
  (let (name (if (fx<= count pairwise-attribute-limit)
               (pairwise-duplicate (i 0 (fx< i count) (fx+ i 1) (attribute-name slots i))
                                   (a b (string-same? a b)))
               (find-duplicate (let loop ((i (fx- count 1)) (names '()))
                                 (if (fx< i 0)
                                   names
                                   (loop (fx- i 1) (cons (attribute-name slots i) names))))
                               string<?
                               string=?)))
    (when name
      (raise-bad-argument write-html "distinct attribute names" name))))

;;; The value of the attribute written as name, or #f.
(def (attribute-ref (slots :- :vector)
                    (count :- :fixnum)
                    (name  :- :string)) => (Maybe :string)
  (let loop ((k 0))
    (and (fx< k count)
         (if (string-same? (attribute-name slots k) name)
           (attribute-value slots k)
           (loop (fx+ k 1))))))

;;; Writes ` name="value"` for an attribute named name of an element in
;;; namespace ns (uri), or ` name="` when value is #f, with the checks of
;;; collect-attributes! but for duplicates: for :std/text/markup/tal, which
;;; writes the values of tal:attributes itself.
(def (emit-attribute! (out   :- basic-output-buffer)
                      (ns    :- :fixnum)
                      (uri   :- :string)
                      (name  :- XMLName)
                      (value :? :string)) => :void
  (emit-ascii! out " ")
  (emit-attribute-name! out (checked-written-name uri name) (not (fx= ns ns-html)))
  (emit-ascii! out "=\"")
  (when value
    (emit-html-string! out value attribute-escapes)
    (emit-ascii! out "\"")))

;;; Writes the count collected attributes; foreign? as for
;;; emit-attribute-name!.
(def (emit-attributes! (h        :- HTMLEmitter)
                       (count    :- :fixnum)
                       (foreign? :- :boolean)) => :void
  (let ((out h.out)
        (slots h.attributes))
    (let loop ((k 0))
      (when (fx< k count)
        (emit-ascii! out " ")
        (emit-attribute-name! out (attribute-name slots k) foreign?)
        (emit-ascii! out "=\"")
        (emit-html-string! out (attribute-value slots k) attribute-escapes)
        (emit-ascii! out "\"")
        (loop (fx+ k 1))))))

;;; literal data

;;; Raises unless literal data can be written inside an open noscript
;;; element, which a scripting parser reads as raw text.
(def (check-noscript! (h    :- HTMLEmitter)
                      (data :- :string)) => :void
  (when (and (fx> h.noscript 0) (not (noscript-data-ok? data)))
    (raise-bad-argument write-html "data without </noscript inside noscript" data)))

;;; The string data of a text or raw node.
(def (text-node-data (node :- XML)) => :string
  (cond
   ((XMLText? node) (using (node :- XMLText) node.data))
   ((HTMLRaw? node) (using (node :- HTMLRaw) node.data))
   (else
    (raise-bad-argument write-html "only text in a raw text, RCDATA or plaintext element"
                        node))))

;;; The text of the children kids of a raw text or plaintext element, joined.
(def (literal-text (kids :- :list)) => :string
  (cond
   ((null? kids) "")
   ((null? (##cdr kids)) (text-node-data (##car kids)))
   (else
    (let loop ((rest kids) (parts '()))
      (if (pair? rest)
        (loop (##cdr rest) (cons (text-node-data (##car rest)) parts))
        (string-concatenate (reverse parts)))))))

;;; Writes the children of a raw text element local literally, unless the
;;; text would not end exactly at the end tag written after it
;;; (raw-text-ends?).
(def (emit-raw-text! (h      :- HTMLEmitter)
                     (local  :- :string)
                     (class  :- :fixnum)
                     (kids   :- :list)) => :void
  (let (data (literal-text kids))
    (unless (raw-text-ends? local (class-has? class class-script) data)
      (raise-bad-argument write-html "raw text that does not end its element" local data))
    (check-noscript! h data)
    (emit-html-string! h.out data literal-escapes)))

;;; Writes the children of a title or textarea element: text only.
(def (emit-rcdata! (h    :- HTMLEmitter)
                   (kids :- :list)) => :void
  (let loop ((rest kids))
    (when (pair? rest)
      (let (node (##car rest))
        (cond
         ((XMLText? node)
          (using (node :- XMLText)
            (emit-html-string! h.out node.data text-escapes)))
         ((HTMLRaw? node)
          (using (node :- HTMLRaw)
            (emit-html-string! h.out node.data verbatim-escapes)))
         (else
          (raise-bad-argument write-html "only text in a title or textarea element" node))))
      (loop (##cdr rest)))))

;;; nodes

;;; Checks element el for context and collects its attributes, then runs
;;; body with out, name (its XMLName), local, ns, kids, class, inner (the
;;; context of its children) and count (its attributes) bound.
(defrule (with-checked-start-tag (h el context) (out name local ns kids class inner count)
           body ...)
  (using ((emitter h :- HTMLEmitter)
          (element el :- XMLElement))
    (let ((out emitter.out)
          (name element.name)
          (attrs element.attributes)
          (kids element.children)
          (uri element.name.uri)
          (local element.name.local)
          (prefix element.name.prefix))
      (let (ns (namespace-code uri))
        (unless (and (fx>= ns 0) (fx= (string-length prefix) 0) (not (fx= (string-length local) 0)))
          (raise-bad-argument write-html "element named in no namespace, SVG or MathML, without prefix"
                              name))
        ;; At the top level, as in an HTML context, but only svg and math
        ;; are bound to a namespace: the parser reads <svg> as SVG and
        ;; <math> as MathML there, so in another namespace their children
        ;; would be read by other rules, HTML raw text as markup.
        (let (expected (start-tag-namespace (if (fx= context context-free) context-html context)
                                            local
                                            (and (not (fx= ns ns-html))
                                                 (string-same? local "font")
                                                 (font-breakout-attributes? attrs))))
          (unless (or (fx= ns expected)
                      (and (fx= context context-free) (fx= expected ns-html)))
            (raise-bad-argument write-html "element in the namespace its start tag gets here"
                                name)))
        ;; emit-tag-name! rejects ASCII upper case in HTML names; a call of
        ;; element-local-round-trips? for every HTML element took 5% more
        ;; instructions and 6% more cycles writing HTML (markup-benchmark.ss
        ;; mode html-write-elements, SIZE 1000, ITERATIONS 300).
        (unless (if (fx= ns ns-html)
                  (not (html-element-renamed? local))
                  (element-local-round-trips? uri local))
          (raise-bad-argument write-html "element name the tree builder keeps" name))
        ;; A scripting parser reads noscript as raw text: a nested one
        ;; would end the outer element early.
        (when (and (fx> emitter.noscript 0) (ascii-ci=? local "noscript"))
          (raise-bad-argument write-html "no noscript inside noscript" name))
        (let ((count (if (null? attrs) 0 (collect-attributes! emitter uri attrs)))
              (class (if (fx= ns ns-html) (element-class-of-name local) 0)))
          (when (and (fx> emitter.ignored ignored-none)
                     (or (class-has? class class-raw)
                         (fx= class class-plaintext)
                         (and (fx= class class-noscript) emitter.scripting?))
                     (not (and (fx= emitter.ignored ignored-frameset)
                               (string-same? local "noframes"))))
            (raise-bad-argument write-html
                                "no raw text element in or after a frameset, or after col in a template"
                                name))
          (let (inner (child-context ns local
                                     (attribute-ref emitter.attributes count "encoding")))
            body ...))))))

;;; Checks element el for context, writes its start tag, then runs body
;;; with out, name (its XMLName), local, ns, kids, class and inner (the
;;; context of its children) bound; h is an HTMLEmitter variable. A macro
;;; shared by emit-element! and :std/text/markup/tal's start tags, so that
;;; emit-element! stays one procedure.
(defrule (with-start-tag (h el context) (out name local ns kids class inner) body ...)
  (with-checked-start-tag (h el context) (out name local ns kids class inner count)
    (emit-ascii! out "<")
    (emit-tag-name! out local (fx= ns ns-svg))
    (emit-attributes! h count (not (fx= ns ns-html)))
    (emit-ascii! out ">")
    body ...))

;;; The class of the start tag of el in context and the context of its
;;; children, (values class inner), checked as with-start-tag checks it;
;;; nothing is written. For :std/text/markup/tal.
(def (start-tag-info (h       :- HTMLEmitter)
                     (el      :- XMLElement)
                     (context :- :fixnum)) => :values
  (with-checked-start-tag (h el context) (out name local ns kids class inner count)
    (values class inner)))

;;; Writes the children kids of an element named name (local) in
;;; namespace ns and of class class, written in context and whose children
;;; are in context inner; noscript elements of an emitter that is not
;;; scripting? count themselves open in h.noscript when count-noscript? is
;;; set.
(def (emit-element-children! (h               :- HTMLEmitter)
                             (out             :- basic-output-buffer)
                             (name            :- XMLName)
                             (local           :- :string)
                             (ns              :- :fixnum)
                             (kids            :- :list)
                             (class           :- :fixnum)
                             (context         :- :fixnum)
                             (inner           :- :fixnum)
                             (count-noscript? :- :boolean)) => :void
  (cond
   ((fx= class 0)
    (if (and (not (fx= ns ns-html))
             (or (fx= context context-free) h.html-read?))
      (emit-foreign-children! h local kids inner)
      (emit-children! h kids inner)))
   ((class-has? class class-void)
    (unless (null? kids)
      (raise-bad-argument write-html "void element without children" name)))
   ((or (class-has? class class-raw)
        (and (fx= class class-noscript) h.scripting?))
    (emit-raw-text! h local class kids))
   ((fx= class class-plaintext)
    (let (data (literal-text kids))
      (check-noscript! h data)
      (emit-html-string! out data literal-escapes)
      (set! h.ended? #t)))
   (else
    (when (and (class-has? class class-newline)
               (newline-first? kids))
      (emit-ascii! out "\n"))
    (cond
     ((class-has? class class-rcdata)
      (emit-rcdata! h kids))
     ((and count-noscript? (fx= class class-noscript))
      (set! h.noscript (fx+ h.noscript 1))
      (emit-children! h kids inner)
      (set! h.noscript (fx- h.noscript 1)))
     ((fx= class class-frameset)
      (set! h.ignored (fxmax h.ignored ignored-frameset))
      (emit-children! h kids inner))
     ((fx= class class-template)
      (emit-template-children! h kids inner))
     (else
      (emit-children! h kids inner))))))

;;; Writes the end tag of an element local in namespace ns, of class class.
(def (emit-element-end-tag! (h     :- HTMLEmitter)
                            (out   :- basic-output-buffer)
                            (local :- :string)
                            (ns    :- :fixnum)
                            (class :- :fixnum)) => :void
  (unless (or (class-has? class class-void) h.ended?)
    (emit-ascii! out "</")
    (emit-tag-name! out local (fx= ns ns-svg))
    (emit-ascii! out ">")))

(def (emit-element! (h       :- HTMLEmitter)
                    (el      :- XMLElement)
                    (context :- :fixnum)) => :void
  (with-start-tag (h el context) (out name local ns kids class inner)
    (emit-element-children! h out name local ns kids class context inner #t)
    (emit-element-end-tag! h out local ns class)))

(def (emit-children! (h       :- HTMLEmitter)
                     (kids    :- :list)
                     (context :- :fixnum)) => :void
  (let loop ((rest kids))
    (when (pair? rest)
      (emit-node! h (##car rest) context)
      (loop (##cdr rest)))))

;;; Writes the children of a foreign element at the top level, or below one
;;; outside a nested svg or math element: parsed in an HTML context (a
;;; fragment inserted into a body), these elements are HTML elements, so an
;;; element named like an HTML raw text, RCDATA or (scripting) noscript
;;; element must hold nothing that would end it early there.
(def (emit-foreign-children! (h     :- HTMLEmitter)
                             (local :- :string)
                             (kids  :- :list)
                             (inner :- :fixnum)) => :void
  (let ((outer h.html-read?)
        (class (element-class-of-name local)))
    (set! h.html-read? (not (or (string-same? local "svg") (string-same? local "math"))))
    (if (or (class-has? class class-raw)
            (class-has? class class-rcdata)
            (and (fx= class class-noscript) h.scripting?))
      (using ((sub (make-memory-output) :- memory-output-buffer)
              (h2 (make-HTMLEmitter sub h.scripting? h.noscript h.ended? h.ignored h.html-read?
                                    (vector))
                  :- HTMLEmitter))
        (emit-children! h2 kids inner)
        (set! h.ended? h2.ended?)
        (let (data (memory-output-string sub))
          (unless (raw-text-ends? local (class-has? class class-script) data)
            (raise-bad-argument write-html "foreign element content that does not end it when read as HTML"
                                local data))
          (emit-html-string! h.out data verbatim-escapes)))
      (emit-children! h kids inner))
    (set! h.html-read? outer)))

(def (column-element? (node :- XML)) => :boolean
  (and (XMLElement? node)
       (using (node :- XMLElement)
         (and (fx= (string-length node.name.uri) 0)
              (string-same? node.name.local "col")))))

;;; The children of a template: its contents start a new insertion mode,
;;; which a col child switches to column group (any col, conservatively:
;;; head elements before it keep the template mode). A template start tag is
;;; ignored in frameset modes, which then continue.
(def (emit-template-children! (h       :- HTMLEmitter)
                              (kids    :- :list)
                              (context :- :fixnum)) => :void
  (let (outer h.ignored)
    (unless (fx= outer ignored-frameset)
      (set! h.ignored ignored-none))
    (let loop ((rest kids))
      (when (pair? rest)
        (let (node (##car rest))
          (when (column-element? node)
            (set! h.ignored ignored-column-group))
          (emit-node! h node context)
          (loop (##cdr rest)))))
    (set! h.ignored outer)))

;;; Comment data the tokenizer reads back: not starting with > or ->, and
;;; without --> or --!> (NUL is rejected as it is written).
(def (emit-comment! (h    :- HTMLEmitter)
                    (node :- XMLComment)) => :void
  (let (data node.data)
    (when (or (and (fx> (##string-length data) 0) (eq? (##string-ref data 0) #\>))
              (and (fx> (##string-length data) 1)
                   (eq? (##string-ref data 0) #\-)
                   (eq? (##string-ref data 1) #\>))
              (string-contains data "-->")
              (string-contains data "--!>"))
      (raise-bad-argument write-html "comment data the parser reads back" data))
    (check-noscript! h data)
    (let (out h.out)
      (emit-ascii! out "<!--")
      (emit-html-string! out data literal-escapes)
      (emit-ascii! out "-->"))))

;;; A processing instruction the tokenizer reads back: the target an ASCII
;;; letter or _, then ASCII letters, digits, - or _, but not xml or
;;; xml-stylesheet (ASCII case-insensitively, which the parser reads as
;;; bogus comments); data without > and not starting with whitespace.
(def (emit-pi! (h    :- HTMLEmitter)
               (node :- XMLPI)) => :void
  (let ((target node.target)
        (data node.data))
    (unless (and (fx> (##string-length target) 0)
                 (let loop ((k 0))
                   (or (fx>= k (##string-length target))
                       (and (pi-target-code? (##char->integer (##string-ref target k)) (fx= k 0))
                            (loop (fx+ k 1)))))
                 (not (reserved-pi-target? target)))
      (raise-bad-argument write-html "processing instruction target the parser reads back" target))
    (when (or (string-index data #\>)
              (and (fx> (##string-length data) 0)
                   (html-space-code? (##char->integer (##string-ref data 0)))))
      (raise-bad-argument write-html "processing instruction data the parser reads back" data))
    (check-noscript! h data)
    (let (out h.out)
      (emit-ascii! out "<?")
      (emit-html-string! out target verbatim-escapes)
      (emit-ascii! out " ")
      (emit-html-string! out data verbatim-escapes)
      (emit-ascii! out "?>"))))

(def (emit-node! (h       :- HTMLEmitter)
                 (node    :- XML)
                 (context :- :fixnum)) => :void
  (when h.ended?
    (raise-bad-argument write-html "nothing after a plaintext element" node))
  (cond
   ((XMLText? node)
    (using (node :- XMLText)
      (emit-html-string! h.out node.data text-escapes)))
   ((XMLElement? node)
    (emit-element! h node context))
   ((XMLComment? node)
    (emit-comment! h node))
   ((HTMLRaw? node)
    (using (node :- HTMLRaw)
      (emit-html-string! h.out node.data verbatim-escapes)))
   ((XMLPI? node)
    (emit-pi! h node))
   (else
    (raise-bad-argument write-html "HTML node" node))))

;;; <!DOCTYPE name>, with PUBLIC "id" and/or SYSTEM "id" like Go's
;;; x/net/html; identifiers are quoted with ' when they contain ".
(def (emit-doctype! (h       :- HTMLEmitter)
                    (doctype :- HTMLDoctype)) => :void
  (let ((name doctype.name)
        (public-id doctype.public-id)
        (system-id doctype.system-id)
        (out h.out))
    (defrule (emit-id! id)
      (let (quote? (string-index id #\"))
        (if quote? (emit-ascii! out "'") (emit-ascii! out "\""))
        (emit-html-string! out id literal-escapes)
        (if quote? (emit-ascii! out "'") (emit-ascii! out "\""))))
    (emit-ascii! out "<!DOCTYPE ")
    (emit-html-string! out name literal-escapes)
    (when public-id
      (emit-ascii! out " PUBLIC ")
      (emit-id! public-id))
    (when system-id
      (if public-id
        (emit-ascii! out " ")
        (emit-ascii! out " SYSTEM "))
      (emit-id! system-id))
    (emit-ascii! out ">")))

;;; The children of a document: HTML nodes and its DOCTYPE.
(def (emit-document! (h   :- HTMLEmitter)
                     (doc :- HTMLDocument)) => :void
  (let loop ((rest doc.children))
    (when (pair? rest)
      (let (node (##car rest))
        (if (HTMLDoctype? node)
          (emit-doctype! h node)
          (emit-node! h node context-html))
        (loop (##cdr rest))))))

;;; Writes node: an HTMLDocument, an HTML node, or a list of HTML nodes (a
;;; fragment, a proper list as ./writer checks). The top-level elements of a
;;; node or fragment are written in their own namespace; their children must
;;; be what the parser makes of their start tags there.
(def (emit-html! (h    :- HTMLEmitter)
                 (node :- :t)) => :void
  (cond
   ((HTMLDocument? node) (emit-document! h node))
   ((or (pair? node) (null? node))
    (let loop ((rest node))
      (when (pair? rest)
        (emit-node! h (##car rest) context-free)
        (loop (##cdr rest)))))
   (else (emit-node! h node context-free))))

;;; html-escape

;;; Bytes added by escaping a character below #x80: & < > " ' as
;;; &amp; &lt; &gt; &quot; &#39;.
(def escape-growth
  (let (table (make-u8vector 128 0))
    (for-each (lambda (escape) (u8vector-set! table (char->integer (car escape)) (cdr escape)))
              '((#\& . 4) (#\< . 3) (#\> . 3) (#\" . 5) (#\' . 4)))
    table))

;;; str with & < > " ' escaped; str itself when it has none of them. The
;;; counting loop adds escape-growth and reads the length of str at each
;;; step: a case over the characters with the length as a loop variable
;;; instead took 8% more instructions and 11% more cycles
;;; (markup-benchmark.ss mode html-escape, SIZE 10000, ITERATIONS 6000), and
;;; 6% and 34% more on 20 characters (SIZE 20, ITERATIONS 2000000).
(def (html-escape-string (str :- :string)) => :string
  (let (growth (let loop ((k 0) (growth 0))
                 (if (fx< k (##string-length str))
                   (let (c (##char->integer (##string-ref str k)))
                     (loop (fx+ k 1)
                           (if (fx< c #x80)
                             (fx+ growth (##u8vector-ref escape-growth c))
                             growth)))
                   growth)))
    (if (fx= growth 0)
      str
      (let* ((n (##string-length str))
             (out (##make-string (fx+ n growth))))
        (defrule (put! j s)
          (let* ((escape s)
                 (m (##string-length escape)))
            (let copy ((k 0))
              (when (fx< k m)
                (##string-set! out (fx+ j k) (##string-ref escape k))
                (copy (fx+ k 1))))
            (fx+ j m)))
        (let loop ((k 0) (j 0))
          (if (fx< k n)
            (let (c (##string-ref str k))
              (loop (fx+ k 1)
                    (case c
                      ((#\&) (put! j "&amp;"))
                      ((#\<) (put! j "&lt;"))
                      ((#\>) (put! j "&gt;"))
                      ((#\") (put! j "&quot;"))
                      ((#\') (put! j "&#39;"))
                      (else
                       (##string-set! out j c)
                       (fx+ j 1)))))
            out))))))
