;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; The HTML rules that the parser (./scanner, ./builder), the writer
;;; (./emitter), the checked constructors (./types), :std/text/markup/tal
;;; and Djot share: element namespaces and how a start tag is read among an
;;; element's children, the start tags that close a p, the element
;;; categories that close elements and bound scopes, element classes and
;;; the tokenizer states of their content, the end of literal text, the
;;; tree builder's foreign name
;;; adjustments and the names attributes and DOCTYPEs are written with,
;;; HTML name syntax, ASCII case and whitespace, and the interned names of
;;; the known atoms. Rules only: each consumer keeps its own traversal.
;;; Internal; free of I/O, as :std/text/markup/tal runs it at expansion
;;; time.
(import ../xml/node
        (only-in ../scan-input ascii ascii-fold-code)
        ./atoms)
(export svg-namespace-uri
        mathml-namespace-uri
        xlink-namespace-uri
        ns-html
        ns-svg
        ns-mathml
        namespace-code
        namespace-uri
        context-free
        context-html
        context-svg
        context-text-point
        context-annotation
        child-context
        start-tag-namespace
        cdata-allowed?
        foreign-breakout-atom?
        foreign-breakout-name?
        font-breakout-attribute-atom?
        font-breakout-attributes?
        start-tag-closes-p?
        flag-special
        flag-scope
        flag-list-scope
        flag-button-scope
        flag-table-scope
        flag-implied
        flag-thorough
        flag-text-point
        flag-html-point
        flag-foster
        flag-heading
        flag-cell
        flag-section
        list-scope
        button-scope
        foreign-flags
        html-element-flags
        element-flags
        p-in-button-scope-after
        html-special-element?
        class-void
        class-raw
        class-script
        class-rcdata
        class-plaintext
        class-newline
        class-noscript
        class-frameset
        class-template
        class-has?
        element-class-of-atom
        element-class-of-name
        html-state-data
        html-state-rcdata
        html-state-rawtext
        html-state-script-data
        html-state-plaintext
        html-state-cdata
        class-tokenizer-state
        newline-first?
        script-text-ends?
        raw-text-ends?
        noscript-data-ok?
        foreign-attribute-names
        adjusted-element-local
        adjusted-foreign-attribute-name
        html-element-renamed?
        element-local-round-trips?
        foreign-attribute-local-round-trips?
        written-attribute-name
        html-doctype-name-ok?
        html-doctype-id-ok?
        html-tag-name?
        html-attribute-name?
        pi-target-code?
        reserved-pi-target?
        html-space-code?
        html-space-string?
        ascii-upper-in?
        ascii-downcase
        ascii-ci=?
        ascii-ci-prefix?
        known-name
        atom-vector)
(declare (not safe))

;;; known atoms

;;; XMLName of each known atom, in no namespace: the parser names elements
;;; and attributes with these, so equal known names are one object.
(def known-names
  (let (names (make-vector (fx+ known-atom-count 1) #f))
    (let loop ((k 1))
      (when (fx<= k known-atom-count)
        (vector-set! names k (unchecked-node XMLName (vector-ref known-atom-names k) "" ""))
        (loop (fx+ k 1))))
    names))

;;; The XMLName of known-names for atom, a known atom (atom-div): 1 ..
;;; known-atom-count, unchecked.
(definline (known-name (atom :- :fixnum)) => XMLName
  (:- (##vector-ref known-names atom) XMLName))

;;; A vector by atom, 0 .. known-atom-count, of the values of entries,
;;; (atom . value) pairs; absent for other atoms.
(def (atom-vector (entries :- :list)
                  (absent  :- :t := 0)) => :vector
  (let (table (make-vector (fx+ known-atom-count 1) absent))
    (for-each (lambda ((entry :- :pair)) (vector-set! table (car entry) (cdr entry))) entries)
    table))

;;; name tables: names to fixnums, in buckets by length, first and last
;;; character; a name missing from a table maps to 0. The writer looks up
;;; every element's name: list->hash-table-string tables read with hash-ref
;;; instead took 18% more instructions and 21% more cycles writing HTML
;;; (markup-benchmark.ss mode html-write-elements, SIZE 1000, ITERATIONS
;;; 300).

(definline (name-bucket (s :- :string)) => :fixnum
  (let (n (##string-length s))
    (fxand (fx+ (fx* n 5)
                (##char->integer (##string-ref s 0))
                (fx* 3 (##char->integer (##string-ref s (fx- n 1)))))
           63)))

;;; A name table of entries, (atom . value) pairs, keyed by the atoms' names.
(def (make-name-table (entries :- :list)) => :vector
  (let (table (make-vector 64 '()))
    (for-each (lambda ((entry :- :pair))
                (let* ((name (vector-ref known-atom-names (car entry)))
                       (k (name-bucket name)))
                  (vector-set! table k (cons (cons name (cdr entry)) (vector-ref table k)))))
              entries)
    table))

;;; The value of the non-empty name s in table, or 0. Inline: the writer
;;; looks up every element's name.
(definline (name-table-ref (table :- :vector)
                           (s     :- :string)) => :fixnum
  (:- (let loop ((rest (##vector-ref table (name-bucket s))))
        (if (pair? rest)
          (let (entry (##car rest))
            (if (string-same? (##car entry) s)
              (##cdr entry)
              (loop (##cdr rest))))
          0))
      :fixnum))

;;; ASCII whitespace and case: HTML folds and compares ASCII letters only,
;;; while the core -ci procedures (string-ci=?, string-contains-ci) fold
;;; Unicode case: (string-ci=? "\x212a;" "k") is true.

;;; TAB, LF, FF, CR or SPACE: ASCII whitespace in HTML.
(definline (html-space-code? (c :- :fixnum)) => :boolean
  (or (fx= c (ascii #\space)) (fx= c (ascii #\newline)) (fx= c (ascii #\tab))
      (fx= c #xc) (fx= c (ascii #\return))))

;;; True when str is all ASCII whitespace.
(def (html-space-string? (str :- :string)) => :boolean
  (let (n (##string-length str))
    (let loop ((k 0))
      (or (fx>= k n)
          (and (html-space-code? (##char->integer (##string-ref str k)))
               (loop (fx+ k 1)))))))

(def (ascii-upper-code? (c :- :fixnum)) => :boolean
  (and (fx>= c (ascii #\A)) (fx<= c (ascii #\Z))))

(def (ascii-upper-in? (str :- :string)) => :boolean
  (let (n (string-length str))
    (let loop ((k 0))
      (and (fx< k n)
           (or (ascii-upper-code? (char->integer (string-ref str k)))
               (loop (fx+ k 1)))))))

(def (ascii-downcase (str : :string)) => :string
  (let* ((n (string-length str))
         (out (make-string n)))
    (let loop ((k 0))
      (if (fx< k n)
        (begin
          (string-set! out k (integer->char (ascii-fold-code (char->integer (string-ref str k)))))
          (loop (fx+ k 1)))
        out))))

(def (ascii-ci=? (a :- :string)
                 (b :- :string)) => :boolean
  (and (fx= (string-length a) (string-length b))
       (ascii-ci-prefix? b a)))

;;; True when str starts with prefix, ASCII case-insensitively.
(def (ascii-ci-prefix? (prefix :- :string)
                       (str    :- :string)) => :boolean
  (let (n (string-length prefix))
    (and (fx<= n (string-length str))
         (let loop ((k 0))
           (or (fx>= k n)
               (and (fx= (ascii-fold-code (char->integer (string-ref prefix k)))
                         (ascii-fold-code (char->integer (string-ref str k))))
                    (loop (fx+ k 1))))))))

;;; True when str contains the string lower (lower case ASCII) ASCII
;;; case-insensitively, followed by tab, LF, FF, CR, space, / or > when tag?
;;; is set.
;;; Not string-contains-ci, which folds Unicode: it finds "</script" in
;;; "</\x17f;cript", where the tokenizer sees no end tag.
(def (contains-ci? (str   :- :string)
                   (lower :- :string)
                   (tag?  :- :boolean)) => :boolean
  (let ((n (##string-length str))
        (m (##string-length lower)))
    (let loop ((i 0))
      (and (fx<= (fx+ i m) n)
           (or (and (let match ((k 0))
                      (or (fx>= k m)
                          (and (fx= (ascii-fold-code (##char->integer (##string-ref str (fx+ i k))))
                                    (##char->integer (##string-ref lower k)))
                               (match (fx+ k 1)))))
                    (or (not tag?)
                        (and (fx< (fx+ i m) n)
                             (let (c (##char->integer (##string-ref str (fx+ i m))))
                               (or (html-space-code? c)
                                   (fx= c (ascii #\/)) (fx= c (ascii #\>)))))))
               (loop (fx+ i 1)))))))

;;; names

(def (ascii-alpha-code? (c :- :fixnum)) => :boolean
  (or (and (fx>= c (ascii #\a)) (fx<= c (ascii #\z)))
      (and (fx>= c (ascii #\A)) (fx<= c (ascii #\Z)))))

;;; A tag name the tokenizer reads back as one name: an ASCII letter, then no
;;; whitespace, /, > or NUL.
(def (html-tag-name? (str : :string)) => :boolean
  (let (n (string-length str))
    (and (fx> n 0)
         (ascii-alpha-code? (char->integer (string-ref str 0)))
         (let loop ((k 1))
           (or (fx>= k n)
               (let (c (char->integer (string-ref str k)))
                 (and (not (html-space-code? c))
                      (not (fx= c (ascii #\/)))
                      (not (fx= c (ascii #\>)))
                      (not (fx= c 0))
                      (loop (fx+ k 1)))))))))

;;; Unicode noncharacters: U+FDD0..U+FDEF and the last two code points of
;;; every plane.
(def (noncharacter-code? (c :- :fixnum)) => :boolean
  (or (and (fx>= c #xfdd0) (fx<= c #xfdef))
      (fx= (fxand c #xfffe) #xfffe)))

;;; 1 for the characters below #x80 an attribute name cannot hold: controls,
;;; SPACE, " ' / = > and DEL.
(def attribute-name-invalid
  (let (table (make-u8vector #x80 0))
    (let loop ((c 0))
      (when (fx< c #x21)
        (u8vector-set! table c 1)
        (loop (fx+ c 1))))
    (for-each (lambda (c) (u8vector-set! table c 1)) [#x22 #x27 #x2f #x3d #x3e #x7f])
    table))

;;; An attribute name of the HTML syntax: one or more characters other than
;;; controls, SPACE, " ' > / = and noncharacters.
(def (html-attribute-name? (str : :string)) => :boolean
  (let (n (string-length str))
    (and (fx> n 0)
         (let loop ((k 0))
           (or (fx>= k n)
               (let (c (char->integer (string-ref str k)))
                 (and (if (fx< c #x80)
                        (fx= (##u8vector-ref attribute-name-invalid c) 0)
                        (not (or (fx<= c #x9f) (noncharacter-code? c))))
                      (loop (fx+ k 1)))))))))

;;; A code a processing instruction target can hold, as its first character
;;; when first?: an ASCII letter or _, then also ASCII digits and -.
(def (pi-target-code? (c      :- :fixnum)
                      (first? :- :boolean)) => :boolean
  (or (ascii-alpha-code? c)
      (fx= c (ascii #\_))
      (and (not first?)
           (or (and (fx>= c (ascii #\0)) (fx<= c (ascii #\9)))
               (fx= c (ascii #\-))))))

;;; The targets the tokenizer reads as bogus comments, ASCII
;;; case-insensitively.
(def (reserved-pi-target? (target :- :string)) => :boolean
  (or (ascii-ci=? target "xml")
      (ascii-ci=? target "xml-stylesheet")))

;;; An annotation-xml start tag with this encoding is an HTML integration point.
(def (html-encoding? (value :? :string)) => :boolean
  (and value
       (or (ascii-ci=? value "text/html")
           (ascii-ci=? value "application/xhtml+xml"))))

;;; namespaces of elements, as codes

(def svg-namespace-uri "http://www.w3.org/2000/svg")
(def mathml-namespace-uri "http://www.w3.org/1998/Math/MathML")
(def xlink-namespace-uri "http://www.w3.org/1999/xlink")

(defconst ns-html 0)
(defconst ns-svg 1)
(defconst ns-mathml 2)

;;; The code of an element namespace URI ("" for HTML), or -1.
(definline (namespace-code (uri :- :string)) => :fixnum
  (cond
   ((fx= (##string-length uri) 0) ns-html)
   ((string-same? uri svg-namespace-uri) ns-svg)
   ((string-same? uri mathml-namespace-uri) ns-mathml)
   (else -1)))

(def (namespace-uri (ns :- :fixnum)) => :string
  (cond
   ((fx= ns ns-svg) svg-namespace-uri)
   ((fx= ns ns-mathml) mathml-namespace-uri)
   (else "")))

;;; contexts: how the tree builder reads a start tag among an element's
;;; children

(defconst context-free -1)       ; top-level node of a fragment: any namespace
(defconst context-html 0)        ; HTML content: svg and math switch
(defconst context-svg 1)         ; SVG content
(defconst context-mathml 2)      ; MathML content
(defconst context-text-point 3)  ; MathML text integration point: HTML, but
                                 ; mglyph and malignmark stay MathML
(defconst context-annotation 4)  ; annotation-xml, not an HTML integration
                                 ; point: MathML, but svg switches

;;; The context of the children of an element of namespace ns named local
;;; (as adjusted: foreignObject): integration points read HTML. encoding,
;;; evaluated only for annotation-xml, is the value of its encoding
;;; attribute, or #f.
(defrule (child-context ns local encoding)
  (let ((n ns) (l local))
    (cond
     ((fx= n ns-html) context-html)
     ((fx= n ns-svg)
      (if (or (string-same? l "foreignObject") (string-same? l "desc") (string-same? l "title"))
        context-html
        context-svg))
     ((or (string-same? l "mi") (string-same? l "mo") (string-same? l "mn")
          (string-same? l "ms") (string-same? l "mtext"))
      context-text-point)
     ((string-same? l "annotation-xml")
      (if (html-encoding? encoding) context-html context-annotation))
     (else context-mathml))))

;;; Start tags that leave foreign content, and font with color, face or
;;; size.
(def foreign-breakout-entries
  (map (cut cons <> 1)
       [atom-b atom-big atom-blockquote atom-body atom-br atom-center atom-code atom-dd
        atom-div atom-dl atom-dt atom-em atom-embed atom-h1 atom-h2 atom-h3 atom-h4
        atom-h5 atom-h6 atom-head atom-hr atom-i atom-img atom-li atom-listing atom-menu
        atom-meta atom-nobr atom-ol atom-p atom-pre atom-ruby atom-s atom-small atom-span
        atom-strong atom-strike atom-sub atom-sup atom-table atom-tt atom-u atom-ul
        atom-var]))

(def foreign-breakout-atoms (atom-vector foreign-breakout-entries))
(def foreign-breakout-names (make-name-table foreign-breakout-entries))

(definline (foreign-breakout-atom? (atom :- :fixnum)) => :boolean
  (and (fx<= atom known-atom-count) (fx= (##vector-ref foreign-breakout-atoms atom) 1)))

(definline (foreign-breakout-name? (str :- :string)) => :boolean
  (fx= (name-table-ref foreign-breakout-names str) 1))

;;; The attributes that take a font start tag out of foreign content, by
;;; atom; ./scanner applies the rule to the tokenizer's start tag
;;; (html-font-breakout-token?), font-breakout-attributes? to an element's
;;; attributes.
(def font-breakout-attribute-entries
  (map (cut cons <> 1) [atom-color atom-face atom-size]))

(def font-breakout-attribute-atoms (atom-vector font-breakout-attribute-entries))
(def font-breakout-attribute-names (make-name-table font-breakout-attribute-entries))

(definline (font-breakout-attribute-atom? (atom :- :fixnum)) => :boolean
  (and (fx<= atom known-atom-count) (fx= (##vector-ref font-breakout-attribute-atoms atom) 1)))

;;; True when attrs, the attributes (XMLAttribute) of a font start tag,
;;; take it out of foreign content: one in no namespace is named as a
;;; font-breakout-attribute-atom?.
(def (font-breakout-attributes? (attrs :- :list)) => :boolean
  (let loop ((rest attrs))
    (and (pair? rest)
         (using (attr (##car rest) :- XMLAttribute)
           (or (let (local attr.name.local)
                 (and (fx= (##string-length attr.name.uri) 0)
                      (fx> (##string-length local) 0)
                      (fx= (name-table-ref font-breakout-attribute-names local) 1)))
               (loop (##cdr rest)))))))

;;; The namespace the tree builder gives a start tag local among the
;;; children of an element of context context, or -1 when the start tag
;;; leaves foreign content: the foreign breakout names, and font when
;;; font-breakout? (font-breakout-attributes?).
(definline (start-tag-namespace (context        :- :fixnum)
                                (local          :- :string)
                                (font-breakout? :- :boolean)) => :fixnum
  (defrule (html-rules)
    (cond
     ((string-same? local "svg") ns-svg)
     ((string-same? local "math") ns-mathml)
     (else ns-html)))
  (defrule (foreign-rules ns)
    (if (or (foreign-breakout-name? local) font-breakout?) -1 ns))
  (cond
   ((fx= context context-html) (html-rules))
   ((fx= context context-svg) (foreign-rules ns-svg))
   ((fx= context context-mathml) (foreign-rules ns-mathml))
   ((fx= context context-text-point)
    (if (or (string-same? local "mglyph") (string-same? local "malignmark"))
      ns-mathml
      (html-rules)))
   ((string-same? local "svg") ns-svg)
   (else (foreign-rules ns-mathml))))

;;; The HTML start tags that close a p element in button scope in the "in
;;; body" insertion mode (§13.2.6.4.7) in every context.
(def p-closing-atoms
  (atom-vector
   (map (cut cons <> 1)
        [atom-address atom-article atom-aside atom-blockquote atom-center atom-details
         atom-dialog atom-dir atom-div atom-dl atom-fieldset atom-figcaption atom-figure
         atom-footer atom-header atom-hgroup atom-main atom-menu atom-nav atom-ol atom-p
         atom-search atom-section atom-summary atom-ul atom-h1 atom-h2 atom-h3 atom-h4
         atom-h5 atom-h6 atom-pre atom-listing atom-li atom-dd atom-dt atom-plaintext
         atom-hr atom-xmp])))

;;; True when the "in body" start tag of the HTML element atom closes a p
;;; element in button scope. The context decides two: table closes it
;;; unless the document is in quirks mode (quirks?), and form unless the
;;; tree builder ignores the start tag (form-ignored?: the form element
;;; pointer is set and the template contents are not being parsed). li, dd
;;; and dt close it after the list item steps.
(definline (start-tag-closes-p? (atom          :- :fixnum)
                                (quirks?       :- :boolean)
                                (form-ignored? :- :boolean)) => :boolean
  (cond
   ((fx= atom atom-table) (not quirks?))
   ((fx= atom atom-form) (not form-ignored?))
   (else (and (fx<= atom known-atom-count) (fx= (##vector-ref p-closing-atoms atom) 1)))))

;;; Whether <![CDATA[ opens a CDATA section where the adjusted current node
;;; is in namespace ns (§13.2.5.42): in foreign content, integration points
;;; included.
(definline (cdata-allowed? (ns :- :fixnum)) => :boolean
  (not (fx= ns ns-html)))

;;; element categories: how the tree builder closes elements and bounds
;;; its scopes, as bits of an element's flags

(defconst flag-special 1)
(defconst flag-scope 2)          ; ends "in scope" (and list item and button scope)
(defconst flag-list-scope 4)     ; ol, ul: end "in list item scope"
(defconst flag-button-scope 8)   ; button: ends "in button scope"
(defconst flag-table-scope 16)   ; html, table, template: end "in table scope"
(defconst flag-implied 32)       ; closed by "generate implied end tags"
(defconst flag-thorough 64)      ; ... "thoroughly"
(defconst flag-text-point 128)   ; MathML text integration point
(defconst flag-html-point 256)   ; HTML integration point
(defconst flag-foster 512)       ; table, tbody, tfoot, thead, tr
(defconst flag-heading 1024)     ; h1 .. h6
(defconst flag-cell 2048)        ; td, th
(defconst flag-section 4096)     ; tbody, tfoot, thead

(defconst list-scope 6)          ; flag-scope, flag-list-scope
(defconst button-scope 10)       ; flag-scope, flag-button-scope

;;; Flags of the HTML elements, by atom.
(def html-flags
  (let (flags (make-vector (fx+ known-atom-count 1) 0))
    (def (add! atoms flag)
      (for-each (lambda (atom)
                  (vector-set! flags atom (fxior (vector-ref flags atom) flag)))
                atoms))
    (add! [atom-address atom-applet atom-area atom-article atom-aside atom-base
           atom-basefont atom-bgsound atom-blockquote atom-body atom-br atom-button
           atom-caption atom-center atom-col atom-colgroup atom-dd atom-details
           atom-dir atom-div atom-dl atom-dt atom-embed atom-fieldset atom-figcaption
           atom-figure atom-footer atom-form atom-frame atom-frameset atom-h1 atom-h2
           atom-h3 atom-h4 atom-h5 atom-h6 atom-head atom-header atom-hgroup atom-hr
           atom-html atom-iframe atom-img atom-input atom-keygen atom-li atom-link
           atom-listing atom-main atom-marquee atom-menu atom-meta atom-nav
           atom-noembed atom-noframes atom-noscript atom-object atom-ol atom-p
           atom-param atom-plaintext atom-pre atom-script atom-search atom-section
           atom-select atom-source atom-style atom-summary atom-table atom-tbody
           atom-td atom-template atom-textarea atom-tfoot atom-th atom-thead
           atom-title atom-tr atom-track atom-ul atom-wbr atom-xmp]
          flag-special)
    (add! [atom-applet atom-caption atom-html atom-table atom-td atom-th atom-marquee
           atom-object atom-select atom-template]
          flag-scope)
    (add! [atom-ol atom-ul] flag-list-scope)
    (add! [atom-button] flag-button-scope)
    (add! [atom-html atom-table atom-template] flag-table-scope)
    (add! [atom-dd atom-dt atom-li atom-optgroup atom-option atom-p atom-rb atom-rp
           atom-rt atom-rtc]
          (fxior flag-implied flag-thorough))
    (add! [atom-caption atom-colgroup atom-tbody atom-td atom-tfoot atom-th atom-thead
           atom-tr]
          flag-thorough)
    (add! [atom-table atom-tbody atom-tfoot atom-thead atom-tr] flag-foster)
    (add! [atom-h1 atom-h2 atom-h3 atom-h4 atom-h5 atom-h6] flag-heading)
    (add! [atom-td atom-th] flag-cell)
    (add! [atom-tbody atom-tfoot atom-thead] flag-section)
    flags))

;;; Flags of a foreign element of namespace ns named local (as adjusted)
;;; whose encoding attribute has value encoding (or #f), from the context
;;; of its children: the integration points are special and bound scopes,
;;; as is annotation-xml.
(def (foreign-flags (ns       :- :fixnum)
                    (local    :- :string)
                    (encoding :? :string)) => :fixnum
  (let (inner (child-context ns local encoding))
    (cond
     ((fx= inner context-html) (fxior flag-special flag-scope flag-html-point))
     ((fx= inner context-text-point) (fxior flag-special flag-scope flag-text-point))
     ((fx= inner context-annotation) (fxior flag-special flag-scope))
     (else 0))))

(definline (html-element-flags (atom :- :fixnum)) => :fixnum
  (if (fx<= atom known-atom-count) (##vector-ref html-flags atom) 0))

;;; Flags of an element of namespace ns whose start tag has folded name
;;; atom.
(def (element-flags (ns       :- :fixnum)
                    (atom     :- :fixnum)
                    (encoding :? :string)) => :fixnum
  (cond
   ((fx= ns ns-html) (html-element-flags atom))
   ((fx<= atom known-atom-count)
    (foreign-flags ns (adjusted-element-local ns (##vector-ref known-atom-names atom)) encoding))
   (else 0)))

;;; Whether an HTML p is in button scope when an element of namespace ns,
;;; atom atom and flags flags (element-flags) is the current node, from
;;; below?, whether one is for the element below it: a p sets it, an
;;; element that bounds button scope (a p below it is not closed by the
;;; start tags above) clears it, any other element keeps it.
(definline (p-in-button-scope-after (ns     :- :fixnum)
                                    (atom   :- :fixnum)
                                    (flags  :- :fixnum)
                                    (below? :- :boolean)) => :boolean
  (cond
   ((and (fx= ns ns-html) (fx= atom atom-p)) #t)
   (below? (fx= (fxand flags button-scope) 0))
   (else #f)))

;;; True when an element of flags flags (element-flags) is in the special
;;; category, where the list item steps of an li, dd or dt start tag stop
;;; unless it is address, div or p.
(def (html-special-element? (flags :- :fixnum)) => :boolean
  (not (fx= (fxand flags flag-special) 0)))

;;; element classes: how an HTML element is serialized and its content
;;; tokenized, as bits

(defconst class-void 1)          ; no end tag, no children
(defconst class-raw 2)           ; text written literally, checked for its end tag
(defconst class-script 4)        ; raw, and checked for script escapes
(defconst class-rcdata 8)        ; text only, escaped
(defconst class-plaintext 16)    ; text written literally, then nothing
(defconst class-newline 32)      ; the parser drops a newline after the start tag
(defconst class-noscript 64)     ; raw when scripting?
(defconst class-frameset 128)
(defconst class-template 256)

;;; True when the element class class has the bits of bit.
(definline (class-has? (class :- :fixnum)
                       (bit   :- :fixnum)) => :boolean
  (fx= (fxand class bit) bit))

;;; Void: the WHATWG void elements and the elements that serialize as void,
;;; which the parser also reads without end tag. Not legacy's command: the
;;; parser reads it as an ordinary element.
(def element-class-entries
  (append
   (map (cut cons <> class-void)
        [atom-area atom-base atom-br atom-col atom-embed atom-hr atom-img atom-input
         atom-link atom-meta atom-source atom-track atom-wbr atom-basefont atom-bgsound
         atom-frame atom-keygen atom-param])
   (map (cut cons <> class-raw)
        [atom-style atom-xmp atom-iframe atom-noembed atom-noframes])
   [(cons atom-script (fxior class-raw class-script))
    (cons atom-plaintext class-plaintext)
    (cons atom-title class-rcdata)
    (cons atom-textarea (fxior class-rcdata class-newline))
    (cons atom-pre class-newline)
    (cons atom-listing class-newline)
    (cons atom-noscript class-noscript)
    (cons atom-frameset class-frameset)
    (cons atom-template class-template)]))

(def element-classes-by-atom (atom-vector element-class-entries))
(def html-element-classes (make-name-table element-class-entries))

;;; The class of the HTML element with folded name atom atom.
(definline (element-class-of-atom (atom :- :fixnum)) => :fixnum
  (if (fx<= atom known-atom-count) (:- (##vector-ref element-classes-by-atom atom) :fixnum) 0))

;;; The class of the HTML element named str (not empty).
(definline (element-class-of-name (str :- :string)) => :fixnum
  (name-table-ref html-element-classes str))

;;; tokenizer states the content of an element starts in
(defconst html-state-data 0)
(defconst html-state-rcdata 1)
(defconst html-state-rawtext 2)
(defconst html-state-script-data 3)
(defconst html-state-plaintext 4)
(defconst html-state-cdata 5)

;;; The state the tokenizer reads the content of an element of class class
;;; in; noscript content is raw text when scripting?.
(def (class-tokenizer-state (class      :- :fixnum)
                            (scripting? :- :boolean)) => :fixnum
  (cond
   ((class-has? class class-script) html-state-script-data)
   ((class-has? class class-raw) html-state-rawtext)
   ((class-has? class class-rcdata) html-state-rcdata)
   ((fx= class class-plaintext) html-state-plaintext)
   ((and (fx= class class-noscript) scripting?) html-state-rawtext)
   (else html-state-data)))

;;; True when kids, the children of an element of class class-newline,
;;; start with text whose first character is LF or CR (read as LF), after
;;; any empty text nodes: the parser would drop that LF after the start tag
;;; unless another LF precedes it.
(def (newline-first? (kids :- :list)) => :boolean
  (let loop ((rest kids))
    (and (pair? rest)
         (let (node (##car rest))
           (and (XMLText? node)
                (using (node :- XMLText)
                  (let (data node.data)
                    (if (fx= (##string-length data) 0)
                      (loop (##cdr rest))
                      (let (c (##string-ref data 0))
                        (or (eq? c #\newline) (eq? c #\return)))))))))))

;;; literal text

;;; script data states of the tokenizer (§13.2.5.4, .15-.31)
(defconst script-data 0)
(defconst script-lt 1)                   ; <
(defconst script-end-open 2)             ; </
(defconst script-end-name 3)             ; </ letters
(defconst script-escape-start 4)         ; <!
(defconst script-escape-start-dash 5)    ; <!-
(defconst script-escaped 6)
(defconst script-escaped-dash 7)
(defconst script-escaped-dash-dash 8)
(defconst script-escaped-lt 9)
(defconst script-escaped-end-open 10)
(defconst script-escaped-end-name 11)
(defconst script-double-start 12)        ; escaped < letters
(defconst script-double 13)
(defconst script-double-dash 14)
(defconst script-double-dash-dash 15)
(defconst script-double-lt 16)
(defconst script-double-end 17)          ; double escaped </ letters

;;; True when the script text data, followed by </script>, is script data up
;;; to exactly that end tag: run through the tokenizer's script data states,
;;; no end tag ends it early, and it does not leave the tokenizer in the
;;; double escaped state, where </script> does not end the script. The
;;; tokenizer (./scanner scan-script) scans the same states, but over UTF-8
;;; bytes up to a 0 sentinel on the reader's path, while the writer and TAL
;;; ask this question of a string; the two are kept separate, and a seeded
;;; differential test (./rules-test) checks that they agree.
(def (script-text-ends? (data :- :string)) => :boolean
  (let ((n (##string-length data))
        (end-tag "</script>"))
    (defrule (alpha? c)
      (let (x (ascii-fold-code c)) (and (fx>= x (ascii #\a)) (fx<= x (ascii #\z)))))
    ;; buffer: the letters after < or </, as a count of matched "script"
    ;; letters, or -1 after a mismatch
    (def (append-letter buffer c)
      (if (and (fx>= buffer 0) (fx< buffer 6)
               (fx= (ascii-fold-code c) (##char->integer (##string-ref "script" buffer))))
        (fx+ buffer 1)
        -1))
    (let loop ((i 0) (state script-data) (buffer 0))
      (let (c (cond
               ((fx< i n) (##char->integer (##string-ref data i)))
               ((fx< i (fx+ n 9)) (##char->integer (##string-ref end-tag (fx- i n))))
               (else -1)))
        (defrule (next state) (loop (fx+ i 1) state buffer))
        (defrule (again state) (loop i state buffer))
        (cond
         ((fx< c 0) #f)
         ((fx= state script-data)
          (next (if (fx= c (ascii #\<)) script-lt script-data)))
         ((fx= state script-lt)
          (cond
           ((fx= c (ascii #\/)) (loop (fx+ i 1) script-end-open 0))
           ((fx= c (ascii #\!)) (next script-escape-start))
           (else (again script-data))))
         ((or (fx= state script-end-open) (fx= state script-escaped-end-open))
          (let (name (if (fx= state script-end-open) script-end-name script-escaped-end-name))
            (if (alpha? c)
              (again name)
              (again (if (fx= state script-end-open) script-data script-escaped)))))
         ((or (fx= state script-end-name) (fx= state script-escaped-end-name))
          (cond
           ((alpha? c) (loop (fx+ i 1) state (append-letter buffer c)))
           ((and (fx= buffer 6) (or (html-space-code? c) (fx= c (ascii #\/)) (fx= c (ascii #\>))))
            ;; an end tag: ours, at the last character, or one in data
            (fx= i (fx+ n 8)))
           (else (again (if (fx= state script-end-name) script-data script-escaped)))))
         ((fx= state script-escape-start)
          (if (fx= c (ascii #\-)) (next script-escape-start-dash) (again script-data)))
         ((fx= state script-escape-start-dash)
          (if (fx= c (ascii #\-)) (next script-escaped-dash-dash) (again script-data)))
         ((or (fx= state script-escaped) (fx= state script-escaped-dash)
              (fx= state script-escaped-dash-dash))
          (cond
           ((fx= c (ascii #\-))
            (next (if (fx= state script-escaped) script-escaped-dash script-escaped-dash-dash)))
           ((fx= c (ascii #\<)) (next script-escaped-lt))
           ((and (fx= c (ascii #\>)) (fx= state script-escaped-dash-dash)) (next script-data))
           (else (next script-escaped))))
         ((fx= state script-escaped-lt)
          (cond
           ((fx= c (ascii #\/)) (loop (fx+ i 1) script-escaped-end-open 0))
           ((alpha? c) (loop i script-double-start 0))
           (else (again script-escaped))))
         ((or (fx= state script-double-start) (fx= state script-double-end))
          (cond
           ((or (html-space-code? c) (fx= c (ascii #\/)) (fx= c (ascii #\>)))
            (next (if (eq? (fx= buffer 6) (fx= state script-double-start))
                    script-double
                    script-escaped)))
           ((alpha? c) (loop (fx+ i 1) state (append-letter buffer c)))
           (else (again (if (fx= state script-double-start) script-escaped script-double)))))
         ((fx= state script-double-lt)
          (if (fx= c (ascii #\/)) (loop (fx+ i 1) script-double-end 0) (again script-double)))
         (else                          ; double escaped, dash, dash dash
          (cond
           ((fx= c (ascii #\-))
            (next (if (fx= state script-double) script-double-dash script-double-dash-dash)))
           ((fx= c (ascii #\<)) (next script-double-lt))
           ((and (fx= c (ascii #\>)) (fx= state script-double-dash-dash)) (next script-data))
           (else (next script-double)))))))))

;;; True when data, the text of a raw text element local (script?: a script
;;; element) written literally, ends exactly at the end tag written after
;;; it: </local followed by whitespace, / or > in data ends the element
;;; early, and a script's text may also leave the tokenizer in a state where
;;; </script> does not end it (script-text-ends?).
(def (raw-text-ends? (local   :- :string)
                     (script? :- :boolean)
                     (data    :- :string)) => :boolean
  (if script?
    (script-text-ends? data)
    (not (contains-ci? data (string-append "</" local) #t))))

;;; True when data can be written literally inside a noscript element, which
;;; a scripting parser reads as raw text: no </noscript.
(def (noscript-data-ok? (data :- :string)) => :boolean
  (not (contains-ci? data "</noscript" #f)))

;;; foreign names: the tree builder's case adjustments and namespaced
;;; attributes

;;; SVG tag names whose case the tree builder adjusts, by folded name.
(def svg-tag-names
  (list->hash-table-string
   (map (lambda (name) (cons (string-downcase name) name))
        ["altGlyph" "altGlyphDef" "altGlyphItem" "animateColor" "animateMotion"
         "animateTransform" "clipPath" "feBlend" "feColorMatrix" "feComponentTransfer"
         "feComposite" "feConvolveMatrix" "feDiffuseLighting" "feDisplacementMap"
         "feDistantLight" "feDropShadow" "feFlood" "feFuncA" "feFuncB" "feFuncG"
         "feFuncR" "feGaussianBlur" "feImage" "feMerge" "feMergeNode" "feMorphology"
         "feOffset" "fePointLight" "feSpecularLighting" "feSpotLight" "feTile"
         "feTurbulence" "foreignObject" "glyphRef" "linearGradient" "radialGradient"
         "textPath"])))

;;; XMLName of the SVG attributes whose case is adjusted, by folded name.
(def svg-attribute-names
  (list->hash-table-string
   (map (lambda (name) (cons (string-downcase name) (unchecked-node XMLName name "" "")))
        ["attributeName" "attributeType" "baseFrequency" "baseProfile" "calcMode"
         "clipPathUnits" "diffuseConstant" "edgeMode" "filterUnits" "glyphRef"
         "gradientTransform" "gradientUnits" "kernelMatrix" "kernelUnitLength"
         "keyPoints" "keySplines" "keyTimes" "lengthAdjust" "limitingConeAngle"
         "markerHeight" "markerUnits" "markerWidth" "maskContentUnits" "maskUnits"
         "numOctaves" "pathLength" "patternContentUnits" "patternTransform"
         "patternUnits" "pointsAtX" "pointsAtY" "pointsAtZ" "preserveAlpha"
         "preserveAspectRatio" "primitiveUnits" "refX" "refY" "repeatCount"
         "repeatDur" "requiredExtensions" "requiredFeatures" "specularConstant"
         "specularExponent" "spreadMethod" "startOffset" "stdDeviation"
         "stitchTiles" "surfaceScale" "systemLanguage" "tableValues" "targetX"
         "targetY" "textLength" "viewBox" "viewTarget" "xChannelSelector"
         "yChannelSelector" "zoomAndPan"])))

(def mathml-definitionurl (unchecked-node XMLName "definitionURL" "" ""))

;;; XMLName of the namespaced attributes of foreign elements, by token name.
(def foreign-attribute-names
  (list->hash-table-string
   (append
    (map (lambda (local)
           (cons (string-append "xlink:" local) (unchecked-node XMLName local xlink-namespace-uri "xlink")))
         ["actuate" "arcrole" "href" "role" "show" "title" "type"])
    [(cons "xml:lang" (unchecked-node XMLName "lang" xml-namespace-uri "xml"))
     (cons "xml:space" (unchecked-node XMLName "space" xml-namespace-uri "xml"))
     (cons "xmlns" (unchecked-node XMLName "xmlns" xmlns-namespace-uri ""))
     (cons "xmlns:xlink" (unchecked-node XMLName "xlink" xmlns-namespace-uri "xmlns"))])))

;;; The local name the tree builder gives an element of namespace ns whose
;;; start tag is named folded (ASCII lower case).
(def (adjusted-element-local (ns     :- :fixnum)
                             (folded :- :string)) => :string
  (or (and (fx= ns ns-svg) (hash-get svg-tag-names folded))
      folded))

;;; The name the tree builder gives an attribute named folded (as tokenized:
;;; ASCII lower case) of a foreign element of namespace ns, or #f when it
;;; keeps the name in no namespace.
(def (adjusted-foreign-attribute-name (ns     :- :fixnum)
                                      (folded :- :string)) => (Maybe XMLName)
  (and (not (fx= ns ns-html))
       (or (and (fx= ns ns-svg) (hash-get svg-attribute-names folded))
           (and (fx= ns ns-mathml) (string=? folded "definitionurl") mathml-definitionurl)
           (hash-get foreign-attribute-names folded))))

;;; True when the tree builder reads an HTML element named local (in lower
;;; case) as another element: image as img.
(definline (html-element-renamed? (local :- :string)) => :boolean
  (string-same? local "image"))

;;; True when a tag name local, read back by the tokenizer (which folds
;;; ASCII case) and the tree builder (which adjusts SVG names and renames
;;; some HTML elements), names an element of namespace uri local again: no
;;; ASCII upper case, except the adjusted SVG spellings, which have no lower
;;; case form.
(def (element-local-round-trips? (uri   :- :string)
                                 (local :- :string)) => :boolean
  (cond
   ((ascii-upper-in? local)
    (and (string=? uri svg-namespace-uri)
         (equal? (hash-get svg-tag-names (ascii-downcase local)) local)))
   ((fx= (string-length uri) 0)
    (not (html-element-renamed? local)))
   (else
    (not (and (string=? uri svg-namespace-uri)
              (hash-get svg-tag-names local))))))

;;; True when an attribute named local in no namespace, on an SVG or MathML
;;; element of namespace uri, reads back as itself: the tree builder adjusts
;;; the case of some names and puts xlink:, xml: and xmlns names in their
;;; namespaces.
(def (foreign-attribute-local-round-trips? (uri   :- :string)
                                           (local :- :string)) => :boolean
  (let (folded (if (ascii-upper-in? local) (ascii-downcase local) local))
    (and (not (hash-get foreign-attribute-names folded))
         (string=? local
                   (cond
                    ((and (string=? uri svg-namespace-uri)
                          (hash-get svg-attribute-names folded))
                     => XMLName-local)
                    ((and (string=? uri mathml-namespace-uri)
                          (string=? folded "definitionurl"))
                     "definitionURL")
                    (else folded))))))

;;; (XMLName . written name) of the namespaced foreign attributes.
(def foreign-attribute-qnames
  (hash-map (lambda (qname name) (cons name qname)) foreign-attribute-names))

;;; The written name of a namespaced attribute of an SVG or MathML element,
;;; named as the tree builder names it (xlink:href in the XLink namespace
;;; with prefix xlink, xmlns in the XMLNS namespace with prefix ""), or #f.
(def (foreign-attribute-qname (uri    :- :string)
                              (local  :- :string)
                              (prefix :- :string)) => (Maybe :string)
  (let loop ((rest foreign-attribute-qnames))
    (and (pair? rest)
         (using (name (caar rest) :- XMLName)
           (if (and (string=? uri name.uri)
                    (string=? local name.local)
                    (string=? prefix name.prefix))
             (cdar rest)
             (loop (cdr rest)))))))

;;; The name an attribute named uri, local and prefix of an element of
;;; namespace element-uri is written with so that the parser reads it back
;;; on that element, or #f. HTML elements take attributes in no namespace
;;; whose names have no ASCII upper case, which the tokenizer folds:
;;; html-case-ok? is that check, which the writer makes as it writes the
;;; name instead (./emitter). SVG and MathML elements take the XLink, XML
;;; and XMLNS attributes the tree builder makes (xlink:href), and in no
;;; namespace only names whose case it does not adjust otherwise (viewBox,
;;; never viewbox).
(definline (written-attribute-name (element-uri   :- :string)
                                   (uri           :- :string)
                                   (local         :- :string)
                                   (prefix        :- :string)
                                   (html-case-ok? :- :boolean)) => (Maybe :string)
  (let (html? (fx= (##string-length element-uri) 0))
    (cond
     ((and (fx= (##string-length uri) 0) (fx= (##string-length prefix) 0))
      (and (if html?
             html-case-ok?
             (foreign-attribute-local-round-trips? element-uri local))
           local))
     (html? #f)
     (else (foreign-attribute-qname uri local prefix)))))

;;; DOCTYPE

;;; A DOCTYPE name the tokenizer reads back: no whitespace, >, NUL or ASCII
;;; upper case (which it folds); empty only without identifiers (ids?).
(def (html-doctype-name-ok? (name :- :string)
                            (ids? :- :boolean)) => :boolean
  (let (n (##string-length name))
    (and (or (fx> n 0) (not ids?))
         (let loop ((k 0))
           (or (fx>= k n)
               (let (c (##char->integer (##string-ref name k)))
                 (and (not (html-space-code? c))
                      (not (fx= c (ascii #\>)))
                      (not (fx= c 0))
                      (not (ascii-upper-code? c))
                      (loop (fx+ k 1)))))))))

;;; A DOCTYPE identifier that can be written quoted and read back: no > or
;;; NUL, and quotable as a SystemLiteral is.
(def (html-doctype-id-ok? (id :- :string)) => :boolean
  (and (not (string-index id #\>))
       (not (string-index id #\nul))
       (system-literal-string? id)))
