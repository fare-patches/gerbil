;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; TAL template reader: an HTML template as written, as typed HTML nodes.
;;; Internal to :std/text/markup/tal, which runs it at expansion time; its
;;; imports must stay free of I/O (and so of C code).
;;;
;;; Unlike the HTML tree builder, the reader keeps the template's structure:
;;; it tokenizes with ../html/scanner and keeps its own stack of open
;;; elements. An element's end tag may be left out only when the element is
;;; one whose end tag HTML lets authors omit and it carries no tal:
;;; attribute; then a later start or end tag closes it, as in HTML. Any
;;; other mismatch is an error. Text is decoded (character references,
;;; CR LF), adjacent text is one node, and the first LF of pre, listing and
;;; textarea text is dropped, as the parser drops it. SVG and MathML names
;;; get the parser's case and namespace adjustments.
(import :std/string/utf8
        ../xml/node
        ../scan-input
        ../html/node
        ../html/rules
        ../html/scanner
        ../html/atoms)
(export read-tal-template
        (struct-out TALTemplate)
        template-attribute-name
        tal-name?
        tal-offset-locator)

;;; A template: its top-level nodes (XMLElement, XMLText, XMLComment,
;;; XMLPI, HTMLDoctype) and their source positions: an eq? table from
;;; every element, comment, processing instruction and DOCTYPE, and the
;;; first text node of each run, to the byte offset where it starts in the
;;; template's UTF-8 encoding.
(defstruct TALTemplate
  ((nodes     :- :list)
   (positions :- HashTable))
  final: #t)

;;; An open element. p-scope?, li and dd/dt are what the parser would find
;;; searching the open elements from this one up, kept as each element is
;;; opened so that no start tag searches them: whether an HTML p is open in
;;; button scope, and the open li, and dd or dt, that the list item steps of
;;; an li, and of a dd or dt, start tag would end (#f for none).
(deftype @TALOpenElement TALOpenElement)
(defstruct TALOpenElement
  ((tag      :- :string)     ; tag name as tokenized, for end tag matching
   (atom     :- :fixnum)     ; of the tag name
   (name     :- XMLName)
   (ns       :- :fixnum)
   (context  :- :fixnum)     ; namespace rules for start tags among its children
   (attrs    :- :list)       ; in order
   (kids     :- :list)       ; children, last first
   (text     :- :list)       ; text not yet a node, last piece first
   (text-at  :- :fixnum)     ; offset of the first piece of text
   (offset   :- :fixnum)
   (tal?     :- :boolean)
   (newline? :- :boolean)    ; the next text drops a leading LF
   (p-scope? :- :boolean)
   (li       :? @TALOpenElement)
   (dd/dt    :? @TALOpenElement))
  final: #t)

;;; True when the start tag of the HTML element atom closes an open p
;;; element in button scope, as the tree builder decides it in a template:
;;; no quirks mode, no form element pointer.
(def (template-start-tag-closes-p? (atom :- :fixnum)) => :boolean
  (start-tag-closes-p? atom #f #f))

;;; The HTML elements whose end tag authors may omit, by atom, and the atoms
;;; of the start tags that close them, as the tree builder closes them; #f
;;; for other elements. colgroup and p are closed by rule
;;; (closed-by-start-tag?).
(def optional-end-closers
  (atom-vector
   [[atom-li atom-li]
    [atom-dt atom-dt atom-dd]
    [atom-dd atom-dt atom-dd]
    [atom-option atom-option atom-optgroup atom-hr]
    [atom-optgroup atom-optgroup atom-hr]
    [atom-tr atom-tr atom-tbody atom-tfoot atom-thead]
    [atom-td atom-td atom-th atom-tr atom-tbody atom-tfoot atom-thead]
    [atom-th atom-td atom-th atom-tr atom-tbody atom-tfoot atom-thead]
    [atom-thead atom-tbody atom-tfoot]
    [atom-tbody atom-tbody atom-tfoot]
    [atom-tfoot atom-tbody]
    [atom-rb atom-rb atom-rt atom-rtc atom-rp]
    [atom-rt atom-rb atom-rt atom-rtc atom-rp]
    [atom-rtc atom-rb atom-rtc]
    [atom-rp atom-rb atom-rt atom-rtc atom-rp]
    [atom-caption atom-caption atom-colgroup atom-col atom-thead atom-tbody atom-tfoot atom-tr]
    [atom-colgroup]
    [atom-p]]
   #f))

;;; The closers of el in optional-end-closers, or #f.
(def (optional-end-closers-of (el :- TALOpenElement)) => (Maybe :list)
  (and (fx= el.ns ns-html)
       (fx<= el.atom known-atom-count)
       (vector-ref optional-end-closers el.atom)))

(def (optional-end? (el :- TALOpenElement)) => :boolean
  (and (optional-end-closers-of el) #t))

;;; True when a start tag of atom atom closes the open element el by
;;; implication. A colgroup is closed by any start tag but col and
;;; template, which the tree builder reads inside it; a p by the start tags
;;; that close a p in button scope.
(def (closed-by-start-tag? (el   :- TALOpenElement)
                           (atom :- :fixnum)) => :boolean
  (and (fx= el.ns ns-html)
       (let (open el.atom)
         (cond
          ((fx= open atom-colgroup) (not (or (fx= atom atom-col) (fx= atom atom-template))))
          ((fx= open atom-p) (template-start-tag-closes-p? atom))
          (else (let (atoms (optional-end-closers-of el))
                  (and atoms (memv atom atoms) #t)))))))

;;; True for the names of TAL elements and attributes: tal:<something>.
(def (tal-name? (name :- :string)) => :boolean
  (and (fx> (string-length name) 4) (string-prefix? "tal:" name)))

;;; Reads str, a template, into a TALTemplate. Errors call fail with the
;;; byte offset they are at and a message; fail must not return.
(def (read-tal-template (str  :- :string)
                        (fail :- :procedure)) => TALTemplate
  (let* ((buf (string->scan-input str))
         (tz (scan-input->html-tokenizer buf 0 (fx- (u8vector-length buf) 1) #t))
         (positions (make-hash-table-eq))
         (root (make-TALOpenElement "" 0 (unchecked-node XMLName "" "" "") ns-html context-html
                                    '() '() '() 0 0 #f #f #f #f #f))
         (stack [root])
         (doctype-place? #t))
    (using ((tz   :- HTMLTokenizer)
            (root :- TALOpenElement))
      (defrule (current) (car stack))

      (def (flush-text! (el :- TALOpenElement))
        (unless (null? el.text)
          (let (node (unchecked-node XMLText (string-concatenate (reverse el.text))))
            (hash-put! positions node el.text-at)
            (set! el.kids (cons node el.kids))
            (set! el.text '()))))

      (def (add-node! node offset)
        (using (el (current) :- TALOpenElement)
          (flush-text! el)
          (set! el.newline? #f)
          (hash-put! positions node offset)
          (set! el.kids (cons node el.kids))))

      (def (add-text! text offset)
        (using (el (current) :- TALOpenElement)
          (let (text (if (and el.newline?
                              (fx> (string-length text) 0)
                              (eq? (string-ref text 0) #\newline))
                       (substring text 1 (string-length text))
                       text))
            (set! el.newline? #f)
            (when (fx> (string-length text) 0)
              (when (null? el.text)
                (set! el.text-at offset))
              (set! el.text (cons text el.text))
              (when (and doctype-place? (not (html-space-string? text)))
                (set! doctype-place? #f))))))

      ;; Closes the current element; explicit? when its end tag was read.
      (def (close! explicit?)
        (using (el (current) :- TALOpenElement)
          (when (and (not explicit?) el.tal?)
            (fail el.offset
                  (string-append "<" el.tag "> with tal: attributes needs an explicit </"
                                 el.tag ">")))
          (flush-text! el)
          (set! stack (cdr stack))
          (let (node (unchecked-node XMLElement el.name el.attrs (reverse el.kids)))
            (add-node! node el.offset))))

      (def (start-tag! offset)
        (let ((tag (html-atom-name tz tz.tag))
              (atom tz.tag)
              (self-closing? tz.self-closing?))
          (let close-implied ()
            (let (el (current))
              (when (and (not (eq? el root)) (closed-by-start-tag? el atom))
                (close! #f)
                (close-implied))))
          (using (parent (current) :- TALOpenElement)
            (let* ((ns (let (ns (start-tag-namespace parent.context tag
                                                     (html-font-breakout-token? tz)))
                         ;; The parser would close the foreign elements
                         ;; here, and read what follows them as HTML.
                         (when (fx< ns 0)
                           (fail offset (string-append "<" tag "> inside <" parent.tag
                                                       ">, where the parser ends SVG and MathML"
                                                       " content; close the SVG or MathML"
                                                       " element first")))
                         ns))
                   (html? (fx= ns ns-html))
                   (local (adjusted-element-local ns tag))
                   (attrs (token-attributes ns))
                   (tal? (or (tal-name? tag)
                             (ormap (lambda ((attr :- XMLAttribute)) (tal-name? attr.name.local))
                                    attrs)))
                   (class (if html? (element-class-of-atom atom) 0))
                   (inner (child-context ns local
                                         (using (attr (find (lambda ((attr :- XMLAttribute))
                                                              (string=? attr.name.local "encoding"))
                                                            attrs)
                                                      :? XMLAttribute)
                                           (and attr attr.value))))
                   ;; the encoding only decides whether annotation-xml is an
                   ;; HTML integration point, not whether it bounds a scope
                   ;; or is special
                   (flags (element-flags ns atom #f))
                   ;; the searches of TALOpenElement stop at an element that
                   ;; bounds button scope, and at a special element other
                   ;; than address, div and p
                   (p-scope? (p-in-button-scope-after ns atom flags parent.p-scope?))
                   (stop? (and (html-special-element? flags)
                               (not (and html?
                                         (or (fx= atom atom-address) (fx= atom atom-div)
                                             (fx= atom atom-p)))))))
              (when html?
                (when (class-has? class class-plaintext)
                  (fail offset "<plaintext> cannot be in a template: the parser reads all that follows as its text"))
                ;; The parser would end the p here, and the markup that follows
                ;; would not be read as written.
                (when (and (template-start-tag-closes-p? atom) parent.p-scope?)
                  (fail offset (string-append "<" tag "> inside an open <p>, which the parser ends here;"
                                              " close the <p> first")))
                ;; The parser's list item steps would end an open li, dd or
                ;; dt here, with what is open inside it. A current one has
                ;; been closed by close-implied already.
                (using (item (cond
                              ((fx= atom atom-li) parent.li)
                              ((or (fx= atom atom-dd) (fx= atom atom-dt)) parent.dd/dt)
                              (else #f))
                             :? TALOpenElement)
                  (when item
                    (fail offset (string-append "<" tag "> inside an open <" item.tag
                                                ">, which the parser ends here with the elements"
                                                " inside it; close them first")))))
              (using (el (make-TALOpenElement tag atom (unchecked-node XMLName local (namespace-uri ns) "")
                                              ns inner attrs '() '() 0 offset tal?
                                              (class-has? class class-newline) p-scope?
                                              (and (not stop?) parent.li)
                                              (and (not stop?) parent.dd/dt))
                         :- TALOpenElement)
                (when html?
                  (cond
                   ((fx= atom atom-li) (set! el.li el))
                   ((or (fx= atom atom-dd) (fx= atom atom-dt)) (set! el.dd/dt el))))
                (set! doctype-place? #f)
                (set! stack (cons el stack))
                (if (or (class-has? class class-void) self-closing?)
                  (close! #t)
                  (let (state (class-tokenizer-state class #f))
                    (unless (fx= state html-state-data)
                      (set-raw-state! state)))))
              ;; CDATA sections are read where the current element itself is
              ;; foreign, as the tree builder decides by the adjusted current
              ;; node: also inside foreignObject, mi and annotation-xml.
              (using (el (current) :- TALOpenElement)
                (set! tz.cdata? (cdata-allowed? el.ns)))))))

      (def (set-raw-state! state)
        (set! tz.state state)
        (set! tz.last-start-tag tz.tag))

      (def (current-context)
        (using (el (current) :- TALOpenElement)
          (if (or (fx= el.context context-html) (fx= el.context context-text-point))
            context-html
            el.context)))

      ;; The attributes of the current start tag of an element in ns, named
      ;; as the tree builder names them.
      (def (token-attributes ns)
        (html-token-attribute-list tz (atom value)
          (unchecked-node XMLAttribute (template-attribute-name ns (html-atom-name tz atom)) value)))

      (def (end-tag! offset)
        (let (tag (html-atom-name tz tz.tag))
          (when (and (class-has? (element-class-of-atom tz.tag) class-void)
                     (fx= (current-context) context-html))
            (fail offset (string-append "</" tag ">: <" tag "> is a void element, without end tag")))
          (let (target (find (lambda ((el :- TALOpenElement))
                               (and (not (eq? el root)) (string=? el.tag tag)))
                             stack))
            (unless target
              (fail offset (string-append "</" tag "> has no open <" tag ">")))
            (let close-to ()
              (using (el (current) :- TALOpenElement)
                (cond
                 ((eq? el target)
                  (close! #t))
                 ((optional-end? el)
                  (close! #f)
                  (close-to))
                 (else
                  (fail offset (string-append "open <" el.tag
                                              "> does not match </" tag ">")))))))
          (using (el (current) :- TALOpenElement)
            (set! tz.cdata? (cdata-allowed? el.ns)))))

      (let loop ()
        (let* ((offset (html-tokenizer-offset tz))
               (kind (html-tokenizer-next! tz)))
          (cond
           ((fx= kind html-token-eof)
            ;; the tokenizer drops a tag or attribute value cut off by the end
            (when (fx< offset tz.end)
              (fail offset "unterminated markup at the end of the template"))
            (let close-all ()
              (using (el (current) :- TALOpenElement)
                (unless (eq? el root)
                  (unless (optional-end? el)
                    (fail el.offset (string-append "unclosed <" el.tag ">")))
                  (close! #f)
                  (close-all))))
            (flush-text! root)
            (make-TALTemplate (reverse root.kids) positions))
           (else
            (cond
             ((fx= kind html-token-characters)
              (add-text! (html-token-text tz) offset))
             ((fx= kind html-token-null-character)
              (fail offset "NUL character in template"))
             ((fx= kind html-token-start-tag)
              (start-tag! offset))
             ((fx= kind html-token-end-tag)
              (end-tag! offset))
             ((fx= kind html-token-comment)
              (add-node! (unchecked-node XMLComment tz.data) offset))
             ((fx= kind html-token-pi)
              (add-node! (unchecked-node XMLPI tz.target tz.data) offset))
             ((fx= kind html-token-doctype)
              (unless (and doctype-place? (eq? (current) root))
                (fail offset "DOCTYPE after elements or text"))
              (set! doctype-place? #f)
              (add-node! (unchecked-node HTMLDoctype (or tz.doctype-name "")
                                                     tz.public-id
                                                     tz.system-id)
                         offset)))
            (loop))))))))

;;; The name of an attribute name (as tokenized: ASCII lower case) of an
;;; element in namespace ns, as the tree builder names it.
(def (template-attribute-name (ns   :- :fixnum)
                              (name :- :string)) => XMLName
  (or (adjusted-foreign-attribute-name ns name)
      (unchecked-node XMLName name "" "")))

;;; A procedure from a byte offset of str's UTF-8 encoding to its 1-based
;;; [line column], the column in characters; CR LF, CR and LF end lines.
;;; The positions are computed once, a line end or character each, so that
;;; each offset is a binary search: locating every expression of a
;;; template is O(n log n) (markup-benchmark.ss mode tal-dynamic-lines).
(def (tal-offset-locator (str :- :string)) => :procedure
  (let* ((n (string-length str))
         (stops (make-vector (fx+ n 1) 0)))   ; byte offset of each position
    (let loop ((k 0) (stop 0) (bytes 0) (lines [0]))
      (vector-set! stops stop bytes)
      (if (fx>= k n)
        (let ((end stop)
              (lines (list->vector (reverse lines)))) ; position of each line start
          ;; the first position at or past offset, or the last
          (def (position offset)
            (let search ((lo 0) (hi end))
              (if (fx< lo hi)
                (let (mid (fxquotient (fx+ lo hi) 2))
                  (if (fx>= (vector-ref stops mid) offset)
                    (search lo mid)
                    (search (fx+ mid 1) hi)))
                lo)))
          ;; the index of the last line starting at or before position s
          (def (line-of s)
            (let search ((lo 0) (hi (fx- (vector-length lines) 1)))
              (if (fx< lo hi)
                (let (mid (fxquotient (fx+ lo hi 1) 2))
                  (if (fx<= (vector-ref lines mid) s)
                    (search mid hi)
                    (search lo (fx- mid 1))))
                lo)))
          (lambda (offset)
            (let* ((s (position offset))
                   (line (line-of s)))
              [(fx+ line 1) (fx+ (fx- s (vector-ref lines line)) 1)])))
        (let (c (string-ref str k))
          (cond
           ((and (eq? c #\return) (fx< (fx+ k 1) n) (eq? (string-ref str (fx+ k 1)) #\newline))
            (loop (fx+ k 2) (fx+ stop 1) (fx+ bytes 2) (cons (fx+ stop 1) lines)))
           ((or (eq? c #\newline) (eq? c #\return))
            (loop (fx+ k 1) (fx+ stop 1) (fx+ bytes 1) (cons (fx+ stop 1) lines)))
           (else
            (loop (fx+ k 1) (fx+ stop 1) (fx+ bytes (utf8-char-length c)) lines))))))))
