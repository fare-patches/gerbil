;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Rendering semantics adapted from jgm/djot.js; MIT notice: testdata/LICENSE.
(import :std/interface
        (only-in :std/error raise/context)
        (only-in ../xml/node unchecked-node XML XMLName XMLAttribute XMLElement XMLElement?
                 XMLText XMLText?)
        (only-in ../html/node HTMLRaw)
        ../html/atoms
        (only-in ../html/rules known-name)
        (only-in ../html/types make-html-attribute)
        (only-in ../html/writer html->string)
        ./ast
        (only-in ./inline inline-string-content))
(export djot->html-fragment
        djot->html)

;;; The attributes and text Djot writes itself, shared by every rendering;
;;; tag and attribute names are the parser's (known-name).
(def role-backlink (unchecked-node XMLAttribute (known-name atom-role) "doc-backlink"))
(def role-endnotes (unchecked-node XMLAttribute (known-name atom-role) "doc-endnotes"))
(def checkbox-attributes
  [(unchecked-node XMLAttribute (known-name atom-disabled) "")
   (unchecked-node XMLAttribute (known-name atom-type) "checkbox")])
(def checked-checkbox-attributes
  (append checkbox-attributes [(unchecked-node XMLAttribute (known-name atom-checked) "")]))

(def text-newline (XMLText "\n"))
(def text-left-single-quote (XMLText "‘"))
(def text-right-single-quote (XMLText "’"))
(def text-left-double-quote (XMLText "“"))
(def text-right-double-quote (XMLText "”"))
(def text-ellipses (XMLText "…"))
(def text-en-dash (XMLText "–"))
(def text-em-dash (XMLText "—"))
(def text-inline-math-open (XMLText "\\("))
(def text-inline-math-close (XMLText "\\)"))
(def text-display-math-open (XMLText "\\["))
(def text-display-math-close (XMLText "\\]"))
(def text-backlink (XMLText "↩︎"))
(def raw-nbsp (HTMLRaw "&nbsp;"))

;;; str with U+0000, which HTML text and attribute values cannot carry, as
;;; U+FFFD (CommonMark's rule); str itself when it has none. Every text is
;;; scanned, eight characters per iteration: (string-index str #\nul)
;;; instead took 6% more instructions and 8% more cycles (djot-benchmark.ss
;;; mode render, FILE src/std/text/markup/djot/testdata/footnotes.test,
;;; ITERATIONS 4000).
(def (render-string (str : :string)) => :string
  (defrule (nul-at? k) (##eq? (##string-ref str k) #\nul))
  (let* ((n (##string-length str))
         (m (##fx- n 7)))
    (def (replace)
      (string-map (lambda ((c : :char)) => :char (if (eq? c #\nul) #\xfffd c)) str))
    (let loop ((k 0))
      (cond
       ((##fx< k m)
        (if (or (nul-at? k) (nul-at? (##fx+ k 1)) (nul-at? (##fx+ k 2)) (nul-at? (##fx+ k 3))
                (nul-at? (##fx+ k 4)) (nul-at? (##fx+ k 5)) (nul-at? (##fx+ k 6))
                (nul-at? (##fx+ k 7)))
          (replace)
          (loop (##fx+ k 8))))
       ((##fx= k n) str)
       ((nul-at? k) (replace))
       (else (loop (##fx+ k 1)))))))

(def (render-text-node (str : :string)) => XMLText
  (XMLText (render-string str)))

;;; All mutable state belongs to one rendering, never to the public document.
(defstruct render-context
  ((references : HashTable)
   (notes      : HashTable)
   (note-order : :list)
   (emitted    : HashTable)
   (next-note  : :fixnum)))

(def (attribute-value (attributes : :list)
                      (name       : :string)) => (Maybe :string)
  (let loop ((rest attributes)) => (Maybe :string)
    (and (pair? rest)
         (let (attribute (:- (car rest) djot-attribute))
           (if (string=? name (djot-attribute-name attribute))
             (djot-attribute-value attribute) (loop (cdr rest)))))))

;;; Replacement retains the original key's position, like ordered Djot attributes.
(def (overlay-attributes (base      : :list)
                         (overrides : :list)) => :list
  (let ((index (make-hash-table)) (result []))
    (for-each
      (lambda ((attribute : djot-attribute)) => :void
        (let* ((key attribute.name)
               (entry (hash-get index key)))
          (if entry (set-car! entry attribute)
              (let (entry (cons attribute []))
                (hash-put! index key entry)
                (set! result (cons entry result))))))
      (append base overrides))
    (map car (reverse result))))

(def (render-attributes (node  : djot-node)
                        (extra : :list)) => :list
  (if (and (null? node.attributes) (null? node.auto-attributes) (null? extra))
    []
    (render-attribute-list node extra)))

(def (render-attribute-list (node  : djot-node)
                            (extra : :list)) => :list
  (let* ((explicit node.attributes)
         (explicit-keys (make-hash-table))
         (attributes
          (begin
            (for-each
              (lambda ((a : djot-attribute)) => :void
                (hash-put! explicit-keys a.name #t))
              explicit)
            (append (filter (lambda ((a : djot-attribute)) => :boolean
                              (not (hash-get explicit-keys a.name)))
                            node.auto-attributes)
                    explicit)))
         (extra-class (attribute-value extra "class"))
         (own-class (attribute-value explicit "class"))
         (seen-keys (make-hash-table)))
    (filter-map
     (lambda ((a :- djot-attribute)) => (Maybe XMLAttribute)
       (let (key (string-map
                  (lambda ((c : :char)) => :char
                    (if (char<=? #\A c #\Z)
                      (integer->char (+ 32 (char->integer c))) c))
                  a.name))
         (and (not (hash-get seen-keys key))
              (begin
                (hash-put! seen-keys key #t)
                (let (value (render-string
                             (if (and extra-class own-class (string=? a.name "class"))
                               (string-append extra-class " " own-class)
                               a.value)))
                  ;; Written in ASCII lower case, as HTML parsers read names.
                  (make-html-attribute key value))))))
     (append extra attributes))))

(def (render-element (tag      : XMLName)
                     (node     : djot-node)
                     (extra    : :list)
                     (children : :list)
                     (newlines : :fixnum)) => :list
  (let (element (unchecked-node XMLElement tag (render-attributes node extra)
                                            (if (>= newlines 2) (cons text-newline children) children)))
    (if (> newlines 0) [element text-newline] [element])))

(def (render-children (node    : djot-container)
                      (context : render-context)
                      (tight?  : :boolean)
                      (depth   : :fixnum)) => :list
  (let loop ((rest node.children) (result [])) => :list
    (if (null? rest) (reverse result)
        (loop (cdr rest)
              (foldl cons result (render-node (car rest) context tight? (+ depth 1)))))))

;;; The reference definition label names, or #f when label is #f or names
;;; none.
(def (reference-of (context : render-context)
                   (label   :? :string)) => (Maybe djot-reference)
  (and label (hash-get context.references label)))

;;; A link or image: an element tag with node's own attributes, then the
;;; attributes extra gives for its destination and those of the reference
;;; definition it uses, unless node has them, and children.
(def (render-reference (tag       : XMLName)
                       (node      : djot-container)
                       (reference :? djot-reference)
                       (extra     : :list)
                       (children  : :list)) => :list
  (let (own-keys (make-hash-table))
    (for-each
      (lambda ((a : djot-attribute)) => :void
        (hash-put! own-keys a.name #t))
      (append node.auto-attributes node.attributes))
    (def (not-own? (a :- djot-attribute)) => :boolean
      (not (hash-get own-keys a.name)))
    (let* ((extra (filter not-own? extra))
           (extra (if reference
                    (overlay-attributes extra
                                        (filter not-own?
                                                (overlay-attributes reference.auto-attributes
                                                                    reference.attributes)))
                    extra)))
      (render-element tag node extra children 0))))

(def (render-note-reference (node    : djot-footnote-reference)
                            (context : render-context)) => :list
  (let* ((label node.text)
         (index (or (hash-get context.notes label)
                    (let (index context.next-note)
                      (hash-put! context.notes label index)
                      (set! context.next-note (+ index 1))
                      (set! context.note-order (cons label context.note-order))
                      index)))
         (number (number->string index))
         (extra (if (hash-get context.emitted label) []
                    [(make-djot-attribute "id" (string-append "fnref" number))])))
    (hash-put! context.emitted label #t)
    (render-element (known-name atom-a) node
                    (append extra [(make-djot-attribute "href" (string-append "#fn" number))
                                   (make-djot-attribute "role" "doc-noteref")])
                    [(unchecked-node XMLElement (known-name atom-sup) [] [(XMLText number)])] 0)))

;;; Internal HTML node rendering operation; public AST objects never hold
;;; render state.
(interface DjotRender
  (render (context : render-context)
          (tight?  : :boolean)
          (depth   : :fixnum))
  => :list)

(def (render-node (node    : djot-node)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (when (and (djot-container? node) (> depth 512))
    (raise/context (DjotResourceError "Djot rendering nesting limit exceeded"
                                      irritants: [depth: depth limit: 512])
                   where: render-node))

  (using (renderer node : DjotRender)
    (renderer.render context tight? depth)))

(def (render-paragraph (node    : djot-paragraph)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (if tight? (append (render-children node context tight? depth) [text-newline]) (render-element (known-name atom-p) node [] (render-children node context tight? depth) 1)))

(def (render-section (node    : djot-section)
                     (context : render-context)
                     (tight?  : :boolean)
                     (depth   : :fixnum)) => :list
  (render-element (known-name atom-section) node [] (render-children node context tight? depth) 2))

(def (render-div (node    : djot-div)
                 (context : render-context)
                 (tight?  : :boolean)
                 (depth   : :fixnum)) => :list
  (render-element (known-name atom-div) node [] (render-children node context tight? depth) 2))

(def (render-block-quote (node    : djot-block-quote)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element (known-name atom-blockquote) node [] (render-children node context tight? depth) 2))

(def (render-list-item (node    : djot-list-item)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (render-element (known-name atom-li) node [] (render-children node context tight? depth) 2))

(def (render-task-list-item (node    : djot-task-list-item)
                            (context : render-context)
                            (tight?  : :boolean)
                            (depth   : :fixnum)) => :list
  (let (attributes (if node.checked? checked-checkbox-attributes checkbox-attributes))
    (render-element (known-name atom-li) node []
                    (append [(unchecked-node XMLElement (known-name atom-input) attributes []) text-newline] (render-children node context tight? depth)) 2)))

(def (render-definition-list-item (node    : djot-definition-list-item)
                                  (context : render-context)
                                  (tight?  : :boolean)
                                  (depth   : :fixnum)) => :list
  (render-children node context tight? depth))

(def (render-definition (node    : djot-definition)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  (render-element (known-name atom-dd) node [] (render-children node context tight? depth) 2))

(def (render-term (node    : djot-term)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element (known-name atom-dt) node [] (render-children node context tight? depth) 1))

(def (render-definition-list (node    : djot-definition-list)
                             (context : render-context)
                             (tight?  : :boolean)
                             (depth   : :fixnum)) => :list
  (render-element (known-name atom-dl) node [] (render-children node context tight? depth) 2))

(def (render-bullet-list (node    : djot-bullet-list)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element (known-name atom-ul) node [] (render-children node context node.tight? depth) 2))

(def (render-task-list (node    : djot-task-list)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (render-element (known-name atom-ul) node [(make-djot-attribute "class" "task-list")]
                  (render-children node context node.tight? depth) 2))

(def (render-ordered-list (node    : djot-ordered-list)
                          (context : render-context)
                          (tight?  : :boolean)
                          (depth   : :fixnum)) => :list
  (let ((extra (if (= node.start 1) []
                   [(make-djot-attribute "start" (number->string node.start))]))
        (style (list->string (filter char-alphabetic? (string->list node.style)))))
    (unless (string=? style "")
      (set! extra (append extra [(make-djot-attribute "type" style)])))
    (render-element (known-name atom-ol) node extra (render-children node context node.tight? depth) 2)))

(def (render-heading (node    : djot-heading)
                     (context : render-context)
                     (tight?  : :boolean)
                     (depth   : :fixnum)) => :list
  (render-element (case node.level
                    ((1) (known-name atom-h1)) ((2) (known-name atom-h2)) ((3) (known-name atom-h3)) ((4) (known-name atom-h4)) ((5) (known-name atom-h5)) ((6) (known-name atom-h6))
                    (else (unchecked-node XMLName
                                          (string-append "h" (number->string node.level)) "" ""))) node [] (render-children node context tight? depth) 1))

(def (render-table (node    : djot-table)
                   (context : render-context)
                   (tight?  : :boolean)
                   (depth   : :fixnum)) => :list
  (render-element (known-name atom-table) node [] (render-children node context tight? depth) 2))

(def (render-caption (node    : djot-caption)
                     (context : render-context)
                     (tight?  : :boolean)
                     (depth   : :fixnum)) => :list
  (if (null? node.children) [] (render-element (known-name atom-caption) node [] (render-children node context tight? depth) 1)))

(def (render-row (node    : djot-row)
                 (context : render-context)
                 (tight?  : :boolean)
                 (depth   : :fixnum)) => :list
  (render-element (known-name atom-tr) node [] (render-children node context tight? depth) 2))

(def (render-cell (node    : djot-cell)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element (if node.head? (known-name atom-th) (known-name atom-td)) node (if (eq? node.alignment 'default) []
                                                   [(make-djot-attribute "style"
                                                                         (string-append "text-align: " (symbol->string node.alignment) ";"))]) (render-children node context tight? depth) 1))

(def (render-thematic-break (node    : djot-thematic-break)
                            (context : render-context)
                            (tight?  : :boolean)
                            (depth   : :fixnum)) => :list
  (render-element (known-name atom-hr) node [] [] 1))

(def (render-code-block (node    : djot-code-block)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  (let (language node.language)
    (render-element (known-name atom-pre) node []
                    [(unchecked-node XMLElement (known-name atom-code)
                                                 (if language
                                                   [(unchecked-node XMLAttribute (known-name atom-class)
                                                                                  (render-string (string-append "language-" language)))]
                                                   [])
                                                 [(render-text-node node.text)])] 1)))

(def (render-raw-block (node    : djot-raw-block)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (if (string=? node.format "html") [(HTMLRaw node.text)] []))

(def (render-raw-inline (node    : djot-raw-inline)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  (if (string=? node.format "html") [(HTMLRaw node.text)] []))

(def (render-text (node    : djot-text)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (if (and (null? node.attributes) (null? node.auto-attributes))
    [(render-text-node node.text)]
    (render-element (known-name atom-span) node [] [(render-text-node node.text)] 0)))

(def (render-smart-punctuation (node    : djot-smart-punctuation)
                               (context : render-context)
                               (tight?  : :boolean)
                               (depth   : :fixnum)) => :list
  [(case node.kind
     ((left-single-quote) text-left-single-quote) ((right-single-quote) text-right-single-quote)
     ((left-double-quote) text-left-double-quote) ((right-double-quote) text-right-double-quote)
     ((ellipses) text-ellipses) ((en-dash) text-en-dash) ((em-dash) text-em-dash)
     (else (render-text-node node.text)))])

(def (render-double-quoted (node    : djot-double-quoted)
                           (context : render-context)
                           (tight?  : :boolean)
                           (depth   : :fixnum)) => :list
  (append [text-left-double-quote] (render-children node context tight? depth)
          [text-right-double-quote]))

(def (render-single-quoted (node    : djot-single-quoted)
                           (context : render-context)
                           (tight?  : :boolean)
                           (depth   : :fixnum)) => :list
  (append [text-left-single-quote] (render-children node context tight? depth)
          [text-right-single-quote]))

(def (render-symbol (node    : djot-symbol)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  [(render-text-node (string-append ":" node.alias ":"))])

(def (render-inline-math (node    : djot-inline-math)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element (known-name atom-span) node [(make-djot-attribute "class" "math inline")]
    [text-inline-math-open (render-text-node node.text) text-inline-math-close] 0))

(def (render-display-math (node    : djot-display-math)
                          (context : render-context)
                          (tight?  : :boolean)
                          (depth   : :fixnum)) => :list
  (render-element (known-name atom-span) node [(make-djot-attribute "class" "math display")]
    [text-display-math-open (render-text-node node.text) text-display-math-close] 0))

(def (render-verbatim (node    : djot-verbatim)
                      (context : render-context)
                      (tight?  : :boolean)
                      (depth   : :fixnum)) => :list
  (render-element (known-name atom-code) node [] [(render-text-node node.text)] 0))

(def (render-soft-break (node    : djot-soft-break)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  [text-newline])

(def (render-hard-break (node    : djot-hard-break)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  [(unchecked-node XMLElement (known-name atom-br) [] []) text-newline])

(def (render-nonbreaking-space (node    : djot-nonbreaking-space)
                               (context : render-context)
                               (tight?  : :boolean)
                               (depth   : :fixnum)) => :list
  [raw-nbsp])

(def (render-link (node    : djot-link)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (using (reference (reference-of context node.reference) :? djot-reference)
    (let (destination (if reference reference.destination node.destination))
      (render-reference (known-name atom-a) node reference
                        (if destination [(make-djot-attribute "href" destination)] [])
                        (render-children node context tight? depth)))))

;;; An image whose reference names no definition has no alt or src.
(def (render-image (node    : djot-image)
                   (context : render-context)
                   (tight?  : :boolean)
                   (depth   : :fixnum)) => :list
  (using (reference (reference-of context node.reference) :? djot-reference)
    (let (destination (if reference reference.destination node.destination))
      (render-reference (known-name atom-img) node reference
                        (if (and node.reference (not reference))
                          []
                          (cons (make-djot-attribute "alt" (inline-string-content node.children))
                                (if destination [(make-djot-attribute "src" destination)] [])))
                        []))))

(def (render-url (node    : djot-url)
                 (context : render-context)
                 (tight?  : :boolean)
                 (depth   : :fixnum)) => :list
  (render-element (known-name atom-a) node [(make-djot-attribute "href" node.text)]
    [(render-text-node node.text)] 0))

(def (render-email (node    : djot-email)
                   (context : render-context)
                   (tight?  : :boolean)
                   (depth   : :fixnum)) => :list
  (render-element (known-name atom-a) node [(make-djot-attribute "href" (string-append "mailto:" node.text))]
    [(render-text-node node.text)] 0))

(def (render-footnote-reference (node    : djot-footnote-reference)
                                (context : render-context)
                                (tight?  : :boolean)
                                (depth   : :fixnum)) => :list
  (render-note-reference node context))

(def (render-strong (node    : djot-strong)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  (render-element (known-name atom-strong) node [] (render-children node context tight? depth) 0))

(def (render-emph (node    : djot-emph)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element (known-name atom-em) node [] (render-children node context tight? depth) 0))

(def (render-span (node    : djot-span)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element (known-name atom-span) node [] (render-children node context tight? depth) 0))

(def (render-mark (node    : djot-mark)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element (known-name atom-mark) node [] (render-children node context tight? depth) 0))

(def (render-insert (node    : djot-insert)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  (render-element (known-name atom-ins) node [] (render-children node context tight? depth) 0))

(def (render-delete (node    : djot-delete)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  (render-element (known-name atom-del) node [] (render-children node context tight? depth) 0))

(def (render-superscript (node    : djot-superscript)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element (known-name atom-sup) node [] (render-children node context tight? depth) 0))

(def (render-subscript (node    : djot-subscript)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (render-element (known-name atom-sub) node [] (render-children node context tight? depth) 0))

(def (render-invalid-node (node    : djot-node)
                          (context : render-context)
                          (tight?  : :boolean)
                          (depth   : :fixnum)) => :list
  (error "Invalid visible Djot node" node))

(implement DjotRender djot-paragraph
           (render __render-paragraph))

(implement DjotRender djot-section
           (render __render-section))

(implement DjotRender djot-div
           (render __render-div))

(implement DjotRender djot-block-quote
           (render __render-block-quote))

(implement DjotRender djot-list-item
           (render __render-list-item))

(implement DjotRender djot-task-list-item
           (render __render-task-list-item))

(implement DjotRender djot-definition-list-item
           (render __render-definition-list-item))

(implement DjotRender djot-definition
           (render __render-definition))

(implement DjotRender djot-term
           (render __render-term))

(implement DjotRender djot-definition-list
           (render __render-definition-list))

(implement DjotRender djot-bullet-list
           (render __render-bullet-list))

(implement DjotRender djot-task-list
           (render __render-task-list))

(implement DjotRender djot-ordered-list
           (render __render-ordered-list))

(implement DjotRender djot-heading
           (render __render-heading))

(implement DjotRender djot-table
           (render __render-table))

(implement DjotRender djot-caption
           (render __render-caption))

(implement DjotRender djot-row
           (render __render-row))

(implement DjotRender djot-cell
           (render __render-cell))

(implement DjotRender djot-thematic-break
           (render __render-thematic-break))

(implement DjotRender djot-code-block
           (render __render-code-block))

(implement DjotRender djot-raw-block
           (render __render-raw-block))

(implement DjotRender djot-raw-inline
           (render __render-raw-inline))

(implement DjotRender djot-text
           (render __render-text))

(implement DjotRender djot-smart-punctuation
           (render __render-smart-punctuation))

(implement DjotRender djot-double-quoted
           (render __render-double-quoted))

(implement DjotRender djot-single-quoted
           (render __render-single-quoted))

(implement DjotRender djot-symbol
           (render __render-symbol))

(implement DjotRender djot-inline-math
           (render __render-inline-math))

(implement DjotRender djot-display-math
           (render __render-display-math))

(implement DjotRender djot-verbatim
           (render __render-verbatim))

(implement DjotRender djot-soft-break
           (render __render-soft-break))

(implement DjotRender djot-hard-break
           (render __render-hard-break))

(implement DjotRender djot-nonbreaking-space
           (render __render-nonbreaking-space))

(implement DjotRender djot-link
           (render __render-link))

(implement DjotRender djot-image
           (render __render-image))

(implement DjotRender djot-url
           (render __render-url))

(implement DjotRender djot-email
           (render __render-email))

(implement DjotRender djot-footnote-reference
           (render __render-footnote-reference))

(implement DjotRender djot-strong
           (render __render-strong))

(implement DjotRender djot-emph
           (render __render-emph))

(implement DjotRender djot-span
           (render __render-span))

(implement DjotRender djot-mark
           (render __render-mark))

(implement DjotRender djot-insert
           (render __render-insert))

(implement DjotRender djot-delete
           (render __render-delete))

(implement DjotRender djot-superscript
           (render __render-superscript))

(implement DjotRender djot-subscript
           (render __render-subscript))

(implement DjotRender djot-node
           (render __render-invalid-node))

;;; The "\n" text after a block element.
(def (newline-text? (node : XML)) => :boolean
  (and (XMLText? node)
       (using (text node :- XMLText)
         (string=? text.data "\n"))))

(def (paragraph? (node : XML)) => :boolean
  (and (XMLElement? node)
       (using (el node :- XMLElement)
         (eq? el.name (known-name atom-p)))))

(def (note-with-backlink (content : :list)
                         (index   : :fixnum)) => :list
  (let* ((backlink (unchecked-node XMLElement
                                   (known-name atom-a)
                                   [(unchecked-node XMLAttribute (known-name atom-href) (string-append "#fnref" (number->string index)))
                                    role-backlink]
                                   [text-backlink]))
         (reversed (reverse content)))
    (if (and (pair? reversed) (newline-text? (car reversed))
             (pair? (cdr reversed)) (paragraph? (cadr reversed)))
      (using (paragraph (cadr reversed) :- XMLElement)
        (reverse (cons text-newline
                       (cons (unchecked-node XMLElement (known-name atom-p) paragraph.attributes
                                                        (append paragraph.children [backlink]))
                             (cddr reversed)))))
      (append content [(unchecked-node XMLElement (known-name atom-p) [] [backlink]) text-newline]))))

(def (render-notes (document : djot-document)
                   (context  : render-context)) => :list
  (let (definitions (make-hash-table))
    (for-each
      (lambda ((entry : :pair)) => :void
        (hash-put! definitions (car entry) (cdr entry)))
      document.footnotes)
    ;; References are indexed before being queued, so cycles never requeue a note.
    (let loop ((labels []) (items [])) => :list
      (cond
       ((pair? labels)
        (let* ((label (car labels))
               (index (:- (hash-get context.notes label) :fixnum))
               (definition (hash-get definitions label))
               (content (if definition (render-children definition context #f 0) []))
               (item (unchecked-node XMLElement
                                     (known-name atom-li)
                                     [(unchecked-node XMLAttribute (known-name atom-id) (string-append "fn" (number->string index)))]
                                     (cons text-newline (note-with-backlink content index)))))
          (loop (cdr labels) (cons text-newline (cons item items)))))
       ((pair? context.note-order)
        (let (labels (reverse context.note-order))
          (set! context.note-order [])
          (loop labels items)))
       (else
        [(unchecked-node XMLElement (known-name atom-section) [role-endnotes]
                                     [text-newline (unchecked-node XMLElement (known-name atom-hr) [] []) text-newline
                                      (unchecked-node XMLElement (known-name atom-ol) [] (cons text-newline (reverse items)))
                                      text-newline])
         text-newline])))))

;;; Validate also image alternative text and unused notes, which need not pass
;;; through render-node. Public constructors can supply trees not made by parsing.
(def (check-render-nesting! (nodes : :list)
                            (depth : :fixnum)) => :void
  (for-each
    (lambda ((node : djot-node)) => :void
      (when (djot-container? node)
        (using (node :- djot-container)
          (when (>= depth 512)
            (raise/context (DjotResourceError "Djot rendering nesting limit exceeded"
                                              irritants: [depth: (fx+ depth 1) limit: 512])
                           where: check-render-nesting!))
          (check-render-nesting! node.children (+ depth 1)))))
    nodes))

;;; The HTML nodes of document, in order; text is unescaped, raw HTML is
;;; HTMLRaw.
(def (djot->html-fragment (document : djot-document)) => :list
  (check-render-nesting! document.children 0)
  (check-render-nesting! (map cdr document.footnotes) 0)
  (let* ((references (make-hash-table))
         (context (make-render-context references (make-hash-table) [] (make-hash-table) 1)))
    (for-each
      (lambda ((entry : :pair)) => :void
        (hash-put! references (car entry) (cdr entry)))
      (append document.auto-references document.references))
    (let (content (render-children document context #f 0))
      (if (> (render-context-next-note context) 1)
        (append content (render-notes document context))
        content))))

(def (djot->html (document : djot-document)) => :string
  (html->string (djot->html-fragment document)))
