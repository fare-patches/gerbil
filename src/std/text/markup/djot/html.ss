;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Rendering semantics adapted from jgm/djot.js; MIT notice: testdata/LICENSE.
(import :std/interface
        (only-in :std/error raise/context)
        :std/text/markup/sxml/print
        ./ast
        (only-in ./inline inline-string-content))
(export djot->sxml
        djot->html)

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
     (lambda ((a : djot-attribute)) => (Maybe :list)
       (let (key (string-map
                  (lambda ((c : :char)) => :char
                    (if (char<=? #\A c #\Z)
                      (integer->char (+ 32 (char->integer c))) c))
                  a.name))
         (and (not (hash-get seen-keys key))
              (begin
                (hash-put! seen-keys key #t)
                [(string->symbol a.name)
                 (if (and extra-class own-class (string=? a.name "class"))
                   (string-append extra-class " " own-class)
                   a.value)]))))
     (append extra attributes))))

(def (render-element (tag      : :symbol)
                     (node     : djot-node)
                     (extra    : :list)
                     (children : :list)
                     (newlines : :fixnum)) => :list
  (let (element (cons tag (cons (cons '@ (render-attributes node extra))
                                (if (>= newlines 2) (cons "\n" children) children))))
    (if (> newlines 0) [element "\n"] [element])))

(def (render-children (node    : djot-container)
                      (context : render-context)
                      (tight?  : :boolean)
                      (depth   : :fixnum)) => :list
  (let loop ((rest node.children) (result [])) => :list
    (if (null? rest) (reverse result)
        (loop (cdr rest)
              (foldl cons result (render-node (car rest) context tight? (+ depth 1)))))))

(def (render-reference (node    : djot-container)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (let* ((image? (djot-image? node))
         (label (if image? (djot-image-reference node) (djot-link-reference node)))
         (reference (and label (hash-get context.references label)))
         (destination (if reference (djot-reference-destination reference)
                          (if image? (djot-image-destination node) (djot-link-destination node))))
         (extra (if image?
                  (if (and label (not reference)) []
                      (cons (make-djot-attribute "alt" (inline-string-content node.children))
                            (if destination [(make-djot-attribute "src" destination)] [])))
                  (if destination [(make-djot-attribute "href" destination)] []))))
    (let (own-keys (make-hash-table))
      (for-each
        (lambda ((a : djot-attribute)) => :void
          (hash-put! own-keys a.name #t))
        (append node.auto-attributes node.attributes))
      (set! extra
        (filter (lambda ((a : djot-attribute)) => :boolean
                  (not (hash-get own-keys a.name)))
                extra))
      (when reference
        (set! extra
          (overlay-attributes extra
                              (filter (lambda ((a : djot-attribute)) => :boolean
                                        (not (hash-get own-keys a.name)))
                                      (overlay-attributes (djot-node-auto-attributes reference)
                                                          (djot-node-attributes reference)))))))
    (render-element (if image? 'img 'a) node extra
                    (if image? [] (render-children node context tight? depth)) 0)))

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
    (render-element 'a node
                    (append extra [(make-djot-attribute "href" (string-append "#fn" number))
                                   (make-djot-attribute "role" "doc-noteref")])
                    [['sup number]] 0)))

;;; Internal SXML rendering operation; public AST objects never hold render state.
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
  (if tight? (append (render-children node context tight? depth) ["\n"]) (render-element 'p node [] (render-children node context tight? depth) 1)))

(def (render-section (node    : djot-section)
                     (context : render-context)
                     (tight?  : :boolean)
                     (depth   : :fixnum)) => :list
  (render-element 'section node [] (render-children node context tight? depth) 2))

(def (render-div (node    : djot-div)
                 (context : render-context)
                 (tight?  : :boolean)
                 (depth   : :fixnum)) => :list
  (render-element 'div node [] (render-children node context tight? depth) 2))

(def (render-block-quote (node    : djot-block-quote)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element 'blockquote node [] (render-children node context tight? depth) 2))

(def (render-list-item (node    : djot-list-item)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (render-element 'li node [] (render-children node context tight? depth) 2))

(def (render-task-list-item (node    : djot-task-list-item)
                            (context : render-context)
                            (tight?  : :boolean)
                            (depth   : :fixnum)) => :list
  (let (attributes (append [['disabled ""] ['type "checkbox"]]
                           (if node.checked? [['checked ""]] [])))
    (render-element 'li node []
                    (append [(list 'input (cons '@ attributes)) "\n"] (render-children node context tight? depth)) 2)))

(def (render-definition-list-item (node    : djot-definition-list-item)
                                  (context : render-context)
                                  (tight?  : :boolean)
                                  (depth   : :fixnum)) => :list
  (render-children node context tight? depth))

(def (render-definition (node    : djot-definition)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  (render-element 'dd node [] (render-children node context tight? depth) 2))

(def (render-term (node    : djot-term)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element 'dt node [] (render-children node context tight? depth) 1))

(def (render-definition-list (node    : djot-definition-list)
                             (context : render-context)
                             (tight?  : :boolean)
                             (depth   : :fixnum)) => :list
  (render-element 'dl node [] (render-children node context tight? depth) 2))

(def (render-bullet-list (node    : djot-bullet-list)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element 'ul node [] (render-children node context node.tight? depth) 2))

(def (render-task-list (node    : djot-task-list)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (render-element 'ul node [(make-djot-attribute "class" "task-list")]
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
    (render-element 'ol node extra (render-children node context node.tight? depth) 2)))

(def (render-heading (node    : djot-heading)
                     (context : render-context)
                     (tight?  : :boolean)
                     (depth   : :fixnum)) => :list
  (render-element (case node.level
                    ((1) 'h1) ((2) 'h2) ((3) 'h3) ((4) 'h4) ((5) 'h5) ((6) 'h6)
                    (else (string->symbol
                           (string-append "h" (number->string node.level))))) node [] (render-children node context tight? depth) 1))

(def (render-table (node    : djot-table)
                   (context : render-context)
                   (tight?  : :boolean)
                   (depth   : :fixnum)) => :list
  (render-element 'table node [] (render-children node context tight? depth) 2))

(def (render-caption (node    : djot-caption)
                     (context : render-context)
                     (tight?  : :boolean)
                     (depth   : :fixnum)) => :list
  (if (null? node.children) [] (render-element 'caption node [] (render-children node context tight? depth) 1)))

(def (render-row (node    : djot-row)
                 (context : render-context)
                 (tight?  : :boolean)
                 (depth   : :fixnum)) => :list
  (render-element 'tr node [] (render-children node context tight? depth) 2))

(def (render-cell (node    : djot-cell)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element (if node.head? 'th 'td) node (if (eq? node.alignment 'default) []
                                                   [(make-djot-attribute "style"
                                                                         (string-append "text-align: " (symbol->string node.alignment) ";"))]) (render-children node context tight? depth) 1))

(def (render-thematic-break (node    : djot-thematic-break)
                            (context : render-context)
                            (tight?  : :boolean)
                            (depth   : :fixnum)) => :list
  (render-element 'hr node [] [] 1))

(def (render-code-block (node    : djot-code-block)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  (let (language node.language)
    (render-element 'pre node []
                    [(cons 'code (cons (cons '@ (if language [['class (string-append "language-" language)]] []))
                                       [node.text]))] 1)))

(def (render-raw-block (node    : djot-raw-block)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (if (string=? node.format "html") [['*unencoded* node.text]] []))

(def (render-raw-inline (node    : djot-raw-inline)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  (if (string=? node.format "html") [['*unencoded* node.text]] []))

(def (render-text (node    : djot-text)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (if (and (null? node.attributes) (null? node.auto-attributes))
    [node.text] (render-element 'span node [] [node.text] 0)))

(def (render-smart-punctuation (node    : djot-smart-punctuation)
                               (context : render-context)
                               (tight?  : :boolean)
                               (depth   : :fixnum)) => :list
  [(case node.kind
     ((left-single-quote) "‘") ((right-single-quote) "’")
     ((left-double-quote) "“") ((right-double-quote) "”")
     ((ellipses) "…") ((en-dash) "–") ((em-dash) "—")
     (else node.text))])

(def (render-double-quoted (node    : djot-double-quoted)
                           (context : render-context)
                           (tight?  : :boolean)
                           (depth   : :fixnum)) => :list
  (append ["“"] (render-children node context tight? depth) ["”"]))

(def (render-single-quoted (node    : djot-single-quoted)
                           (context : render-context)
                           (tight?  : :boolean)
                           (depth   : :fixnum)) => :list
  (append ["‘"] (render-children node context tight? depth) ["’"]))

(def (render-symbol (node    : djot-symbol)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  [(string-append ":" node.alias ":")])

(def (render-inline-math (node    : djot-inline-math)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element 'span node [(make-djot-attribute "class" "math inline")]
    ["\\(" node.text "\\)"] 0))

(def (render-display-math (node    : djot-display-math)
                          (context : render-context)
                          (tight?  : :boolean)
                          (depth   : :fixnum)) => :list
  (render-element 'span node [(make-djot-attribute "class" "math display")]
    ["\\[" node.text "\\]"] 0))

(def (render-verbatim (node    : djot-verbatim)
                      (context : render-context)
                      (tight?  : :boolean)
                      (depth   : :fixnum)) => :list
  (render-element 'code node [] [node.text] 0))

(def (render-soft-break (node    : djot-soft-break)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  ["\n"])

(def (render-hard-break (node    : djot-hard-break)
                        (context : render-context)
                        (tight?  : :boolean)
                        (depth   : :fixnum)) => :list
  [['br] "\n"])

(def (render-nonbreaking-space (node    : djot-nonbreaking-space)
                               (context : render-context)
                               (tight?  : :boolean)
                               (depth   : :fixnum)) => :list
  [['*unencoded* "&nbsp;"]])

(def (render-link (node    : djot-link)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-reference node context tight? depth))

(def (render-image (node    : djot-image)
                   (context : render-context)
                   (tight?  : :boolean)
                   (depth   : :fixnum)) => :list
  (render-reference node context tight? depth))

(def (render-url (node    : djot-url)
                 (context : render-context)
                 (tight?  : :boolean)
                 (depth   : :fixnum)) => :list
  (render-element 'a node [(make-djot-attribute "href" node.text)] [node.text] 0))

(def (render-email (node    : djot-email)
                   (context : render-context)
                   (tight?  : :boolean)
                   (depth   : :fixnum)) => :list
  (render-element 'a node [(make-djot-attribute "href" (string-append "mailto:" node.text))]
    [node.text] 0))

(def (render-footnote-reference (node    : djot-footnote-reference)
                                (context : render-context)
                                (tight?  : :boolean)
                                (depth   : :fixnum)) => :list
  (render-note-reference node context))

(def (render-strong (node    : djot-strong)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  (render-element 'strong node [] (render-children node context tight? depth) 0))

(def (render-emph (node    : djot-emph)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element 'em node [] (render-children node context tight? depth) 0))

(def (render-span (node    : djot-span)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element 'span node [] (render-children node context tight? depth) 0))

(def (render-mark (node    : djot-mark)
                  (context : render-context)
                  (tight?  : :boolean)
                  (depth   : :fixnum)) => :list
  (render-element 'mark node [] (render-children node context tight? depth) 0))

(def (render-insert (node    : djot-insert)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  (render-element 'ins node [] (render-children node context tight? depth) 0))

(def (render-delete (node    : djot-delete)
                    (context : render-context)
                    (tight?  : :boolean)
                    (depth   : :fixnum)) => :list
  (render-element 'del node [] (render-children node context tight? depth) 0))

(def (render-superscript (node    : djot-superscript)
                         (context : render-context)
                         (tight?  : :boolean)
                         (depth   : :fixnum)) => :list
  (render-element 'sup node [] (render-children node context tight? depth) 0))

(def (render-subscript (node    : djot-subscript)
                       (context : render-context)
                       (tight?  : :boolean)
                       (depth   : :fixnum)) => :list
  (render-element 'sub node [] (render-children node context tight? depth) 0))

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

(def (note-with-backlink (content : :list)
                         (index   : :fixnum)) => :list
  (let* ((backlink ['a ['@ ['href (string-append "#fnref" (number->string index))]
                           ['role "doc-backlink"]] "↩︎"])
         (reversed (reverse content)))
    (if (and (pair? reversed) (equal? (car reversed) "\n")
             (pair? (cdr reversed)) (pair? (cadr reversed)) (eq? (caadr reversed) 'p))
      (reverse (cons "\n" (cons (append (cadr reversed) [backlink]) (cddr reversed))))
      (append content [['p backlink] "\n"]))))

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
               (item (cons 'li (cons ['@ ['id (string-append "fn" (number->string index))]]
                                     (cons "\n" (note-with-backlink content index))))))
          (loop (cdr labels) (cons "\n" (cons item items)))))
       ((pair? context.note-order)
        (let (labels (reverse context.note-order))
          (set! context.note-order [])
          (loop labels items)))
       (else
        [['section ['@ ['role "doc-endnotes"]] "\n" ['hr] "\n"
                   (cons 'ol (cons "\n" (reverse items))) "\n"] "\n"])))))

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

(def (djot->sxml (document : djot-document)) => :list
  (check-render-nesting! document.children 0)
  (check-render-nesting! (map cdr document.footnotes) 0)
  (let* ((references (make-hash-table))
         (context (make-render-context references (make-hash-table) [] (make-hash-table) 1)))
    (for-each
      (lambda ((entry : :pair)) => :void
        (hash-put! references (car entry) (cdr entry)))
      (append document.auto-references document.references))
    (let (content (render-children document context #f 0))
      (cons '*TOP* (if (> (render-context-next-note context) 1)
                     (append content (render-notes document context)) content)))))

(def (djot->html (document : djot-document)) => :string
  (let (port (open-output-string))
    ;; Printing the children also handles the empty document without a dummy node.
    (write-sxml (cdr (djot->sxml document)) port: port xml?: #f indent: #f)
    (get-output-string port)))
