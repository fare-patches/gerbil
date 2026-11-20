;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML tree builder: the tree construction stage of the WHATWG HTML parser
;;; (HTML Living Standard §13.2.6) and the fragment parsing algorithm (§13.4)
;;; over the tokens of ./scanner. Unchecked internals;
;;; :std/text/markup/html/reader checks arguments and makes the tokenizer.
;;;
;;; The builder works on mutable nodes (parent pointers, doubly linked
;;; children) because the algorithm moves nodes: the adoption agency, foster
;;; parenting and template contents. One pass at the end freezes them into
;;; the typed nodes of ./node and ../xml/node, merging adjacent text.
;;;
;;; Not implemented, as they need a DOM with scripts: script execution,
;;; custom elements, declarative shadow roots, template content patching,
;;; the sanitizer, and the selectedcontent element insertion steps.
;;; Parse errors are not reported.
;;;
;;; Depth: the stack of open elements and the list of active formatting
;;; elements hold at most max-open-elements entries; past it, HTMLParseError
;;; is raised (html.md, read-html, states the rule). The list can outgrow
;;; the stack: closing a table pops the elements above it without clearing
;;; their markers and the formatting entries before those markers
;;; (<table><object><table><object>...).
;;; Every search of either is therefore exact and visits max-open-elements
;;; entries at most. Whether a p is in button scope, which a p end tag and
;;; every start tag that closes a p ask, is kept on the open elements
;;; instead (set-p-scope!).
;;; Noah's Ark (push-formatting!) also compares the attributes of each entry
;;; with the new element's, stopping at the first that differs, so a
;;; formatting start tag costs O(max-open-elements × its attributes) at
;;; most. An html or body start tag that adds attributes to the html or
;;; body element costs its own attributes, as the added ones are joined to
;;; the element's once, when the tree is frozen (HTMLMergedAttributes).
(import (only-in ../xml/node
                 unchecked-node
                 XML
                 XMLName
                 XMLAttribute
                 XMLElement
                 XMLText
                 XMLComment
                 XMLPI
                 pairwise-attribute-limit)
        (only-in ../scan-input vector-grow)
        ./node
        ./rules
        ./atoms
        (for-syntax ./atoms)
        ./scanner)
(export build-html-document
        build-html-fragment)
(declare (not safe))

;;; (atom-case expr ((name ...) body ...) ... (else body ...)): case over
;;; atoms, the names being those of ./atoms (an unknown name is a syntax
;;; error).
(begin-syntax
  (def (atom-id stx name)
    (let ((str (symbol->string (stx-e name)))
          (names known-atom-names))
      (let loop ((k 1))
        (cond
         ((fx>= k (vector-length names))
          (raise-syntax-error #f "unknown HTML atom" stx name))
         ((equal? (vector-ref names k) str) k)
         (else (loop (fx+ k 1))))))))

(defsyntax (atom-case stx)
  (syntax-case stx ()
    ((_ expr clause ...)
     (with-syntax (((clause ...)
                    (stx-map (lambda (clause)
                               (syntax-case clause (else)
                                 ((else body ...) clause)
                                 (((name ...) body ...)
                                  (with-syntax (((id ...)
                                                 (stx-map (lambda (name) (atom-id stx name))
                                                          #'(name ...))))
                                    #'((id ...) body ...)))))
                             #'(clause ...))))
       #'(case expr clause ...)))))

;;; Whether a p is in button scope, kept on an open element: state, not a
;;; category, past the category bits of ./rules (set-p-scope!).
(defconst flag-p-scope 8192)

;;; builder nodes

(defconst kind-element 0)
(defconst kind-text 1)
(defconst kind-other 2)          ; comment, processing instruction or DOCTYPE
(defconst kind-document 3)
(defconst kind-contents 4)       ; template contents

;;; A node under construction. Elements keep the name and attributes their
;;; token gave them, which elements recreated for the same token share
;;; (attribute lists are never mutated, but replaced). data holds a text
;;; node's characters (a string, or a list of strings newest first), the typed
;;; node of a comment, processing instruction or DOCTYPE, and the template of
;;; template contents. An HTML template element's children are its contents.
(deftype @HTMLBuilderNode HTMLBuilderNode)
(defstruct HTMLBuilderNode
  ((kind        :- :fixnum)
   (ns          :- :fixnum)
   (atom        :- :fixnum)              ; folded token name; 0 for non-elements
   (flags       :- :fixnum)
   (name        :? XMLName)              ; of an element
   (attributes  :- :list)
   (data        :- :t)
   (parent      :? @HTMLBuilderNode)
   (prev        :? @HTMLBuilderNode)
   (next        :? @HTMLBuilderNode)
   (first       :? @HTMLBuilderNode)
   (last        :? @HTMLBuilderNode)
   (contents    :? @HTMLBuilderNode)     ; template contents of an HTML template
   (open?       :- :boolean)             ; in the stack of open elements
   (formatting? :- :boolean))            ; in the list of active formatting elements
  final: #t)

(defrule (is? node a)
  (using (n node :- HTMLBuilderNode)
    (and (fx= n.atom a) (fx= n.ns ns-html))))

(defrule (flag? node flag)
  (using (n node :- HTMLBuilderNode)
    (not (fx= 0 (fxand n.flags flag)))))

(def (new-node (kind :- :fixnum)
               (data :- :t)) => HTMLBuilderNode
  (make-HTMLBuilderNode kind ns-html 0 0 #f '() data #f #f #f #f #f #f #f #f))

;;; A new element; an HTML template gets its contents.
(def (new-element (ns         :- :fixnum)
                  (atom       :- :fixnum)
                  (flags      :- :fixnum)
                  (name       :- XMLName)
                  (attributes :- :list)) => HTMLBuilderNode
  (using (node (make-HTMLBuilderNode kind-element ns atom flags name attributes #f
                                     #f #f #f #f #f #f #f #f)
               :- HTMLBuilderNode)
    (when (and (fx= atom atom-template) (fx= ns ns-html))
      (set! node.contents (new-node kind-contents node)))
    node))

(def (clone-element (node :- HTMLBuilderNode)) => HTMLBuilderNode
  (new-element node.ns node.atom node.flags node.name node.attributes))

;;; The node that takes the children of node: its contents for an HTML
;;; template.
(def (container-of (node :- HTMLBuilderNode)) => HTMLBuilderNode
  (or node.contents node))

(def (insert-before! (parent :- HTMLBuilderNode)
                     (node   :- HTMLBuilderNode)
                     (before :? HTMLBuilderNode)) => :void
  (set! node.parent parent)
  (set! node.next before)
  (if before
    (begin
      (set! node.prev before.prev)
      (set! before.prev node))
    (begin
      (set! node.prev parent.last)
      (set! parent.last node)))
  (if node.prev
    (set! node.prev.next node)
    (set! parent.first node)))

(def (append-child! (parent :- HTMLBuilderNode)
                    (node   :- HTMLBuilderNode)) => :void
  (insert-before! parent node #f))

;;; Removes node from its parent, if any.
(def (detach! (node :- HTMLBuilderNode)) => :void
  (when node.parent
    (if node.prev
      (set! node.prev.next node.next)
      (set! node.parent.first node.next))
    (if node.next
      (set! node.next.prev node.prev)
      (set! node.parent.last node.prev))
    (set! node.parent #f)
    (set! node.prev #f)
    (set! node.next #f)))

;;; True when a, an element of the stack of open elements newer than the
;;; open elements of b's ancestry, is b or an ancestor of b (through template
;;; contents too). Without scripts an open element's open ancestors are
;;; older than it in the stack, so the walk stops at the first open node
;;; other than a: only closed ancestors are walked, not the whole depth.
(def (inclusive-ancestor? (a :- HTMLBuilderNode)
                          (b :- HTMLBuilderNode)) => :boolean
  (let loop ((node b :- HTMLBuilderNode))
    (cond
     ((eq? node a) #t)
     ((fx= node.kind kind-contents) (loop node.data))
     (node.open? #f)
     (else
      (and node.parent (loop node.parent))))))

;;; parser state

;;; insertion modes
(defconst mode-initial 0)
(defconst mode-before-html 1)
(defconst mode-before-head 2)
(defconst mode-in-head 3)
(defconst mode-in-head-noscript 4)
(defconst mode-after-head 5)
(defconst mode-in-body 6)
(defconst mode-text 7)
(defconst mode-in-table 8)
(defconst mode-in-table-text 9)
(defconst mode-in-caption 10)
(defconst mode-in-column-group 11)
(defconst mode-in-table-body 12)
(defconst mode-in-row 13)
(defconst mode-in-cell 14)
(defconst mode-in-template 15)
(defconst mode-after-body 16)
(defconst mode-in-frameset 17)
(defconst mode-after-frameset 18)
(defconst mode-after-after-body 19)
(defconst mode-after-after-frameset 20)

;;; Longest stack of open elements and list of active formatting elements.
;;; Both start small and grow: allocated at this size, they took 43% more
;;; instructions and 70% more cycles reading small HTML fragments
;;; (markup-benchmark.ss mode html-read-fragments, SIZE 100, ITERATIONS
;;; 400).
(defconst max-open-elements 512)

(defstruct HTMLBuilder
  ((tz               :- HTMLTokenizer)
   (mode             :- :fixnum)
   (original-mode    :- :fixnum)
   (stack            :- :vector)          ; stack of open elements, oldest first
   (top              :- :fixnum)          ; index of the current node, -1 when empty
   (formatting       :- :vector)          ; active formatting elements; #f for a marker
   (formatting-count :- :fixnum)
   (template-modes   :- :list)            ; stack of template insertion modes, newest first
   (templates        :- :fixnum)          ; HTML template elements in the stack
   (document         :- HTMLBuilderNode)
   (head             :? HTMLBuilderNode)  ; head element pointer
   (form             :? HTMLBuilderNode)  ; form element pointer
   (context          :? HTMLBuilderNode)  ; fragment context element
   (scripting?       :- :boolean)
   (frameset-ok?     :- :boolean)
   (foster?          :- :boolean)
   (quirks?          :- :boolean)
   (skip-newline?    :- :boolean)         ; the next token is after pre, listing or textarea
   (text             :- :string)          ; characters of the current character token
   (pending          :- :list)            ; pending table character tokens, newest first
   (pending-space?   :- :boolean)         ; ... are all whitespace
   (pending-start    :- :fixnum)          ; ... the first one's scan input index
   (place-parent     :? HTMLBuilderNode)  ; appropriate place for inserting a node:
   (place-before     :? HTMLBuilderNode)  ; parent and reference child (#f: append)
   (names            :- :vector)          ; XMLName of document atom known-atom-count + 1 + k
   (merged           :- :list))           ; HTMLMergedAttributes of the html and body elements
  final: #t)

;;; The attributes that later html or body start tags add to the html or
;;; body element, kept here and joined to the element's own when the tree
;;; is frozen (join-merged-attributes!), so that each such start tag costs
;;; only its own attributes. A name is compared with each of the first
;;; pairwise-attribute-limit attributes; past them, names holds them all,
;;; built then.
(defstruct HTMLMergedAttributes
  ((element :- HTMLBuilderNode)
   (count   :- :fixnum)     ; of the element's attributes and added
   (names   :? HashTable)   ; by name, past pairwise-attribute-limit
   (added   :- :list))      ; XMLAttribute values, newest first
  final: #t)

(def (new-builder (tz         :- HTMLTokenizer)
                  (scripting? :- :boolean)) => HTMLBuilder
  (make-HTMLBuilder tz mode-initial mode-initial
                    (make-vector 64 #f) -1 (make-vector 16 #f) 0 '() 0
                    (new-node kind-document #f) #f #f #f
                    scripting? #t #f #f #f "" '() #t 0 #f #f
                    (make-vector 16 #f) '()))

;;; XMLName of atom, in no namespace.
(def (atom-name (p    :- HTMLBuilder)
                (atom :- :fixnum)) => XMLName
  (if (fx<= atom known-atom-count)
    (known-name atom)
    (let* ((k (fx- atom (fx+ known-atom-count 1)))
           (names p.names)
           (names (if (fx< k (##vector-length names))
                    names
                    (let (new (vector-grow names (##vector-length names) (fx+ k 1)))
                      (set! p.names new)
                      new))))
      (or (##vector-ref names k)
          (let (name (unchecked-node XMLName (html-atom-name p.tz atom) "" ""))
            (##vector-set! names k name)
            name)))))

;;; The attributes of the current start tag, in no namespace.
(def (token-attributes (p :- HTMLBuilder)) => :list
  (html-token-attribute-list p.tz (atom value)
    (unchecked-node XMLAttribute (atom-name p atom) value)))

;;; The attributes of the current start tag for a foreign element in ns,
;;; adjusted (SVG and MathML case, namespaced attributes).
(def (foreign-attributes (p  :- HTMLBuilder)
                         (ns :- :fixnum)) => :list
  (let (tz p.tz)
    (html-token-attribute-list tz (atom value)
      (unchecked-node XMLAttribute (or (adjusted-foreign-attribute-name ns (html-atom-name tz atom))
                                        (atom-name p atom))
                                    value))))

;;; The value of attribute atom of the current start tag, or #f.
(def (token-attribute (p    :- HTMLBuilder)
                      (atom :- :fixnum)) => (Maybe :string)
  (let* ((attributes p.tz.attributes)
         (n p.tz.attribute-count))
    (let loop ((k 0))
      (cond
       ((fx>= k n) #f)
       ((fx= (##vector-ref attributes (fx* 2 k)) atom)
        (##vector-ref attributes (fx+ (fx* 2 k) 1)))
       (else (loop (fx+ k 1)))))))

;;; whitespace in character tokens

;;; Length of the leading whitespace of str.
(def (space-prefix-end (str :- :string)) => :fixnum
  (let ((n (string-length str)))
    (let loop ((k 0))
      (if (and (fx< k n) (html-space-code? (char->integer (string-ref str k))))
        (loop (fx+ k 1))
        k))))

;;; The whitespace characters of str.
(def (only-space (str :- :string)) => :string
  (if (html-space-string? str)
    str
    (list->string (filter (lambda (c) (html-space-code? (char->integer c))) (string->list str)))))

;;; Raises HTMLParseError at the current token, which would open an element
;;; or formatting entry past max-open-elements; in table text, which opens
;;; elements only when the token after it inserts it, at the text.
(def (raise-nesting-error (p       :- HTMLBuilder)
                          (message :- :string)) => :void
  (let (offset (html-input-offset p.tz (if (fx= p.mode mode-in-table-text)
                                         p.pending-start
                                         p.tz.start)))
    (raise (HTMLParseError message
                           offset: offset
                           where: (if p.context 'read-html-fragment 'read-html)
                           irritants: ['offset offset]))))

;;; stack of open elements

(defrule (current p)
  (using (b p :- HTMLBuilder)
    (##vector-ref b.stack b.top)))

;;; Each open element records in its flag-p-scope whether an HTML p is in
;;; button scope when it is the current node (p-in-button-scope-after), from
;;; its own flags and the record of the element below it (below?, #f for
;;; the oldest), so that the start tags that close a p check it without
;;; searching the stack
;;; (markup-benchmark.ss mode html-read-nested-divs). A flag rather than a
;;; slot, which would enlarge every node.
(definline (set-p-scope! (node   :- HTMLBuilderNode)
                         (below? :- :boolean)) => :void
  (let (flags node.flags)
    (set! node.flags (if (p-in-button-scope-after node.ns node.atom flags below?)
                       (fxior flags flag-p-scope)
                       (fxand flags (fxnot flag-p-scope))))))

;;; Sets the records of the open elements from index k up, after the stack
;;; changed there.
(def (set-p-scope-from! (p :- HTMLBuilder)
                        (k :- :fixnum)) => :void
  (let ((stack p.stack)
        (top p.top))
    (let loop ((j k)
               (below? (and (fx> k 0)
                            (flag? (##vector-ref stack (fx- k 1)) flag-p-scope))))
      (when (fx<= j top)
        (let (node (##vector-ref stack j))
          (set-p-scope! node below?)
          (loop (fx+ j 1) (flag? node flag-p-scope)))))))

(def (push! (p    :- HTMLBuilder)
            (node :- HTMLBuilderNode)) => :void
  (when (fx>= (fx+ p.top 1) max-open-elements)
    (raise-nesting-error p (string-append "elements nested deeper than "
                                         (number->string max-open-elements))))
  (let ((top (fx+ p.top 1))
        (stack p.stack))
    (##vector-set! (if (fx< top (##vector-length stack))
                     stack
                     (let (new (vector-grow stack top 0))
                       (set! p.stack new)
                       new))
                   top node)
    (set-p-scope! node (and (fx> top 0)
                            (flag? (##vector-ref p.stack (fx- top 1)) flag-p-scope)))
    (set! p.top top)
    (set! node.open? #t)
    (when (is? node atom-template)
      (set! p.templates (fx+ p.templates 1)))))

(def (closed! (p    :- HTMLBuilder)
              (node :- HTMLBuilderNode)) => :void
  (set! node.open? #f)
  (when (is? node atom-template)
    (set! p.templates (fx- p.templates 1))))

(def (pop! (p :- HTMLBuilder)) => HTMLBuilderNode
  (let* ((top p.top)
         (node (##vector-ref p.stack top)))
    (##vector-set! p.stack top #f)
    (set! p.top (fx- top 1))
    (closed! p node)
    node))

;;; Pops the elements from the current node down to index k, included.
(def (pop-to! (p :- HTMLBuilder)
              (k :- :fixnum)) => :void
  (let loop ()
    (when (fx>= p.top k)
      (pop! p)
      (loop))))

(def (stack-remove! (p    :- HTMLBuilder)
                    (node :- HTMLBuilderNode)) => :void
  (let ((stack p.stack)
        (top p.top))
    (let find ((k top))
      (when (fx>= k 0)
        (if (eq? (##vector-ref stack k) node)
          (begin
            (subvector-move! stack (fx+ k 1) (fx+ top 1) stack k)
            (##vector-set! stack top #f)
            (set! p.top (fx- top 1))
            (set-p-scope-from! p k)
            (closed! p node))
          (find (fx- k 1)))))))

;;; Index of the newest HTML element with atom in the scope that elements
;;; with a boundary flag end, or -1.
(def (scope-index (p        :- HTMLBuilder)
                  (atom     :- :fixnum)
                  (boundary :- :fixnum)) => :fixnum
  (let (stack p.stack)
    (let loop ((k p.top))
      (if (fx< k 0)
        -1
        (let (node (##vector-ref stack k))
          (cond
           ((is? node atom) k)
           ((flag? node boundary) -1)
           (else (loop (fx- k 1)))))))))

;;; Index of the newest HTML element with a flag in the scope, or -1.
(def (scope-flag-index (p        :- HTMLBuilder)
                       (flag     :- :fixnum)
                       (boundary :- :fixnum)) => :fixnum
  (let (stack p.stack)
    (let loop ((k p.top))
      (if (fx< k 0)
        -1
        (let (node (##vector-ref stack k))
          (cond
           ((flag? node flag) k)
           ((flag? node boundary) -1)
           (else (loop (fx- k 1)))))))))

;;; Index of target in the scope, or -1.
(def (scope-node-index (p        :- HTMLBuilder)
                       (target   :- HTMLBuilderNode)
                       (boundary :- :fixnum)) => :fixnum
  (let (stack p.stack)
    (let loop ((k p.top))
      (if (fx< k 0)
        -1
        (let (node (##vector-ref stack k))
          (cond
           ((eq? node target) k)
           ((flag? node boundary) -1)
           (else (loop (fx- k 1)))))))))

(definline (in-scope? (p        :- HTMLBuilder)
                      (atom     :- :fixnum)
                      (boundary :- :fixnum)) => :boolean
  (fx>= (scope-index p atom boundary) 0))

(definline (p-in-button-scope? (p :- HTMLBuilder)) => :boolean
  (and (fx>= p.top 0) (flag? (current p) flag-p-scope)))

(def (current-is? (p    :- HTMLBuilder)
                  (atom :- :fixnum)) => :boolean
  (and (fx>= p.top 0) (is? (current p) atom)))

(def (adjusted-current (p :- HTMLBuilder)) => HTMLBuilderNode
  (if (and p.context (fx= p.top 0))
    p.context
    (current p)))

(def (parsing-template-contents? (p :- HTMLBuilder)) => :boolean
  (or (fx> p.templates 0)
      (let (context p.context)
        (and context (is? context atom-template)))))

;;; Pops while the current node is closed by implied end tags, except an
;;; HTML element with atom except (0: none).
(def (generate-implied-end-tags! (p      :- HTMLBuilder)
                                 (except :- :fixnum)) => :void
  (let loop ()
    (let (node (current p))
      (when (and (flag? node flag-implied) (not (is? node except)))
        (pop! p)
        (loop)))))

(def (generate-implied-end-tags-thoroughly! (p :- HTMLBuilder)) => :void
  (let loop ()
    (when (flag? (current p) flag-thorough)
      (pop! p)
      (loop))))

;;; Pops until an HTML element with atom has been popped.
(def (pop-until! (p    :- HTMLBuilder)
                 (atom :- :fixnum)) => :void
  (let loop ()
    (when (fx>= p.top 0)
      (unless (is? (pop! p) atom)
        (loop)))))

;;; Pops while the current node is not one of atoms (in the HTML namespace)
;;; or html: clearing the stack back to a table, table body or row context.
(defrule (clear-stack-back! p atom ...)
  (let loop ()
    (let (node (current p))
      (unless (or (is? node atom-html) (is? node atom-template) (is? node atom) ...)
        (pop! p)
        (loop)))))

(def (close-p! (p :- HTMLBuilder)) => :void
  (generate-implied-end-tags! p atom-p)
  (pop-until! p atom-p))

(def (close-p-in-button-scope! (p :- HTMLBuilder)) => :void
  (when (p-in-button-scope? p)
    (close-p! p)))

;;; True when the tree builder ignores a form start tag: the form element
;;; pointer is set and the template contents are not being parsed.
(def (form-ignored? (p :- HTMLBuilder)) => :boolean
  (and p.form (not (parsing-template-contents? p))))

;;; active formatting elements

(def (formatting-push! (p    :- HTMLBuilder)
                       (node :? HTMLBuilderNode)) => :void
  (when (fx>= p.formatting-count max-open-elements)
    (raise-nesting-error p (string-append "more than " (number->string max-open-elements)
                                         " active formatting elements")))
  (let ((n p.formatting-count)
        (list p.formatting))
    (##vector-set! (if (fx< n (##vector-length list))
                     list
                     (let (new (vector-grow list n 0))
                       (set! p.formatting new)
                       new))
                   n node)
    (set! p.formatting-count (fx+ n 1))
    (when node
      (set! node.formatting? #t))))

(def (formatting-index (p    :- HTMLBuilder)
                       (node :- HTMLBuilderNode)) => :fixnum
  (let ((list p.formatting))
    (let loop ((k (fx- p.formatting-count 1)))
      (cond
       ((fx< k 0) -1)
       ((eq? (##vector-ref list k) node) k)
       (else (loop (fx- k 1)))))))

(def (formatting-remove-at! (p :- HTMLBuilder)
                            (k :- :fixnum)) => :void
  (let* ((list p.formatting)
         (n (fx- p.formatting-count 1))
         (node (##vector-ref list k)))
    (subvector-move! list (fx+ k 1) (fx+ n 1) list k)
    (##vector-set! list n #f)
    (set! p.formatting-count n)
    (when node
      (using (node :- HTMLBuilderNode) (set! node.formatting? #f)))))

(def (formatting-insert-at! (p    :- HTMLBuilder)
                            (k    :- :fixnum)
                            (node :- HTMLBuilderNode)) => :void
  (formatting-push! p #f)
  (let* ((list p.formatting)
         (n (fx- p.formatting-count 1)))
    (subvector-move! list k n list (fx+ k 1))
    (##vector-set! list k node)
    (set! node.formatting? #t)))

;;; Index of the newest HTML element with atom after the last marker, or -1.
(def (formatting-find (p    :- HTMLBuilder)
                      (atom :- :fixnum)) => :fixnum
  (let (list p.formatting)
    (let loop ((k (fx- p.formatting-count 1)))
      (if (fx< k 0)
        -1
        (let (node (##vector-ref list k))
          (cond
           ((not node) -1)
           ((is? node atom) k)
           (else (loop (fx- k 1)))))))))

;;; Whether attrs, an entry's, have the names and values of new, the n
;;; attributes of the element being pushed (names are distinct in each): looks
;;; each up in new, or past pairwise-attribute-limit in table, new's values by
;;; name; stops at the first that differs.
(def (same-attributes? (attrs :- :list)
                       (new   :- :list)
                       (n     :- :fixnum)
                       (table :? HashTable)) => :boolean
  (let loop ((rest attrs) (count 0))
    (cond
     ((null? rest) (fx= count n))
     ((fx= count n) #f)
     (else
      (using (attr (car rest) :- XMLAttribute)
        (let* ((name attr.name)
               (value (if table
                        (hash-get table name)
                        (let find ((other new))
                          (and (pair? other)
                               (using (o (car other) :- XMLAttribute)
                                 (if (eq? o.name name)
                                   o.value
                                   (find (cdr other)))))))))
          (and value
               (string=? value attr.value)
               (loop (cdr rest) (fx+ count 1)))))))))

;;; The values of the attributes attrs by name; names are eq? per atom.
(def (attribute-table (attrs :- :list)) => HashTable
  (let (table (make-hash-table-eq))
    (for-each (lambda ((attr :- XMLAttribute)) (hash-put! table attr.name attr.value))
              attrs)
    table))

;;; Pushes node onto the list of active formatting elements, first removing
;;; the earliest of three entries with its name and attributes (Noah's Ark).
;;; At the first entry with its name, counts node's attributes (n, -1 before)
;;; and, past pairwise-attribute-limit, puts them in a table once for all the
;;; entries; most pushes meet no such entry.
(def (push-formatting! (p    :- HTMLBuilder)
                       (node :- HTMLBuilderNode)) => :void
  (let* ((list p.formatting)
         (atom node.atom)
         (attributes node.attributes))
    (let loop ((k (fx- p.formatting-count 1)) (count 0) (earliest -1) (n -1) (table #f))
      (let (entry (and (fx>= k 0) (##vector-ref list k)))
        (if entry
          (using (entry :- HTMLBuilderNode)
            (if (and (fx= entry.atom atom) (fx= entry.ns ns-html))
              (let* ((n (if (fx< n 0) (length attributes) n))
                     (table (or table
                                (and (fx> n pairwise-attribute-limit)
                                     (attribute-table attributes)))))
                (if (same-attributes? entry.attributes attributes n table)
                  (loop (fx- k 1) (fx+ count 1) k n table)
                  (loop (fx- k 1) count earliest n table)))
              (loop (fx- k 1) count earliest n table)))
          (when (fx>= count 3)
            (formatting-remove-at! p earliest)))))
    (formatting-push! p node)))

(def (clear-formatting-to-marker! (p :- HTMLBuilder)) => :void
  (let loop ()
    (let (k (fx- p.formatting-count 1))
      (when (fx>= k 0)
        (let (entry (##vector-ref p.formatting k))
          (formatting-remove-at! p k)
          (when entry
            (loop)))))))

;;; Reconstructs the active formatting elements. Each one reopened is pushed,
;;; so a token reopens fewer than max-open-elements.
(def (reconstruct-formatting! (p :- HTMLBuilder)) => :void
  (let* ((list p.formatting)
         (last (fx- p.formatting-count 1)))
    (def (stop? k)
      (let (entry (##vector-ref list k))
        (or (not entry)
            (using (entry :- HTMLBuilderNode) entry.open?))))
    (unless (or (fx< last 0) (stop? last))
      (let rewind ((k last))
        (if (and (fx> k 0) (not (stop? (fx- k 1))))
          (rewind (fx- k 1))
          (let create ((k k))
            (when (fx<= k last)
              (using ((entry (##vector-ref list k) :- HTMLBuilderNode)
                      (node (clone-element entry) :- HTMLBuilderNode))
                (insert-element! p node)
                (push! p node)
                (set! entry.formatting? #f)
                (##vector-set! list k node)
                (set! node.formatting? #t)
                (create (fx+ k 1))))))))))

;;; inserting nodes

;;; Sets the appropriate place for inserting a node into target.
(def (appropriate-place! (p      :- HTMLBuilder)
                         (target :- HTMLBuilderNode)) => :void
  (if (and p.foster? (flag? target flag-foster))
    (foster-place! p)
    (begin
      (set! p.place-parent (container-of target))
      (set! p.place-before #f))))

;;; Foster parenting: before the last table, or in the last template.
(def (foster-place! (p :- HTMLBuilder)) => :void
  (let (stack p.stack)
    (let loop ((k p.top))
      (if (fx< k 0)
        (begin
          (set! p.place-parent (##vector-ref stack 0))
          (set! p.place-before #f))
        (let (node (##vector-ref stack k))
          (using (node :- HTMLBuilderNode)
            (cond
             ((not node)                ; removed by the adoption agency, not compacted yet
              (loop (fx- k 1)))
             ((is? node atom-template)
              (set! p.place-parent node.contents)
              (set! p.place-before #f))
             ((is? node atom-table)
              (let (parent node.parent)
                (if parent
                  (begin
                    (set! p.place-parent parent)
                    (set! p.place-before node))
                  (begin
                    (set! p.place-parent (container-of (##vector-ref stack (fx- k 1))))
                    (set! p.place-before #f)))))
             (else (loop (fx- k 1))))))))))

(def (insert-element! (p    :- HTMLBuilder)
                      (node :- HTMLBuilderNode)) => :void
  (appropriate-place! p (current p))
  (insert-before! p.place-parent node p.place-before))

;;; Inserts and pushes an HTML element.
(def (insert-html-element! (p          :- HTMLBuilder)
                           (atom       :- :fixnum)
                           (attributes :- :list)) => HTMLBuilderNode
  (let (node (new-element ns-html atom (html-element-flags atom) (atom-name p atom) attributes))
    (insert-element! p node)
    (push! p node)
    node))

;;; Inserts and pushes an HTML element for the current start tag.
(def (insert-token-element! (p :- HTMLBuilder)) => HTMLBuilderNode
  (let (atom p.tz.tag)
    (insert-html-element! p atom (token-attributes p))))

;;; Inserts and pushes a foreign element in ns for the current start tag.
(def (insert-foreign-element! (p  :- HTMLBuilder)
                              (ns :- :fixnum)) => HTMLBuilderNode
  (let* ((tz p.tz)
         (atom p.tz.tag)
         (local (adjusted-element-local ns (html-atom-name tz atom)))
         (name (unchecked-node XMLName local (if (fx= ns ns-svg) svg-namespace-uri mathml-namespace-uri) ""))
         (encoding (and (fx= ns ns-mathml) (fx= atom atom-annotation-xml)
                        (token-attribute p atom-encoding)))
         (node (new-element ns atom (foreign-flags ns local encoding) name
                            (foreign-attributes p ns))))
    (insert-element! p node)
    (push! p node)
    node))

;;; Inserts characters at the appropriate place, appending to a text node
;;; just before it.
(def (insert-text! (p   :- HTMLBuilder)
                   (str :- :string)) => :void
  (appropriate-place! p (current p))
  (unless (fx= p.place-parent.kind kind-document)
    (using (prev (if p.place-before p.place-before.prev p.place-parent.last) :? HTMLBuilderNode)
      (if (and prev (fx= prev.kind kind-text))
        (let (data prev.data)
          (set! prev.data (if (string? data) [str data] (cons str data))))
        (insert-before! p.place-parent (new-node kind-text str) p.place-before)))))

;;; The typed comment or processing instruction of the current token.
(def (token-other (p    :- HTMLBuilder)
                  (kind :- :fixnum)) => XML
  (if (fx= kind html-token-comment)
    (unchecked-node XMLComment p.tz.data)
    (unchecked-node XMLPI p.tz.target p.tz.data)))

;;; Inserts the current comment or processing instruction token into parent,
;;; or at the appropriate place when parent is #f.
(def (insert-other! (p      :- HTMLBuilder)
                    (kind   :- :fixnum)
                    (parent :? HTMLBuilderNode)) => :void
  (let (node (new-node kind-other (token-other p kind)))
    (if parent
      (append-child! parent node)
      (begin
        (appropriate-place! p (current p))
        (insert-before! p.place-parent node p.place-before)))))

;;; True when the element of merged has an attribute named name, or one
;;; was added.
(def (merged-attribute? (merged :- HTMLMergedAttributes)
                        (name   :- XMLName)) => :boolean
  (def (named? (attrs :- :list)) => :boolean
    (let loop ((rest attrs))
      (and (pair? rest)
           (or (using (attr (car rest) :- XMLAttribute) (eq? attr.name name))
               (loop (cdr rest))))))
  (cond
   (merged.names (hash-key? merged.names name))
   ((fx> merged.count pairwise-attribute-limit)
    (let (names (attribute-table merged.element.attributes))
      (for-each (lambda ((attr :- XMLAttribute)) (hash-put! names attr.name attr.value))
                merged.added)
      (set! merged.names names)
      (hash-key? names name)))
   (else
    (or (named? merged.element.attributes) (named? merged.added)))))

;;; Adds the attributes of the current start tag that element, the html or
;;; body element, lacks, to its HTMLMergedAttributes.
(def (merge-attributes! (p       :- HTMLBuilder)
                        (element :- HTMLBuilderNode)) => :void
  (unless (fx= p.tz.attribute-count 0)
    (using (merged (or (find (lambda ((merged :- HTMLMergedAttributes))
                               (eq? merged.element element))
                             p.merged)
                       (let (merged (make-HTMLMergedAttributes
                                     element (length element.attributes) #f '()))
                         (set! p.merged (cons merged p.merged))
                         merged))
                   :- HTMLMergedAttributes)
      (for-each (lambda ((attr :- XMLAttribute))
                  (unless (merged-attribute? merged attr.name)
                    (when merged.names
                      (hash-put! merged.names attr.name attr.value))
                    (set! merged.added (cons attr merged.added))
                    (set! merged.count (fx+ merged.count 1))))
                (token-attributes p)))))

;;; Appends the attributes merge-attributes! added to their elements.
(def (join-merged-attributes! (p :- HTMLBuilder)) => :void
  (for-each (lambda ((merged :- HTMLMergedAttributes))
              (using (element merged.element :- HTMLBuilderNode)
                (set! element.attributes (append element.attributes (reverse merged.added)))))
            p.merged))

;;; token kinds

(definline (characters? (kind :- :fixnum)) => :boolean
  (or (fx= kind html-token-characters) (fx= kind html-token-null-character)))

(definline (other? (kind :- :fixnum)) => :boolean
  (or (fx= kind html-token-comment) (fx= kind html-token-pi)))

;;; Splits the current character token: handles its leading whitespace with
;;; space (an expression using the variable space, the whitespace string),
;;; then the rest, if any, with rest (an expression; p.text is the rest).
(defrule (split-space p kind space-var space rest)
  (if (fx= kind html-token-null-character)
    rest
    (using (b p :- HTMLBuilder)
      (let* ((str b.text)
             (n (space-prefix-end str))
             (len (string-length str)))
        (cond
         ((fx= n len)
          (let (space-var str) space))
         (else
          (when (fx> n 0)
            (let (space-var (substring str 0 n)) space))
          (set! b.text (if (fx= n 0) str (substring str n len)))
          rest))))))

;;; dispatch

;;; True when the token is processed by the insertion mode rules (HTML
;;; content), false for the rules for foreign content.
(def (html-content? (p    :- HTMLBuilder)
                    (kind :- :fixnum)) => :boolean
  (or (fx< p.top 0)
      (fx= kind html-token-eof)
      (using (node (adjusted-current p) :- HTMLBuilderNode)
        (or (fx= node.ns ns-html)
            (cond
             ((fx= kind html-token-start-tag)
              (let (atom p.tz.tag)
                (or (and (flag? node flag-text-point)
                         (not (fx= atom atom-mglyph))
                         (not (fx= atom atom-malignmark)))
                    (and (fx= node.ns ns-mathml) (fx= node.atom atom-annotation-xml)
                         (fx= atom atom-svg))
                    (flag? node flag-html-point))))
             ((characters? kind)
              (flag? node (fxior flag-text-point flag-html-point)))
             (else #f))))))

(def (dispatch (p    :- HTMLBuilder)
               (kind :- :fixnum)) => :void
  (if (html-content? p kind)
    (process-in-mode p kind)
    (in-foreign-content p kind)))

;;; Processes the token by the rules of the current insertion mode.
(def (process-in-mode (p    :- HTMLBuilder)
                      (kind :- :fixnum)) => :void
  (let (mode p.mode)
    (cond
     ((fx= mode mode-in-body) (in-body p kind))
     ((fx= mode mode-text) (in-text p kind))
     ((fx= mode mode-in-cell) (in-cell p kind))
     ((fx= mode mode-in-row) (in-row p kind))
     ((fx= mode mode-in-table-body) (in-table-body p kind))
     ((fx= mode mode-in-table) (in-table p kind))
     ((fx= mode mode-in-table-text) (in-table-text p kind))
     ((fx= mode mode-in-head) (in-head p kind))
     ((fx= mode mode-after-head) (after-head p kind))
     ((fx= mode mode-before-head) (before-head p kind))
     ((fx= mode mode-before-html) (before-html p kind))
     ((fx= mode mode-initial) (initial p kind))
     ((fx= mode mode-in-caption) (in-caption p kind))
     ((fx= mode mode-in-column-group) (in-column-group p kind))
     ((fx= mode mode-in-template) (in-template p kind))
     ((fx= mode mode-in-head-noscript) (in-head-noscript p kind))
     ((fx= mode mode-after-body) (after-body p kind))
     ((fx= mode mode-in-frameset) (in-frameset p kind))
     ((fx= mode mode-after-frameset) (after-frameset p kind))
     ((fx= mode mode-after-after-body) (after-after-body p kind))
     (else (after-after-frameset p kind)))))

;;; Resets the insertion mode appropriately.
(def (reset-insertion-mode! (p :- HTMLBuilder)) => :void
  (let (stack p.stack)
    (let loop ((k p.top))
      (let* ((last? (fx= k 0))
             (node (if (and last? p.context) p.context (##vector-ref stack k))))
        (def (next)
          (if last?
            (set! p.mode mode-in-body)
            (loop (fx- k 1))))
        (using (node :- HTMLBuilderNode)
          (if (fx= node.ns ns-html)
            (atom-case node.atom
              ((td th) (if last? (next) (set! p.mode mode-in-cell)))
              ((tr) (set! p.mode mode-in-row))
              ((tbody thead tfoot) (set! p.mode mode-in-table-body))
              ((caption) (set! p.mode mode-in-caption))
              ((colgroup) (set! p.mode mode-in-column-group))
              ((table) (set! p.mode mode-in-table))
              ((template)
               (let (modes p.template-modes)
                 (set! p.mode (if (pair? modes) (car modes) mode-in-body))))
              ((head) (if last? (next) (set! p.mode mode-in-head)))
              ((body) (set! p.mode mode-in-body))
              ((frameset) (set! p.mode mode-in-frameset))
              ((html) (set! p.mode (if p.head mode-after-head mode-before-head)))
              (else (next)))
            (next)))))))

;;; the "initial" insertion mode

;;; Public identifiers that put the document in quirks mode, as prefixes
;;; (ASCII case-insensitive).
(def quirks-public-prefixes
  ["+//silmaril//dtd html pro v0r11 19970101//"
   "-//as//dtd html 3.0 aswedit + extensions//"
   "-//advasoft ltd//dtd html 3.0 aswedit + extensions//"
   "-//ietf//dtd html 2.0 level 1//"
   "-//ietf//dtd html 2.0 level 2//"
   "-//ietf//dtd html 2.0 strict level 1//"
   "-//ietf//dtd html 2.0 strict level 2//"
   "-//ietf//dtd html 2.0 strict//"
   "-//ietf//dtd html 2.0//"
   "-//ietf//dtd html 2.1e//"
   "-//ietf//dtd html 3.0//"
   "-//ietf//dtd html 3.2 final//"
   "-//ietf//dtd html 3.2//"
   "-//ietf//dtd html 3//"
   "-//ietf//dtd html level 0//"
   "-//ietf//dtd html level 1//"
   "-//ietf//dtd html level 2//"
   "-//ietf//dtd html level 3//"
   "-//ietf//dtd html strict level 0//"
   "-//ietf//dtd html strict level 1//"
   "-//ietf//dtd html strict level 2//"
   "-//ietf//dtd html strict level 3//"
   "-//ietf//dtd html strict//"
   "-//ietf//dtd html//"
   "-//metrius//dtd metrius presentational//"
   "-//microsoft//dtd internet explorer 2.0 html strict//"
   "-//microsoft//dtd internet explorer 2.0 html//"
   "-//microsoft//dtd internet explorer 2.0 tables//"
   "-//microsoft//dtd internet explorer 3.0 html strict//"
   "-//microsoft//dtd internet explorer 3.0 html//"
   "-//microsoft//dtd internet explorer 3.0 tables//"
   "-//netscape comm. corp.//dtd html//"
   "-//netscape comm. corp.//dtd strict html//"
   "-//o'reilly and associates//dtd html 2.0//"
   "-//o'reilly and associates//dtd html extended 1.0//"
   "-//o'reilly and associates//dtd html extended relaxed 1.0//"
   "-//sq//dtd html 2.0 hotmetal + extensions//"
   "-//softquad software//dtd hotmetal pro 6.0::19990601::extensions to html 4.0//"
   "-//softquad//dtd hotmetal pro 4.0::19971010::extensions to html 4.0//"
   "-//spyglass//dtd html 2.0 extended//"
   "-//sun microsystems corp.//dtd hotjava html//"
   "-//sun microsystems corp.//dtd hotjava strict html//"
   "-//w3c//dtd html 3 1995-03-24//"
   "-//w3c//dtd html 3.2 draft//"
   "-//w3c//dtd html 3.2 final//"
   "-//w3c//dtd html 3.2//"
   "-//w3c//dtd html 3.2s draft//"
   "-//w3c//dtd html 4.0 frameset//"
   "-//w3c//dtd html 4.0 transitional//"
   "-//w3c//dtd html experimental 19960712//"
   "-//w3c//dtd html experimental 970421//"
   "-//w3c//dtd w3 html//"
   "-//w3o//dtd w3 html 3.0//"
   "-//webtechs//dtd mozilla html 2.0//"
   "-//webtechs//dtd mozilla html//"])

;;; True when the current DOCTYPE token sets quirks mode.
(def (quirks-doctype? (p :- HTMLBuilder)) => :boolean
  (let* ((name p.tz.doctype-name)
         (public p.tz.public-id)
         (system p.tz.system-id))
    (or p.tz.force-quirks?
        (not (equal? name "html"))
        (and public
             (or (ascii-ci=? public "-//W3O//DTD W3 HTML Strict 3.0//EN//")
                 (ascii-ci=? public "-/W3C/DTD HTML 4.0 Transitional/EN")
                 (ascii-ci=? public "HTML")
                 (ormap (lambda (prefix) (ascii-ci-prefix? prefix public))
                        quirks-public-prefixes)
                 (and (not system)
                      (or (ascii-ci-prefix? "-//W3C//DTD HTML 4.01 Frameset//" public)
                          (ascii-ci-prefix? "-//W3C//DTD HTML 4.01 Transitional//" public)))))
        (and system
             (ascii-ci=? system "http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd")))))

(def (initial (p    :- HTMLBuilder)
              (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (split-space p kind space (void) (initial-anything p kind)))
   ((other? kind) (insert-other! p kind p.document))
   ((fx= kind html-token-doctype)
    (append-child! p.document
                   (new-node kind-other
                             (unchecked-node HTMLDoctype (or p.tz.doctype-name "")
                                                         p.tz.public-id p.tz.system-id)))
    (set! p.quirks? (quirks-doctype? p))
    (set! p.mode mode-before-html))
   (else (initial-anything p kind))))

(def (initial-anything (p    :- HTMLBuilder)
                       (kind :- :fixnum)) => :void
  (set! p.quirks? #t)
  (set! p.mode mode-before-html)
  (dispatch p kind))

;;; the "before html" insertion mode

(def (before-html (p    :- HTMLBuilder)
                  (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-doctype) (void))
   ((other? kind) (insert-other! p kind p.document))
   ((characters? kind)
    (split-space p kind space (void) (before-html-anything p kind)))
   ((and (fx= kind html-token-start-tag) (fx= p.tz.tag atom-html))
    (let (node (new-element ns-html atom-html (html-element-flags atom-html)
                            (atom-name p atom-html) (token-attributes p)))
      (append-child! p.document node)
      (push! p node)
      (set! p.mode mode-before-head)))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((head body html br) (before-html-anything p kind))
      (else (void))))
   (else (before-html-anything p kind))))

(def (before-html-anything (p    :- HTMLBuilder)
                           (kind :- :fixnum)) => :void
  (let (node (new-element ns-html atom-html (html-element-flags atom-html)
                          (atom-name p atom-html) '()))
    (append-child! p.document node)
    (push! p node)
    (set! p.mode mode-before-head)
    (dispatch p kind)))

;;; the "before head" insertion mode

(def (before-head (p    :- HTMLBuilder)
                  (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (split-space p kind space (void) (before-head-anything p kind)))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((head)
       (set! p.head (insert-token-element! p))
       (set! p.mode mode-in-head))
      (else (before-head-anything p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((head body html br) (before-head-anything p kind))
      (else (void))))
   (else (before-head-anything p kind))))

(def (before-head-anything (p    :- HTMLBuilder)
                           (kind :- :fixnum)) => :void
  (set! p.head (insert-html-element! p atom-head '()))
  (set! p.mode mode-in-head)
  (dispatch p kind))

;;; the "in head" insertion mode

;;; The generic raw text (rawtext? true) or RCDATA element parsing algorithm.
(def (raw-text-element! (p        :- HTMLBuilder)
                        (rawtext? :- :boolean)) => :void
  (insert-token-element! p)
  (set! p.tz.state (if rawtext? html-state-rawtext html-state-rcdata))
  (set! p.original-mode p.mode)
  (set! p.mode mode-text))

(def (in-head (p    :- HTMLBuilder)
              (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (split-space p kind space (insert-text! p space) (in-head-anything p kind)))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((base basefont bgsound link meta)
       (insert-token-element! p)
       (pop! p))
      ((title) (raw-text-element! p #f))
      ((noscript)
       (if p.scripting?
         (raw-text-element! p #t)
         (begin
           (insert-token-element! p)
           (set! p.mode mode-in-head-noscript))))
      ((noframes style) (raw-text-element! p #t))
      ((script)
       (insert-token-element! p)
       (set! p.tz.state html-state-script-data)
       (set! p.original-mode p.mode)
       (set! p.mode mode-text))
      ((template)
       (formatting-push! p #f)
       (set! p.frameset-ok? #f)
       (set! p.mode mode-in-template)
       (set! p.template-modes (cons mode-in-template p.template-modes))
       (insert-token-element! p))
      ((head) (void))
      (else (in-head-anything p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((head)
       (pop! p)
       (set! p.mode mode-after-head))
      ((body html br) (in-head-anything p kind))
      ((template) (end-template! p))
      (else (void))))
   (else (in-head-anything p kind))))

(def (in-head-anything (p    :- HTMLBuilder)
                       (kind :- :fixnum)) => :void
  (pop! p)
  (set! p.mode mode-after-head)
  (dispatch p kind))

;;; A template end tag, in the "in head" insertion mode.
(def (end-template! (p :- HTMLBuilder)) => :void
  (when (fx> p.templates 0)
    (generate-implied-end-tags-thoroughly! p)
    (pop-until! p atom-template)
    (clear-formatting-to-marker! p)
    (let (modes p.template-modes)
      (when (pair? modes)
        (set! p.template-modes (cdr modes))))
    (reset-insertion-mode! p)))

;;; the "in head noscript" insertion mode

(def (in-head-noscript (p    :- HTMLBuilder)
                       (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((basefont bgsound link meta noframes style) (in-head p kind))
      ((head noscript) (void))
      (else (in-head-noscript-anything p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((noscript)
       (pop! p)
       (set! p.mode mode-in-head))
      ((br) (in-head-noscript-anything p kind))
      (else (void))))
   ((characters? kind)
    (split-space p kind space (insert-text! p space) (in-head-noscript-anything p kind)))
   ((other? kind) (insert-other! p kind #f))
   (else (in-head-noscript-anything p kind))))

(def (in-head-noscript-anything (p    :- HTMLBuilder)
                                (kind :- :fixnum)) => :void
  (pop! p)
  (set! p.mode mode-in-head)
  (dispatch p kind))

;;; the "after head" insertion mode

(def (after-head (p    :- HTMLBuilder)
                 (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (split-space p kind space (insert-text! p space) (after-head-anything p kind)))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((body)
       (insert-token-element! p)
       (set! p.frameset-ok? #f)
       (set! p.mode mode-in-body))
      ((frameset)
       (insert-token-element! p)
       (set! p.mode mode-in-frameset))
      ((base basefont bgsound link meta noframes script style template title)
       (let (head p.head)
         (push! p head)
         (in-head p kind)
         (stack-remove! p head)))
      ((head) (void))
      (else (after-head-anything p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((template) (in-head p kind))
      ((body html br) (after-head-anything p kind))
      (else (void))))
   (else (after-head-anything p kind))))

(def (after-head-anything (p    :- HTMLBuilder)
                          (kind :- :fixnum)) => :void
  (insert-html-element! p atom-body '())
  (set! p.frameset-ok? #t)
  (set! p.mode mode-in-body)
  (dispatch p kind))

;;; the "in body" insertion mode

(def (in-body (p    :- HTMLBuilder)
              (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-characters)
    (let (str p.text)
      (reconstruct-formatting! p)
      (insert-text! p str)
      (when (and p.frameset-ok? (not (html-space-string? str)))
        (set! p.frameset-ok? #f))))
   ((fx= kind html-token-start-tag) (in-body-start-tag p kind p.tz.tag))
   ((fx= kind html-token-end-tag) (in-body-end-tag p kind p.tz.tag))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-eof)
    (when (pair? p.template-modes)
      (in-template p kind)))
   (else (void))))

;;; The start tag for the HTML element atom: its attributes are those of the
;;; current token, which has none when it is a br end tag.
(def (in-body-start-tag (p    :- HTMLBuilder)
                        (kind :- :fixnum)
                        (atom :- :fixnum)) => :void
  (when (start-tag-closes-p? atom p.quirks? (form-ignored? p))
    (cond
     ((fx= atom atom-li) (list-item-steps! p atom-li atom-li))
     ((or (fx= atom atom-dd) (fx= atom atom-dt)) (list-item-steps! p atom-dd atom-dt)))
    (close-p-in-button-scope! p))
  (atom-case atom
    ((html)
     (when (fx= p.templates 0)
       (merge-attributes! p (##vector-ref p.stack 0))))
    ((base basefont bgsound link meta noframes script style template title)
     (in-head p kind))
    ((body)
     (let (stack p.stack)
       (unless (or (fx= p.top 0)
                   (not (is? (##vector-ref stack 1) atom-body))
                   (fx> p.templates 0))
         (set! p.frameset-ok? #f)
         (merge-attributes! p (##vector-ref stack 1)))))
    ((frameset)
     (let (stack p.stack)
       (unless (or (fx= p.top 0)
                   (not (is? (##vector-ref stack 1) atom-body))
                   (not p.frameset-ok?))
         (detach! (##vector-ref stack 1))
         (pop-to! p 1)
         (insert-token-element! p)
         (set! p.mode mode-in-frameset))))
    ((address article aside blockquote center details dialog dir div dl fieldset
      figcaption figure footer header hgroup main menu nav ol p search section
      summary ul)
     (insert-token-element! p))
    ((h1 h2 h3 h4 h5 h6)
     (when (flag? (current p) flag-heading)
       (pop! p))
     (insert-token-element! p))
    ((pre listing)
     (insert-token-element! p)
     (set! p.skip-newline? #t)
     (set! p.frameset-ok? #f))
    ((form)
     (unless (form-ignored? p)
       (let (node (insert-token-element! p))
         (unless (parsing-template-contents? p)
           (set! p.form node)))))
    ((li dd dt)
     (set! p.frameset-ok? #f)
     (insert-token-element! p))
    ((plaintext)
     (insert-token-element! p)
     (set! p.tz.state html-state-plaintext))
    ((button)
     (when (in-scope? p atom-button flag-scope)
       (generate-implied-end-tags! p 0)
       (pop-until! p atom-button))
     (reconstruct-formatting! p)
     (insert-token-element! p)
     (set! p.frameset-ok? #f))
    ((a)
     (let (k (formatting-find p atom-a))
       (when (fx>= k 0)
         (let (node (##vector-ref p.formatting k))
           (adoption-agency! p atom-a)
           (using (node :- HTMLBuilderNode)
             (when node.formatting?
               (formatting-remove-at! p (formatting-index p node)))
             (when node.open?
               (stack-remove! p node))))))
     (reconstruct-formatting! p)
     (push-formatting! p (insert-token-element! p)))
    ((b big code em font i s small strike strong tt u)
     (reconstruct-formatting! p)
     (push-formatting! p (insert-token-element! p)))
    ((nobr)
     (reconstruct-formatting! p)
     (when (in-scope? p atom-nobr flag-scope)
       (adoption-agency! p atom-nobr)
       (reconstruct-formatting! p))
     (push-formatting! p (insert-token-element! p)))
    ((applet marquee object)
     (reconstruct-formatting! p)
     (insert-token-element! p)
     (formatting-push! p #f)
     (set! p.frameset-ok? #f))
    ((table)
     (insert-token-element! p)
     (set! p.frameset-ok? #f)
     (set! p.mode mode-in-table))
    ((area br embed img keygen wbr)
     (reconstruct-formatting! p)
     (insert-html-element! p atom (token-attributes p))
     (pop! p)
     (set! p.frameset-ok? #f))
    ((input)
     (unless (let (context p.context) (and context (is? context atom-select)))
       (let (k (scope-index p atom-select flag-scope))
         (when (fx>= k 0)
           (pop-to! p k)))
       (reconstruct-formatting! p)
       (insert-token-element! p)
       (pop! p)
       (unless (let (type (token-attribute p atom-type))
                 (and type (ascii-ci=? type "hidden")))
         (set! p.frameset-ok? #f))))
    ((param source track)
     (insert-token-element! p)
     (pop! p))
    ((hr)
     (when (in-scope? p atom-select flag-scope)
       (generate-implied-end-tags! p 0))
     (insert-token-element! p)
     (pop! p)
     (set! p.frameset-ok? #f))
    ((image)
     (set! p.tz.tag atom-img)
     (dispatch p kind))
    ((textarea)
     (insert-token-element! p)
     (set! p.skip-newline? #t)
     (set! p.tz.state html-state-rcdata)
     (set! p.original-mode p.mode)
     (set! p.frameset-ok? #f)
     (set! p.mode mode-text))
    ((xmp)
     (reconstruct-formatting! p)
     (set! p.frameset-ok? #f)
     (raw-text-element! p #t))
    ((iframe)
     (set! p.frameset-ok? #f)
     (raw-text-element! p #t))
    ((noembed) (raw-text-element! p #t))
    ((noscript)
     (if p.scripting?
       (raw-text-element! p #t)
       (begin
         (reconstruct-formatting! p)
         (insert-token-element! p))))
    ((select)
     (unless (let (context p.context) (and context (is? context atom-select)))
       (let (k (scope-index p atom-select flag-scope))
         (if (fx>= k 0)
           (pop-to! p k)
           (begin
             (reconstruct-formatting! p)
             (insert-token-element! p)
             (set! p.frameset-ok? #f))))))
    ((option)
     (if (in-scope? p atom-select flag-scope)
       (generate-implied-end-tags! p atom-optgroup)
       (when (current-is? p atom-option)
         (pop! p)))
     (reconstruct-formatting! p)
     (insert-token-element! p))
    ((optgroup)
     (if (in-scope? p atom-select flag-scope)
       (generate-implied-end-tags! p 0)
       (when (current-is? p atom-option)
         (pop! p)))
     (reconstruct-formatting! p)
     (insert-token-element! p))
    ((rb rtc)
     (when (in-scope? p atom-ruby flag-scope)
       (generate-implied-end-tags! p 0))
     (insert-token-element! p))
    ((rp rt)
     (when (in-scope? p atom-ruby flag-scope)
       (generate-implied-end-tags! p atom-rtc))
     (insert-token-element! p))
    ((math)
     (reconstruct-formatting! p)
     (insert-foreign-element! p ns-mathml)
     (when p.tz.self-closing?
       (pop! p)))
    ((svg)
     (reconstruct-formatting! p)
     (insert-foreign-element! p ns-svg)
     (when p.tz.self-closing?
       (pop! p)))
    ((caption col colgroup frame head tbody td tfoot th thead tr) (void))
    (else
     (reconstruct-formatting! p)
     (insert-token-element! p))))

;;; The list item steps of an li (li, li) or dd/dt (dd, dt) start tag.
(def (list-item-steps! (p  :- HTMLBuilder)
                       (a  :- :fixnum)
                       (b  :- :fixnum)) => :void
  (let (stack p.stack)
    (let loop ((k p.top))
      (when (fx>= k 0)
        (let (node (##vector-ref stack k))
          (cond
           ((or (is? node a) (is? node b))
            (using (node :- HTMLBuilderNode)
              (let (atom node.atom)
                (generate-implied-end-tags! p atom)
                (pop-until! p atom))))
           ((and (flag? node flag-special)
                 (not (is? node atom-address))
                 (not (is? node atom-div))
                 (not (is? node atom-p)))
            (void))
           (else (loop (fx- k 1)))))))))

(def (in-body-end-tag (p    :- HTMLBuilder)
                      (kind :- :fixnum)
                      (atom :- :fixnum)) => :void
  (atom-case atom
    ((template) (in-head p kind))
    ((body)
     (when (in-scope? p atom-body flag-scope)
       (set! p.mode mode-after-body)))
    ((html)
     (when (in-scope? p atom-body flag-scope)
       (set! p.mode mode-after-body)
       (dispatch p kind)))
    ((address article aside blockquote button center details dialog dir div dl
      fieldset figcaption figure footer header hgroup listing main menu nav ol pre
      search section select summary ul)
     (let (k (scope-index p atom flag-scope))
       (when (fx>= k 0)
         (generate-implied-end-tags! p 0)
         (pop-to! p k))))
    ((form)
     (if (parsing-template-contents? p)
       (let (k (scope-index p atom-form flag-scope))
         (when (fx>= k 0)
           (generate-implied-end-tags! p 0)
           (pop-to! p k)))
       (let (node p.form)
         (set! p.form #f)
         (when (and node (fx>= (scope-node-index p node flag-scope) 0))
           (generate-implied-end-tags! p 0)
           (stack-remove! p node)))))
    ((p)
     (unless (p-in-button-scope? p)
       (insert-html-element! p atom-p '()))
     (close-p! p))
    ((li)
     (let (k (scope-index p atom-li list-scope))
       (when (fx>= k 0)
         (generate-implied-end-tags! p atom-li)
         (pop-to! p k))))
    ((dd dt)
     (let (k (scope-index p atom flag-scope))
       (when (fx>= k 0)
         (generate-implied-end-tags! p atom)
         (pop-to! p k))))
    ((h1 h2 h3 h4 h5 h6)
     (let (k (scope-flag-index p flag-heading flag-scope))
       (when (fx>= k 0)
         (generate-implied-end-tags! p 0)
         (pop-to! p k))))
    ((a b big code em font i nobr s small strike strong tt u)
     (adoption-agency! p atom))
    ((applet marquee object)
     (let (k (scope-index p atom flag-scope))
       (when (fx>= k 0)
         (generate-implied-end-tags! p 0)
         (pop-to! p k)
         (clear-formatting-to-marker! p))))
    ((br)
     (in-body-start-tag p html-token-start-tag atom-br))
    (else (any-other-end-tag! p atom))))

;;; "Any other end tag" in the "in body" insertion mode.
(def (any-other-end-tag! (p    :- HTMLBuilder)
                         (atom :- :fixnum)) => :void
  (let (stack p.stack)
    (let loop ((k p.top))
      (when (fx>= k 0)
        (let (node (##vector-ref stack k))
          (cond
           ((is? node atom)
            (generate-implied-end-tags! p atom)
            (pop-to! p k))
           ((flag? node flag-special) (void))
           (else (loop (fx- k 1)))))))))

;;; The adoption agency algorithm for an end tag (or a start tag) subject.
(def (adoption-agency! (p       :- HTMLBuilder)
                       (subject :- :fixnum)) => :void
  (let (node (current p))
    (if (and (is? node subject) (not (using (node :- HTMLBuilderNode) node.formatting?)))
      (pop! p)
      (let outer ((count 0))
        (when (fx< count 8)
          (let (fk (formatting-find p subject))
            (if (fx< fk 0)
              (any-other-end-tag! p subject)
              (let (fe (##vector-ref p.formatting fk))
                (using (fe :- HTMLBuilderNode)
                  (if (not fe.open?)
                    (formatting-remove-at! p fk)
                    (let (fe-index (scope-node-index p fe flag-scope))
                      (when (fx>= fe-index 0)
                        (let (fb-index (furthest-block-index p fe-index))
                          (if (fx< fb-index 0)
                            (begin
                              (pop-to! p fe-index)
                              (formatting-remove-at! p fk))
                            (begin
                              (adopt! p fe fe-index fk fb-index)
                              (outer (fx+ count 1)))))))))))))))))

;;; Index of the oldest special element newer than the element at k, or -1.
(def (furthest-block-index (p :- HTMLBuilder)
                           (k :- :fixnum)) => :fixnum
  (let ((stack p.stack)
        (top p.top))
    (let loop ((j (fx+ k 1)))
      (cond
       ((fx> j top) -1)
       ((flag? (##vector-ref stack j) flag-special) j)
       (else (loop (fx+ j 1)))))))

;;; One iteration of the adoption agency's outer loop that has a furthest
;;; block: fe is the formatting element at stack index fe-index and list
;;; index fk; the furthest block is at stack index fb-index.
(def (adopt! (p        :- HTMLBuilder)
             (fe       :- HTMLBuilderNode)
             (fe-index :- :fixnum)
             (fk       :- :fixnum)
             (fb-index :- :fixnum)) => :void
  (let* ((stack p.stack)
         (fb (##vector-ref stack fb-index))
         (common-ancestor (##vector-ref stack (fx- fe-index 1))))
    ;; inner loop: removed stack entries become #f until the stack is
    ;; compacted below
    (let inner ((count 1) (k (fx- fb-index 1)) (last-node fb) (bookmark fk) (moved? #f))
      (let (node (##vector-ref stack k))
        (using (node :- HTMLBuilderNode)
          (if (eq? node fe)
            (adopt-finish! p fe fe-index fb fb-index common-ancestor last-node bookmark)
            (let (bookmark
                  (if (and (fx> count 3) node.formatting?)
                    (let (r (formatting-index p node))
                      (formatting-remove-at! p r)
                      (if (fx< r bookmark) (fx- bookmark 1) bookmark))
                    bookmark))
              (if (not node.formatting?)
                (begin
                  (##vector-set! stack k #f)
                  (closed! p node)
                  (inner (fx+ count 1) (fx- k 1) last-node bookmark moved?))
                (let (r (formatting-index p node))
                  (using (new (clone-element node) :- HTMLBuilderNode)
                    (##vector-set! p.formatting r new)
                    (set! node.formatting? #f)
                    (set! new.formatting? #t)
                    (##vector-set! stack k new)
                    (set! node.open? #f)
                    (set! new.open? #t)
                    (detach! last-node)
                    (append-child! new last-node)
                    (inner (fx+ count 1) (fx- k 1) new
                           (if moved? bookmark (fx+ r 1))
                           #t)))))))))))

(def (adopt-finish! (p               :- HTMLBuilder)
                    (fe              :- HTMLBuilderNode)
                    (fe-index        :- :fixnum)
                    (fb              :- HTMLBuilderNode)
                    (fb-index        :- :fixnum)
                    (common-ancestor :- HTMLBuilderNode)
                    (last-node       :- HTMLBuilderNode)
                    (bookmark        :- :fixnum)) => :void
  (appropriate-place! p common-ancestor)
  (detach! last-node)
  (unless (or (inclusive-ancestor? last-node p.place-parent)
              (and p.place-before (not (eq? p.place-before.parent p.place-parent))))
    (insert-before! p.place-parent last-node p.place-before))
  (using (new (clone-element fe) :- HTMLBuilderNode)
    ;; the children of fb (its contents stay with a template)
    (let move ()
      (let (child fb.first)
        (when child
          (detach! child)
          (append-child! new child)
          (move))))
    (append-child! (container-of fb) new)
    (let* ((r (formatting-index p fe))
           (bookmark (if (fx< r bookmark) (fx- bookmark 1) bookmark)))
      (formatting-remove-at! p r)
      (formatting-insert-at! p bookmark new))
    ;; the stack: drop fe and the removed entries, new right after fb
    (let ((stack p.stack)
          (top p.top))
      (let loop ((k fe-index) (w fe-index))
        (if (fx> k top)
          (begin
            (let clear ((j w))
              (when (fx<= j top)
                (##vector-set! stack j #f)
                (clear (fx+ j 1))))
            (set! p.top (fx- w 1)))
          (let (entry (##vector-ref stack k))
            (cond
             ((or (not entry) (eq? entry fe)) (loop (fx+ k 1) w))
             ((eq? entry fb)
              (##vector-set! stack w fb)
              (##vector-set! stack (fx+ w 1) new)
              (loop (fx+ k 1) (fx+ w 2)))
             (else
              (##vector-set! stack w entry)
              (loop (fx+ k 1) (fx+ w 1))))))))
    (set-p-scope-from! p fe-index)
    (set! fe.open? #f)
    (set! new.open? #t)))

;;; the "text" insertion mode

(def (in-text (p    :- HTMLBuilder)
              (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-characters) (insert-text! p p.text))
   ((fx= kind html-token-eof)
    (pop! p)
    (set! p.mode p.original-mode)
    (dispatch p kind))
   ((fx= kind html-token-end-tag)
    (pop! p)
    (set! p.mode p.original-mode))
   (else (void))))

;;; the "in table" insertion mode

(def (in-table (p    :- HTMLBuilder)
               (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (let (node (current p))
      (if (or (is? node atom-table) (is? node atom-tbody) (is? node atom-template)
              (is? node atom-tfoot) (is? node atom-thead) (is? node atom-tr))
        (begin
          (set! p.pending '())
          (set! p.pending-space? #t)
          (set! p.pending-start p.tz.start)
          (set! p.original-mode p.mode)
          (set! p.mode mode-in-table-text)
          (dispatch p kind))
        (in-table-anything p kind))))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((caption)
       (clear-stack-back! p atom-table)
       (formatting-push! p #f)
       (insert-token-element! p)
       (set! p.mode mode-in-caption))
      ((colgroup)
       (clear-stack-back! p atom-table)
       (insert-token-element! p)
       (set! p.mode mode-in-column-group))
      ((col)
       (clear-stack-back! p atom-table)
       (insert-html-element! p atom-colgroup '())
       (set! p.mode mode-in-column-group)
       (dispatch p kind))
      ((tbody tfoot thead)
       (clear-stack-back! p atom-table)
       (insert-token-element! p)
       (set! p.mode mode-in-table-body))
      ((td th tr)
       (clear-stack-back! p atom-table)
       (insert-html-element! p atom-tbody '())
       (set! p.mode mode-in-table-body)
       (dispatch p kind))
      ((table)
       (let (k (scope-index p atom-table flag-table-scope))
         (when (fx>= k 0)
           (pop-to! p k)
           (reset-insertion-mode! p)
           (dispatch p kind))))
      ((style script template) (in-head p kind))
      ((input)
       (if (let (type (token-attribute p atom-type))
             (and type (ascii-ci=? type "hidden")))
         (begin
           (insert-token-element! p)
           (pop! p))
         (in-table-anything p kind)))
      ((form)
       (let (template? (parsing-template-contents? p))
         (unless (and p.form (not template?))
           (let (node (insert-token-element! p))
             (unless template?
               (set! p.form node))
             (pop! p)))))
      (else (in-table-anything p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((table)
       (let (k (scope-index p atom-table flag-table-scope))
         (when (fx>= k 0)
           (pop-to! p k)
           (reset-insertion-mode! p))))
      ((body caption col colgroup html tbody td tfoot th thead tr) (void))
      ((template) (in-head p kind))
      (else (in-table-anything p kind))))
   ((fx= kind html-token-eof) (in-body p kind))
   (else (in-table-anything p kind))))

(def (in-table-anything (p    :- HTMLBuilder)
                        (kind :- :fixnum)) => :void
  (set! p.foster? #t)
  (in-body p kind)
  (set! p.foster? #f))

;;; the "in table text" insertion mode

(def (in-table-text (p    :- HTMLBuilder)
                    (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-null-character) (void))
   ((fx= kind html-token-characters)
    (let (str p.text)
      (set! p.pending (cons str p.pending))
      (when (and p.pending-space? (not (html-space-string? str)))
        (set! p.pending-space? #f))))
   (else
    (let (pending p.pending)
      (unless (null? pending)
        (let (str (if (null? (cdr pending))
                    (car pending)
                    (string-concatenate (reverse pending))))
          (set! p.pending '())
          (if p.pending-space?
            (insert-text! p str)
            (begin
              (set! p.foster? #t)
              (reconstruct-formatting! p)
              (insert-text! p str)
              (set! p.frameset-ok? #f)
              (set! p.foster? #f))))))
    (set! p.mode p.original-mode)
    (dispatch p kind))))

;;; the "in caption" insertion mode

(def (close-caption! (p :- HTMLBuilder)) => :boolean
  (let (k (scope-index p atom-caption flag-table-scope))
    (and (fx>= k 0)
         (begin
           (generate-implied-end-tags! p 0)
           (pop-until! p atom-caption)
           (clear-formatting-to-marker! p)
           (set! p.mode mode-in-table)
           #t))))

(def (in-caption (p    :- HTMLBuilder)
                 (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((caption col colgroup tbody td tfoot th thead tr)
       (when (close-caption! p)
         (dispatch p kind)))
      (else (in-body p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((caption) (close-caption! p))
      ((table)
       (when (close-caption! p)
         (dispatch p kind)))
      ((body col colgroup html tbody td tfoot th thead tr) (void))
      (else (in-body p kind))))
   (else (in-body p kind))))

;;; the "in column group" insertion mode

(def (in-column-group (p    :- HTMLBuilder)
                      (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (split-space p kind space (insert-text! p space) (in-column-group-anything p kind)))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((col)
       (insert-token-element! p)
       (pop! p))
      ((template) (in-head p kind))
      (else (in-column-group-anything p kind))))
   ((fx= kind html-token-end-tag)
    (atom-case p.tz.tag
      ((colgroup)
       (when (current-is? p atom-colgroup)
         (pop! p)
         (set! p.mode mode-in-table)))
      ((col) (void))
      ((template) (in-head p kind))
      (else (in-column-group-anything p kind))))
   ((fx= kind html-token-eof) (in-body p kind))
   (else (in-column-group-anything p kind))))

(def (in-column-group-anything (p    :- HTMLBuilder)
                               (kind :- :fixnum)) => :void
  (when (current-is? p atom-colgroup)
    (pop! p)
    (set! p.mode mode-in-table)
    (dispatch p kind)))

;;; the "in table body" insertion mode

(def (in-table-body (p    :- HTMLBuilder)
                    (kind :- :fixnum)) => :void
  (def (close-section!)
    (clear-stack-back! p atom-tbody atom-tfoot atom-thead)
    (pop! p)
    (set! p.mode mode-in-table))
  (cond
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((tr)
       (clear-stack-back! p atom-tbody atom-tfoot atom-thead)
       (insert-token-element! p)
       (set! p.mode mode-in-row))
      ((th td)
       (clear-stack-back! p atom-tbody atom-tfoot atom-thead)
       (insert-html-element! p atom-tr '())
       (set! p.mode mode-in-row)
       (dispatch p kind))
      ((caption col colgroup tbody tfoot thead)
       (when (fx>= (scope-flag-index p flag-section flag-table-scope) 0)
         (close-section!)
         (dispatch p kind)))
      (else (in-table p kind))))
   ((fx= kind html-token-end-tag)
    (let (atom p.tz.tag)
      (atom-case atom
        ((tbody tfoot thead)
         (when (in-scope? p atom flag-table-scope)
           (close-section!)))
        ((table)
         (when (fx>= (scope-flag-index p flag-section flag-table-scope) 0)
           (close-section!)
           (dispatch p kind)))
        ((body caption col colgroup html td th tr) (void))
        (else (in-table p kind)))))
   (else (in-table p kind))))

;;; the "in row" insertion mode

(def (in-row (p    :- HTMLBuilder)
             (kind :- :fixnum)) => :void
  ;; closes the row when one is in table scope
  (def (close-row!)
    (and (in-scope? p atom-tr flag-table-scope)
         (begin
           (clear-stack-back! p atom-tr)
           (pop! p)
           (set! p.mode mode-in-table-body)
           #t)))
  (cond
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((th td)
       (clear-stack-back! p atom-tr)
       (insert-token-element! p)
       (set! p.mode mode-in-cell)
       (formatting-push! p #f))
      ((caption col colgroup tbody tfoot thead tr)
       (when (close-row!)
         (dispatch p kind)))
      (else (in-table p kind))))
   ((fx= kind html-token-end-tag)
    (let (atom p.tz.tag)
      (atom-case atom
        ((tr) (close-row!))
        ((table)
         (when (close-row!)
           (dispatch p kind)))
        ((tbody tfoot thead)
         (when (and (in-scope? p atom flag-table-scope) (close-row!))
           (dispatch p kind)))
        ((body caption col colgroup html td th) (void))
        (else (in-table p kind)))))
   (else (in-table p kind))))

;;; the "in cell" insertion mode

(def (close-cell! (p :- HTMLBuilder)) => :void
  (generate-implied-end-tags! p 0)
  (let loop ()
    (when (fx>= p.top 0)
      (unless (flag? (pop! p) flag-cell)
        (loop))))
  (clear-formatting-to-marker! p)
  (set! p.mode mode-in-row))

(def (in-cell (p    :- HTMLBuilder)
              (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-end-tag)
    (let (atom p.tz.tag)
      (atom-case atom
        ((td th)
         (when (in-scope? p atom flag-table-scope)
           (generate-implied-end-tags! p 0)
           (pop-until! p atom)
           (clear-formatting-to-marker! p)
           (set! p.mode mode-in-row)))
        ((body caption col colgroup html) (void))
        ((table tbody tfoot thead tr)
         (when (in-scope? p atom flag-table-scope)
           (close-cell! p)
           (dispatch p kind)))
        (else (in-body p kind)))))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((caption col colgroup tbody td tfoot th thead tr)
       (when (fx>= (scope-flag-index p flag-cell flag-table-scope) 0)
         (close-cell! p)
         (dispatch p kind)))
      (else (in-body p kind))))
   (else (in-body p kind))))

;;; the "in template" insertion mode

(def (in-template (p    :- HTMLBuilder)
                  (kind :- :fixnum)) => :void
  (def (switch! mode)
    (let (modes p.template-modes)
      (set! p.template-modes (cons mode (if (pair? modes) (cdr modes) modes))))
    (set! p.mode mode)
    (dispatch p kind))
  (cond
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((base basefont bgsound link meta noframes script style template title)
       (in-head p kind))
      ((caption colgroup tbody tfoot thead) (switch! mode-in-table))
      ((col) (switch! mode-in-column-group))
      ((tr) (switch! mode-in-table-body))
      ((td th) (switch! mode-in-row))
      (else (switch! mode-in-body))))
   ((fx= kind html-token-end-tag)
    (when (fx= p.tz.tag atom-template)
      (in-head p kind)))
   ((fx= kind html-token-eof)
    (when (fx> p.templates 0)
      (pop-until! p atom-template)
      (clear-formatting-to-marker! p)
      (let (modes p.template-modes)
        (when (pair? modes)
          (set! p.template-modes (cdr modes))))
      (reset-insertion-mode! p)
      (dispatch p kind)))
   (else (in-body p kind))))

;;; the "after body" insertion mode

(def (after-body (p    :- HTMLBuilder)
                 (kind :- :fixnum)) => :void
  (cond
   ((characters? kind)
    (split-space p kind space
                 (let (saved p.text)
                   (set! p.text space)
                   (in-body p html-token-characters)
                   (set! p.text saved))
                 (after-body-anything p kind)))
   ((other? kind) (insert-other! p kind (##vector-ref p.stack 0)))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (if (fx= p.tz.tag atom-html)
      (in-body p kind)
      (after-body-anything p kind)))
   ((fx= kind html-token-end-tag)
    (if (fx= p.tz.tag atom-html)
      (unless p.context
        (set! p.mode mode-after-after-body))
      (after-body-anything p kind)))
   ((fx= kind html-token-eof) (void))
   (else (after-body-anything p kind))))

(def (after-body-anything (p    :- HTMLBuilder)
                          (kind :- :fixnum)) => :void
  (set! p.mode mode-in-body)
  (dispatch p kind))

;;; the "in frameset" and "after frameset" insertion modes

;;; Inserts the whitespace characters of a character token; the others are
;;; ignored.
(def (insert-space-only! (p    :- HTMLBuilder)
                         (kind :- :fixnum)) => :void
  (when (fx= kind html-token-characters)
    (let (str (only-space p.text))
      (unless (string-empty? str)
        (insert-text! p str)))))

(def (in-frameset (p    :- HTMLBuilder)
                  (kind :- :fixnum)) => :void
  (cond
   ((characters? kind) (insert-space-only! p kind))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((frameset) (insert-token-element! p))
      ((frame)
       (insert-token-element! p)
       (pop! p))
      ((noframes) (in-head p kind))
      (else (void))))
   ((fx= kind html-token-end-tag)
    (when (and (fx= p.tz.tag atom-frameset) (fx> p.top 0))
      (pop! p)
      (unless (or p.context (current-is? p atom-frameset))
        (set! p.mode mode-after-frameset))))
   (else (void))))

(def (after-frameset (p    :- HTMLBuilder)
                     (kind :- :fixnum)) => :void
  (cond
   ((characters? kind) (insert-space-only! p kind))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((noframes) (in-head p kind))
      (else (void))))
   ((fx= kind html-token-end-tag)
    (when (fx= p.tz.tag atom-html)
      (set! p.mode mode-after-after-frameset)))
   (else (void))))

;;; the "after after body" and "after after frameset" insertion modes

(def (after-after-body (p    :- HTMLBuilder)
                       (kind :- :fixnum)) => :void
  (cond
   ((other? kind) (insert-other! p kind p.document))
   ((fx= kind html-token-doctype) (in-body p kind))
   ((characters? kind)
    (split-space p kind space
                 (let (saved p.text)
                   (set! p.text space)
                   (in-body p html-token-characters)
                   (set! p.text saved))
                 (after-body-anything p kind)))
   ((and (fx= kind html-token-start-tag) (fx= p.tz.tag atom-html)) (in-body p kind))
   ((fx= kind html-token-eof) (void))
   (else (after-body-anything p kind))))

(def (after-after-frameset (p    :- HTMLBuilder)
                           (kind :- :fixnum)) => :void
  (cond
   ((other? kind) (insert-other! p kind p.document))
   ((fx= kind html-token-characters)
    (let (str (only-space p.text))
      (unless (string-empty? str)
        (set! p.text str)
        (in-body p kind))))
   ((fx= kind html-token-start-tag)
    (atom-case p.tz.tag
      ((html) (in-body p kind))
      ((noframes) (in-head p kind))
      (else (void))))
   (else (void))))

;;; foreign content

;;; True for a start tag that leaves foreign content.
(def (breakout-start-tag? (p :- HTMLBuilder)) => :boolean
  (or (foreign-breakout-atom? p.tz.tag)
      (html-font-breakout-token? p.tz)))

(def (in-foreign-content (p    :- HTMLBuilder)
                         (kind :- :fixnum)) => :void
  (cond
   ((fx= kind html-token-null-character) (insert-text! p "\xfffd;"))
   ((fx= kind html-token-characters)
    (let (str p.text)
      (insert-text! p str)
      (when (and p.frameset-ok? (not (html-space-string? str)))
        (set! p.frameset-ok? #f))))
   ((other? kind) (insert-other! p kind #f))
   ((fx= kind html-token-doctype) (void))
   ((fx= kind html-token-start-tag)
    (if (breakout-start-tag? p)
      (foreign-breakout! p kind)
      (begin
        (insert-foreign-element! p (using (node (adjusted-current p) :- HTMLBuilderNode) node.ns))
        (when p.tz.self-closing?
          (pop! p)))))
   ((fx= kind html-token-end-tag)
    (let (atom p.tz.tag)
      (cond
       ((or (fx= atom atom-br) (fx= atom atom-p)) (foreign-breakout! p kind))
       ((and (fx= atom atom-script)
             (using (node (current p) :- HTMLBuilderNode)
               (and (fx= node.ns ns-svg) (fx= node.atom atom-script))))
        (pop! p))
       (else (foreign-end-tag! p kind atom)))))
   (else (process-in-mode p kind))))

;;; Pops until the current node is HTML or an integration point, then
;;; processes the token as HTML content.
(def (foreign-breakout! (p    :- HTMLBuilder)
                        (kind :- :fixnum)) => :void
  (let loop ()
    (let (node (current p))
      (unless (or (fx= (using (node :- HTMLBuilderNode) node.ns) ns-html)
                  (flag? node (fxior flag-text-point flag-html-point)))
        (pop! p)
        (loop))))
  (process-in-mode p kind))

;;; "Any other end tag" in foreign content.
(def (foreign-end-tag! (p    :- HTMLBuilder)
                       (kind :- :fixnum)
                       (atom :- :fixnum)) => :void
  (let (stack p.stack)
    (let loop ((k p.top))
      (unless (fx= k 0)
        (let (node (##vector-ref stack k))
          (using (node :- HTMLBuilderNode)
            (if (fx= node.atom atom)
              (pop-to! p k)
              (let (k (fx- k 1))
                (using (next (##vector-ref stack k) :- HTMLBuilderNode)
                  (if (fx= next.ns ns-html)
                    (process-in-mode p kind)
                    (loop k)))))))))))

;;; running

(def (process-token! (p    :- HTMLBuilder)
                     (kind :- :fixnum)) => :void
  (when (fx= kind html-token-characters)
    (set! p.text (html-token-text p.tz)))
  (if p.skip-newline?
    (begin
      (set! p.skip-newline? #f)
      (if (and (fx= kind html-token-characters)
               (char=? (string-ref p.text 0) #\newline))
        (let (str p.text)
          (unless (fx= (string-length str) 1)
            (set! p.text (substring str 1 (string-length str)))
            (dispatch p kind)))
        (dispatch p kind)))
    (dispatch p kind)))

(def (run! (p :- HTMLBuilder)) => :void
  (using (tz p.tz :- HTMLTokenizer)
    (let loop ()
      (let (kind (html-tokenizer-next! tz))
        (process-token! p kind)
        (unless (fx= kind html-token-eof)
          (set! tz.cdata? (and (fx>= p.top 0)
                               (cdata-allowed? (using (node (adjusted-current p) :- HTMLBuilderNode)
                                                 node.ns))))
          (loop))))))

;;; freezing

;;; The text of a text node's data: a string, or the list of the strings
;;; inserted into it, last first (insert-text!).
(def (text-string (data :- :t)) => :string
  (if (string? data)
    data
    (using (pieces data :- :list)
      (string-concatenate (reverse pieces)))))

;;; The typed children of parent, adjacent text merged.
(def (freeze-children (parent :- HTMLBuilderNode)) => :list
  ;; from the last child back, so the list is built in order
  (let loop ((node parent.last :? HTMLBuilderNode) (result '()) (texts '()))
    (def (flush)
      (if (null? texts)
        result
        (cons (unchecked-node XMLText (if (null? (cdr texts))
                                         (car texts)
                                         (string-concatenate texts)))
              result)))
    (if (not node)
      (flush)
      (let (kind node.kind)
        (cond
         ((fx= kind kind-text)
          (loop node.prev result (cons (text-string node.data) texts)))
         ((fx= kind kind-element)
          (loop node.prev (cons (freeze-element node) (flush)) '()))
         (else
          (loop node.prev (cons node.data (flush)) '())))))))

(def (freeze-element (node :- HTMLBuilderNode)) => XMLElement
  (unchecked-node XMLElement node.name node.attributes (freeze-children (container-of node))))

;;; entry points

;;; Parses the tokens of tz as a document.
(def (build-html-document (tz         :- HTMLTokenizer)
                          (scripting? :- :boolean)) => HTMLDocument
  (using (p (new-builder tz scripting?) :- HTMLBuilder)
    (run! p)
    (join-merged-attributes! p)
    (unchecked-node HTMLDocument (freeze-children p.document))))

;;; Parses the tokens of tz as a fragment in the context of an element in
;;; namespace ns (a code) named name (an XMLName) with folded name atom and
;;; attributes; returns the typed nodes of the fragment.
(def (build-html-fragment (tz         :- HTMLTokenizer)
                          (scripting? :- :boolean)
                          (ns         :- :fixnum)
                          (atom       :- :fixnum)
                          (name       :- XMLName)
                          (attributes :- :list)) => :list
  (using (p (new-builder tz scripting?) :- HTMLBuilder)
    (let* ((root (new-element ns-html atom-html (html-element-flags atom-html)
                              (atom-name p atom-html) '()))
           (encoding (let find ((rest attributes))
                       (and (pair? rest)
                            (using (attr (car rest) :- XMLAttribute)
                              (if (and (string=? attr.name.local "encoding")
                                       (string=? attr.name.uri ""))
                                attr.value
                                (find (cdr rest)))))))
           (context (new-element ns atom (element-flags ns atom encoding) name attributes)))
      (append-child! p.document root)
      (push! p root)
      (set! p.context context)
      (when (fx= ns ns-html)
        (set! p.tz.state (class-tokenizer-state (element-class-of-atom atom) scripting?))
        (when (fx= atom atom-template)
          (set! p.template-modes [mode-in-template]))
        (when (fx= atom atom-form)
          (set! p.form context)))
      (reset-insertion-mode! p)
      (set! p.tz.cdata? (cdata-allowed? ns))
      (run! p)
      (join-merged-attributes! p)
      (freeze-children root))))
