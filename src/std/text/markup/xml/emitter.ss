;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; XML emitter: serializes typed nodes as UTF-8 into a stdio output
;;; buffer (../output), adding the namespace declarations names need.
;;; Finding a prefix's namespace, or a namespace's prefix, costs O(log n)
;;; with n prefixes or namespaces in scope; the latter also passes at most
;;; max-stale-prefixes prefixes bound again since (bound-prefix), and
;;; generated prefixes skip each bound one once per write. Writing n names
;;; is so O(n log n) at worst, as reading is with the reader's prefix map.
;;; Unchecked internals of :std/text/markup/xml/writer.
;;;
;;; Nodes are immutable (./types): slots are trusted at their declared types.
(import :std/error
        (only-in :std/struct/rbtree RBTree make-RBTree rbtree-ref rbtree-put! string-cmp)
        (only-in :std/encoding/utf8 &put-utf8!)
        :std/io/bio/types
        ../output
        (only-in ../scan-input ascii)
        ./node)
(export XMLEmitter
        make-xml-emitter
        emit-xml!)
(declare (not safe))

;;; The scopes in effect by prefix or namespace, found as the reader finds
;;; prefixes (./scanner): in a list of the first max-listed-scopes, then in
;;; a red-black tree, O(log n) for n of them whatever strings the tree's
;;; author chose. A listed scope leaves the list when nothing binds it, so
;;; that a document whose declarations come and go keeps finding its
;;; namespaces there; the tree keeps its scopes, as the reader's does.
(defstruct XMLScopeTable
  ((listed :- :list)   ; (key . scope) of the first max-listed-scopes keys
   (count  :- :fixnum) ; entries in listed
   (tree   :? RBTree)) ; scope by key for the others, or #f
  final: #t)

;;; With none listed (max-listed-scopes 0), writing small namespace-heavy
;;; documents took 37% more instructions and 35% more cycles
;;; (markup-benchmark.ss mode xml-write-namespaces, SIZE 100, ITERATIONS
;;; 700).
(def max-listed-scopes 8)

(def (make-scope-table) => XMLScopeTable
  (make-XMLScopeTable '() 0 #f))

;;; The scope of key in table, or #f.
(def (scope-ref (table :- XMLScopeTable)
                (key   :- :string)) => :t
  (let loop ((rest table.listed))
    (cond
     ((pair? rest)
      (if (string-same? key (##car (##car rest)))
        (##cdr (##car rest))
        (loop (##cdr rest))))
     (table.tree (rbtree-ref table.tree key #f))
     (else #f))))

;;; Removes scope from the list of table, when listed.
(def (scope-unlist! (table :- XMLScopeTable)
                    (scope :- :t)) => :void
  (let loop ((rest table.listed) (kept '()))
    (when (pair? rest)
      (if (eq? (##cdr (##car rest)) scope)
        (begin
          (set! table.listed (append-reverse kept (##cdr rest)))
          (set! table.count (fx- table.count 1)))
        (loop (##cdr rest) (cons (##car rest) kept))))))

;;; Stores scope under key, which table does not hold.
(def (scope-put! (table :- XMLScopeTable)
                 (key   :- :string)
                 (scope :- :t)) => :void
  (if (fx< table.count max-listed-scopes)
    (begin
      (set! table.listed (cons (cons key scope) table.listed))
      (set! table.count (fx+ table.count 1)))
    (rbtree-put! (or table.tree
                     (let (tree (make-RBTree string-cmp))
                       (set! table.tree tree)
                       tree))
                 key scope)))

;;; The namespace state of a write, over its output. The prefix bindings in
;;; effect are kept as the reader keeps them (./scanner): a stack of
;;; namespaces per prefix, pushed by declarations and popped at the end of
;;; their element, with a stack of prefixes per namespace for bound-prefix.
(defstruct XMLEmitter
  ((out        :- basic-output-buffer)
   (prefixes   :- XMLScopeTable) ; XMLPrefixScope by prefix
   (namespaces :- XMLScopeTable) ; XMLNamespaceScope by namespace
   (declared   :- :list)    ; XMLPrefixScope values the current element bound
   (default-ns :- :string)
   (generated  :- :fixnum)) ; count of generated prefixes
  final: #t)

;;; The namespaces prefix is bound to by the open elements, innermost first;
;;; empty while it is unbound.
(defstruct XMLPrefixScope
  ((prefix     :- :string)
   (namespaces :- :list))   ; XMLNamespaceScope values
  final: #t)

;;; The prefixes the open elements bound to uri, innermost first; a prefix
;;; may since have been bound again, to another namespace.
(defstruct XMLNamespaceScope
  ((uri      :- :string)
   (prefixes :- :list))     ; XMLPrefixScope values
  final: #t)

;;; An emitter at the top level, writing to out.
(def (make-xml-emitter (out :- basic-output-buffer)) => XMLEmitter
  (make-XMLEmitter out (make-scope-table) (make-scope-table) '() "" 0))

;;; escaping

;;; XML escape tables (../output): C0 controls other than TAB, LF and CR are
;;; not representable.
(def (make-escape-table (escapes :- :list)) => :u8vector
  (let (table (make-u8vector 128 escape-none))
    (let loop ((b 0))
      (when (fx< b (ascii #\space))
        (unless (or (fx= b (ascii #\tab)) (fx= b (ascii #\newline)) (fx= b (ascii #\return)))
          (u8vector-set! table b escape-invalid))
        (loop (fx+ b 1))))
    (for-each (lambda (escape)
                (u8vector-set! table (char->integer (car escape)) (cdr escape)))
              escapes)
    table))

(def text-escapes
  (make-escape-table [(cons #\& escape-amp) (cons #\< escape-lt) (cons #\> escape-gt)
                      (cons #\return escape-cr)]))
(def attribute-escapes
  (make-escape-table [(cons #\& escape-amp) (cons #\< escape-lt) (cons #\" escape-quot)
                      (cons #\tab escape-tab) (cons #\newline escape-lf) (cons #\return escape-cr)]))
(def raw-escapes (make-escape-table '()))

;;; Surrogates and the noncharacters U+FFFE and U+FFFF.
(defrule (xml-invalid-code? c)
  (and (fx>= c #xd800)
       (or (fx<= c #xdfff) (fx= c #xfffe) (fx= c #xffff))))

;;; (emit-string! out str table): raises on characters XML cannot represent.
(define-string-emitter (emit-string! write-xml "character representable in XML")
  xml-invalid-code?)

;;; Writes the NCName str, checking its syntax as it goes.
(def (emit-ncname! (out :- basic-output-buffer)
                   (str :- :string)) => :void
  (defrule (bad) (raise-bad-argument write-xml "XML name" str))
  (when (fx= (string-length str) 0)
    (bad))
  (for-each-name-slice (out str) (buf s e)
    (let loop ((i s) (pos out.whi))
      (if (fx< i e)
        (let (c (##char->integer (##string-ref str i)))
          (if (fx< c #x80)
            (let (k (##u8vector-ref name-class c))
              (unless (or (fx= k name-start) (and (fx= k name-char) (fx> i 0)))
                (bad))
              (##u8vector-set! buf pos c)
              (loop (fx+ i 1) (fx+ pos 1)))
            (begin
              (unless (if (fx= i 0) (xml-name-start-code? c) (xml-name-code? c))
                (bad))
              (loop (fx+ i 1) (&put-utf8! buf pos c)))))
        (set! out.whi pos)))))

(def (emit-qname! (out    :- basic-output-buffer)
                  (prefix :- :string)
                  (local  :- :string)) => :void
  (unless (fx= (string-length prefix) 0)
    (emit-ncname! out prefix)
    (emit-ascii! out ":"))
  (emit-ncname! out local))

;;; Writes the qname of an end tag: the strings its start tag checked, copied
;;; without a second check.
(def (emit-end-qname! (out    :- basic-output-buffer)
                      (prefix :- :string)
                      (local  :- :string)) => :void
  (defrule (copy! str)
    (for-each-name-slice (out str) (buf s e)
      (let loop ((i s) (pos out.whi))
        (if (fx< i e)
          (loop (fx+ i 1) (&put-utf8! buf pos (##char->integer (##string-ref str i))))
          (set! out.whi pos)))))
  (unless (fx= (string-length prefix) 0)
    (copy! prefix)
    (emit-ascii! out ":"))
  (copy! local))

;;; Writes a space and qname="value".
(def (emit-attribute! (out    :- basic-output-buffer)
                      (prefix :- :string)
                      (local  :- :string)
                      (value  :- :string)) => :void
  (emit-ascii! out " ")
  (emit-qname! out prefix local)
  (emit-ascii! out "=\"")
  (emit-string! out value attribute-escapes)
  (emit-ascii! out "\""))

;;; attributes

;;; Writes a space and local="value" for the attribute named name in no
;;; namespace; one named xmlns would read back as a declaration. A macro, so
;;; that the local test runs before namespace-declaration-error: a procedure
;;; calling it for every attribute took 10% more instructions and 11% more
;;; cycles writing XML (markup-benchmark.ss mode xml-write-attributes, SIZE
;;; 1000, ITERATIONS 600). Behind the test the call only looks up its
;;; message (it cannot return #f there).
(defrule (emit-plain-attribute! out name local value)
  (begin
    (when (string-same? local "xmlns")
      (raise-bad-argument write-xml (namespace-declaration-error "" local "" value) name))
    (emit-attribute! out "" local value)))

(def (any-namespaced-attribute? (attrs :- :list)) => :boolean
  (let loop ((rest attrs))
    (and (pair? rest)
         (using (attr (##car rest) :- XMLAttribute)
           (or (not (fx= (string-length attr.name.uri) 0))
               (loop (##cdr rest)))))))

;;; namespaces

(def (bound-uri (em     :- XMLEmitter)
                (prefix :- :string)) => (Maybe :string)
  (using (scope (scope-ref em.prefixes prefix) :? XMLPrefixScope)
    (cond
     ((and scope (pair? scope.namespaces))
      (using (ns (##car scope.namespaces) :- XMLNamespaceScope)
        ns.uri))
     ((string-same? prefix "xml") xml-namespace-uri)
     (else #f))))

;;; Prefixes bound to a namespace and then bound again, to another, that
;;; bound-prefix passes before it gives up: a new declaration is always
;;; valid output, only longer (markup-benchmark.ss mode
;;; xml-write-rebound-prefixes).
(def max-stale-prefixes 8)

;;; The innermost prefix bound to uri, or #f, also when the innermost
;;; max-stale-prefixes + 1 prefixes the open elements bound to uri have
;;; all been bound again.
(def (bound-prefix (em  :- XMLEmitter)
                   (uri :- :string)) => (Maybe :string)
  (using (ns (scope-ref em.namespaces uri) :? XMLNamespaceScope)
    (let loop ((rest (if ns ns.prefixes '())) (stale 0))
      (cond
       ((and (pair? rest) (fx<= stale max-stale-prefixes))
        (using (scope (##car rest) :- XMLPrefixScope)
          (if (eq? (##car scope.namespaces) ns)
            scope.prefix
            (loop (##cdr rest) (fx+ stale 1)))))
       ((string-same? uri xml-namespace-uri) "xml")
       (else #f)))))

;;; Binds prefix to uri until the end of the current element.
(def (bind-prefix! (em     :- XMLEmitter)
                   (prefix :- :string)
                   (uri    :- :string)) => :void
  (using ((scope (or (scope-ref em.prefixes prefix)
                     (let (scope (make-XMLPrefixScope prefix '()))
                       (scope-put! em.prefixes prefix scope)
                       scope))
                 :- XMLPrefixScope)
          (ns (or (scope-ref em.namespaces uri)
                  (let (ns (make-XMLNamespaceScope uri '()))
                    (scope-put! em.namespaces uri ns)
                    ns))
              :- XMLNamespaceScope))
    (set! scope.namespaces (cons ns scope.namespaces))
    (set! ns.prefixes (cons scope ns.prefixes))
    (set! em.declared (cons scope em.declared))))

;;; Undoes the bindings of the element that bound declared, innermost first.
(def (unbind-declared! (em       :- XMLEmitter)
                       (declared :- :pair)) => :void
  (let loop ((rest declared))
    (when (pair? rest)
      (using (scope (##car rest) :- XMLPrefixScope)
        (using (ns (##car scope.namespaces) :- XMLNamespaceScope)
          (set! ns.prefixes (##cdr ns.prefixes))
          (when (null? ns.prefixes)
            (scope-unlist! em.namespaces ns)))
        (set! scope.namespaces (##cdr scope.namespaces))
        (when (null? scope.namespaces)
          (scope-unlist! em.prefixes scope)))
      (loop (##cdr rest)))))

;;; True when attrs include a declaration for prefix ("" for the default
;;; namespace).
(def (declared-here? (attrs  :- :list)
                     (prefix :- :string)) => :boolean
  (let loop ((rest attrs))
    (and (pair? rest)
         (using (attr (##car rest) :- XMLAttribute)
           (or (and (string-same? attr.name.uri xmlns-namespace-uri)
                    (if (fx= (string-length prefix) 0)
                      (fx= (string-length attr.name.prefix) 0)
                      (string-same? attr.name.local prefix)))
               (loop (##cdr rest)))))))

;;; Start-tag attributes attrs when names carry namespaces: applies the
;;; element's own xmlns attributes, then declares whatever the element name
;;; (in uri, written with prefix) and the attribute names still need,
;;; generating prefixes for attributes when necessary.
(def (emit-namespaced-attributes! (em     :- XMLEmitter)
                                  (uri    :- :string)
                                  (prefix :- :string)
                                  (attrs  :- :list)) => :void
  (let loop ((rest attrs))
    (when (pair? rest)
      (using (attr (##car rest) :- XMLAttribute)
        (when (string-same? attr.name.uri xmlns-namespace-uri)
          (let (problem (namespace-declaration-error attr.name.uri attr.name.local attr.name.prefix
                                                     attr.value))
            (when problem
              (raise-bad-argument write-xml problem attr.name.local)))
          (if (fx= (string-length attr.name.prefix) 0)
            (set! em.default-ns attr.value)
            (bind-prefix! em attr.name.local attr.value))))
      (loop (##cdr rest))))
  (if (fx= (string-length prefix) 0)
    (unless (string-same? em.default-ns uri)
      (when (declared-here? attrs prefix)
        (raise-bad-argument write-xml "xmlns attribute agreeing with the element namespace"
                            uri))
      (set! em.default-ns uri)
      (emit-attribute! em.out "" "xmlns" uri))
    (unless (string-same? (or (bound-uri em prefix) "") uri)
      (when (declared-here? attrs prefix)
        (raise-bad-argument write-xml "element prefix agreeing with its namespace" prefix uri))
      (bind-prefix! em prefix uri)
      (emit-attribute! em.out "xmlns" prefix uri)))
  (let loop ((rest attrs))
    (when (pair? rest)
      (using (attr (##car rest) :- XMLAttribute)
        (let ((attr-uri attr.name.uri)
              (local attr.name.local)
              (value attr.value))
          (cond
           ((fx= (string-length attr-uri) 0)
            (emit-plain-attribute! em.out attr.name local value))
           ((string-same? attr-uri xmlns-namespace-uri)
            (emit-attribute! em.out attr.name.prefix local value))
           (else
            (let* ((attr-prefix attr.name.prefix)
                   (attr-prefix
                    (cond
                     ((and (not (fx= (string-length attr-prefix) 0))
                           (string-same? (or (bound-uri em attr-prefix) "") attr-uri))
                      attr-prefix)
                     ((bound-prefix em attr-uri))
                     (else
                      (let (attr-prefix (if (and (not (fx= (string-length attr-prefix) 0))
                                                 (not (bound-uri em attr-prefix)))
                                          attr-prefix
                                          (generate-prefix! em)))
                        (bind-prefix! em attr-prefix attr-uri)
                        (emit-attribute! em.out "xmlns" attr-prefix attr-uri)
                        attr-prefix)))))
              (emit-attribute! em.out attr-prefix local value))))))
      (loop (##cdr rest)))))

(def (generate-prefix! (em :- XMLEmitter)) => :string
  (let loop ()
    (let* ((k (fx+ em.generated 1))
           (prefix (string-append "ns" (number->string k))))
      (set! em.generated k)
      (if (bound-uri em prefix)
        (loop)
        prefix))))

;;; nodes

(def (emit-element! (em :- XMLEmitter)
                    (el :- XMLElement)) => :void
  (let* ((attrs el.attributes)
         (kids el.children)
         (declared em.declared)
         (default-ns em.default-ns)
         (uri el.name.uri)
         (local el.name.local)
         (prefix el.name.prefix))
    (set! em.declared '())
    (emit-ascii! em.out "<")
    (emit-qname! em.out prefix local)
    (if (or (not (fx= (string-length uri) 0))
            (not (fx= (string-length default-ns) 0))
            (any-namespaced-attribute? attrs))
      (emit-namespaced-attributes! em uri prefix attrs)
      (let loop ((rest attrs))
        (when (pair? rest)
          (using (attr (##car rest) :- XMLAttribute)
            (let (attr-local attr.name.local)
              (emit-plain-attribute! em.out attr.name attr-local attr.value)))
          (loop (##cdr rest)))))
    (if (pair? kids)
      (begin
        (emit-ascii! em.out ">")
        (emit-children! em kids)
        (emit-ascii! em.out "</")
        (emit-end-qname! em.out prefix local)
        (emit-ascii! em.out ">"))
      (emit-ascii! em.out "/>"))
    (let (bound em.declared)
      (when (pair? bound)
        (unbind-declared! em bound)))
    (set! em.declared declared)
    (set! em.default-ns default-ns)))

;;; Writes the children of an element, or a prolog or epilog.
(def (emit-children! (em   :- XMLEmitter)
                     (kids :- :list)) => :void
  (let loop ((rest kids))
    (when (pair? rest)
      (emit-node! em (##car rest))
      (loop (##cdr rest)))))

;;; Writes a child of an element, a member of a prolog or epilog, or the
;;; node written; text first, as the most frequent.
(def (emit-node! (em   :- XMLEmitter)
                 (node :- XML)) => :void
  (cond
   ((XMLText? node)
    (using (node :- XMLText)
      (emit-string! em.out node.data text-escapes)))
   ((XMLElement? node)
    (emit-element! em node))
   ((XMLPI? node)
    (using (node :- XMLPI)
      (let (data node.data)
        (emit-ascii! em.out "<?")
        (emit-ncname! em.out node.target)
        (unless (fx= (string-length data) 0)
          (emit-ascii! em.out " ")
          (emit-string! em.out data raw-escapes))
        (emit-ascii! em.out "?>"))))
   ((XMLComment? node)
    (using (node :- XMLComment)
      (let (data node.data)
        (unless (xml-comment-data? data)
          (raise-bad-argument write-xml "comment data without -- or a final -" node))
        (emit-ascii! em.out "<!--")
        (emit-string! em.out data raw-escapes)
        (emit-ascii! em.out "-->"))))
   ((XMLCData? node)
    (using (node :- XMLCData)
      (emit-ascii! em.out "<![CDATA[")
      (emit-string! em.out node.data raw-escapes)
      (emit-ascii! em.out "]]>")))
   (else
    (raise-bad-argument write-xml "XML node" node))))

(def (emit-doctype! (em      :- XMLEmitter)
                    (doctype :- XMLDoctype)) => :void
  (let ((name doctype.name)
        (public-id doctype.public-id)
        (system-id doctype.system-id))
    (emit-ascii! em.out "<!DOCTYPE ")
    (emit-string! em.out name raw-escapes)
    (when public-id
      (emit-ascii! em.out " PUBLIC \"")
      (emit-string! em.out public-id raw-escapes)
      (emit-ascii! em.out "\""))
    (when system-id
      (if public-id
        (emit-ascii! em.out " ")
        (emit-ascii! em.out " SYSTEM "))
      (if (string-index system-id #\")
        (begin
          (emit-ascii! em.out "'")
          (emit-string! em.out system-id raw-escapes)
          (emit-ascii! em.out "'"))
        (begin
          (emit-ascii! em.out "\"")
          (emit-string! em.out system-id raw-escapes)
          (emit-ascii! em.out "\""))))
    (emit-ascii! em.out ">")))

(def (emit-document! (em  :- XMLEmitter)
                     (doc :- XMLDocument)) => :void
  (let (doctype doc.doctype)
    (emit-children! em doc.prolog)
    (when doctype
      (emit-doctype! em doctype))
    (emit-element! em doc.root)
    (emit-children! em doc.epilog)))

;;; Writes a document or a node.
(def (emit-xml! (em   :- XMLEmitter)
                (node :- XML)) => :void
  (if (XMLDocument? node)
    (emit-document! em node)
    (emit-node! em node)))
