;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; TAL template compiler: a read template (./reader) as the body of a
;;; template procedure. Internal to :std/text/markup/tal, which runs it at
;;; expansion time; its imports must stay free of I/O (and so of C code).
;;;
;;; Markup without TAL is serialized here, through the HTML writer's
;;; emitter, into byte literals; adjacent static markup is one literal.
;;; Statements become calls to ./runtime in the order of the Zope TAL
;;; specification: define, switch, condition, repeat, case, then content or
;;; replace, attributes, omit-tag; on-error handles errors of the element's
;;; tags and content.
;;;
;;; The result is a datum. Symbols starting with % are temporaries; other
;;; symbols name bindings of the define-TAL module (runtime procedures and
;;; core forms); the caller gives both their syntax. User code (expressions,
;;; define and repeat variables, repeat/<name>.<method>, err) is already
;;; syntax at the use site, made by the user procedure the caller passes.
(import ../xml/node
        :std/io/bio/types
        ../output
        ../html/node
        ../html/rules
        ../html/emitter
        ./reader)
(export compile-tal-template)

;;; The statements, in the order they apply.
(def statement-names
  '("define" "switch" "condition" "repeat" "case" "content" "replace" "attributes"
    "omit-tag" "on-error"))

(defstruct TALCompiler
  ((h         :- HTMLEmitter)   ; serializes static markup into h.out
   (positions :- HashTable)     ; of the template (TALTemplate)
   (dynamic   :- HashTable)     ; of its elements, those that are dynamic? (mark-elements!)
   (columns   :- HashTable)     ; of its elements, those that writes-column? (mark-elements!)
   (fail      :- :procedure)    ; (fail offset message), does not return
   (user      :- :procedure)    ; (user datum offset) => syntax at the use site
   (forms     :- :list)         ; forms of the current block, last first
   (count     :- :fixnum))      ; temporaries made
  final: #t)

;;; Compiles template into the forms of a procedure body that renders it;
;;; the forms refer to the render as %r.
(def (compile-tal-template (template :- TALTemplate)
                           (fail     :- :procedure)
                           (user     :- :procedure)) => :list
  (let* ((h (make-html-emitter (make-memory-output) #f))
         (dynamic (make-hash-table-eq))
         (columns (make-hash-table-eq))
         (c (make-TALCompiler h template.positions dynamic columns fail user '() 0)))
    (mark-elements! template.nodes dynamic columns)
    (block! c (lambda () (compile-nodes! c template.nodes context-free 0)))))

;;; blocks: sequences of forms in which static markup accumulates in the
;;; emitter until code follows

;;; A copy of the static markup written since the last call: the buffer is
;;; reused.
(def (static-bytes! (c :- TALCompiler)) => :u8vector
  (let (bytes (subu8vector c.h.out.buf 0 c.h.out.whi))
    (set! c.h.out.whi 0)
    bytes))

(def (flush! (c :- TALCompiler)) => :void
  (let (bytes (static-bytes! c))
    (unless (fx= (u8vector-length bytes) 0)
      (set! c.forms (cons ['tal-emit-bytes! '%r ['quote bytes]] c.forms)))))

(def (code! (c    :- TALCompiler)
            (form :- :pair)) => :void
  (flush! c)
  (set! c.forms (cons form c.forms)))

;;; The forms that thunk adds to a new block.
(def (block! (c     :- TALCompiler)
             (thunk :- :procedure)) => :list
  (flush! c)
  (let (outer c.forms)
    (set! c.forms '())
    (thunk)
    (flush! c)
    (let (forms (reverse c.forms))
      (set! c.forms outer)
      forms)))

(def (temporary! (c      :- TALCompiler)
                 (prefix :- :string)) => :symbol
  (set! c.count (fx+ c.count 1))
  (string->symbol (string-append "%" prefix (number->string c.count))))

(def (position (c       :- TALCompiler)
               (node    :- XML)
               (default :- :fixnum)) => :fixnum
  (hash-ref c.positions node default))

;;; Runs (write h) for markup at offset; writer errors are template errors.
(def (static! (c      :- TALCompiler)
              (offset :- :fixnum)
              (write  :- :procedure)) => :t
  (with-catch
   (lambda (e) (c.fail offset (writer-error-message e)))
   (lambda () (write c.h))))

(def (writer-error-message (e :- :t)) => :string
  (let (irritants (and (error-object? e) (error-irritants e)))
    (cond
     ((and (list? irritants) (memq expectation: irritants))
      => (lambda (rest)
           (string-append "cannot be written as HTML: expected "
                          (if (pair? (cdr rest)) (value->string (cadr rest)) "?")
                          (if (and (pair? (cdr rest)) (pair? (cddr rest)))
                            (string-append ", got " (value->string (caddr rest)))
                            ""))))
     ((error-message e) => (cut string-append "cannot be written as HTML: " <>))
     (else "cannot be written as HTML"))))

(def (value->string (x :- :t)) => :string
  (cond
   ((string? x) x)
   ((XMLElement? x) (using (x :- XMLElement) (string-append "<" x.name.local ">")))
   ((XMLName? x) (using (x :- XMLName) x.local))
   (else (call-with-output-string "" (lambda (port) (write x port))))))

;;; nodes

;;; True when node, a node of the template, is or holds an element with
;;; TAL.
(def (dynamic? (c    :- TALCompiler)
               (node :- XML)) => :boolean
  (hash-get c.dynamic node))

;;; Puts in dynamic the elements of nodes and their descendants that are or
;;; hold an element with TAL, and in columns the tal: elements and elements
;;; with tal:omit-tag that hold one that may write a col (writes-column?),
;;; both eq? tables to #t. Computed once, bottom up: asking each element for
;;; its subtree would walk the elements below it once for each element
;;; around them (markup-benchmark.ss modes tal-dynamic-spans and
;;; tal-template-columns).
(def (mark-elements! (nodes   :- :list)
                     (dynamic :- HashTable)
                     (columns :- HashTable)) => :void
  (def (mark-nodes! (nodes :- :list)) => :boolean
    (let loop ((rest nodes) (any? #f))
      (if (pair? rest)
        (loop (cdr rest) (or (mark! (car rest)) any?))
        any?)))
  (def (mark! (node :- XML)) => :boolean
    (and (XMLElement? node)
         (using (el node :- XMLElement)
           (let* ((below? (mark-nodes! el.children))
                  (statements (tal-attributes el)))
             (when (and (or (tal-element? el) (assoc "omit-tag" statements))
                        (ormap (cut writes-column? columns <>) el.children))
               (hash-put! columns el #t))
             (and (or below? (tal-element? el) (pair? statements))
                  (begin (hash-put! dynamic el #t) #t))))))
  (mark-nodes! nodes)
  (void))

(def (tal-element? (el :- XMLElement)) => :boolean
  (tal-name? el.name.local))

;;; The tal: attributes of el, as (statement value) lists.
(def (tal-attributes (el :- XMLElement)) => :list
  (filter-map (lambda ((attr :- XMLAttribute))
                (let (local attr.name.local)
                  (and (tal-name? local)
                       [(substring local 4 (string-length local)) attr.value])))
              el.attributes))

(def (compile-nodes! (c        :- TALCompiler)
                     (nodes    :- :list)
                     (context  :- :fixnum)
                     (offset   :- :fixnum)) => :void
  (for-each (cut compile-node! c <> context offset) nodes))

;;; parent: the offset of the parent element, for nodes without their own.
(def (compile-node! (c       :- TALCompiler)
                    (node    :- XML)
                    (context :- :fixnum)
                    (parent  :- :fixnum)) => :void
  (let (offset (position c node parent))
    (cond
     ((dynamic? c node)
      (compile-element! c node context offset))
     ((HTMLDoctype? node)
      (static! c offset (cut emit-html! <> (unchecked-node HTMLDocument [node]))))
     (else
      (static! c offset (cut emit-node! <> node context))))))

;;; tags

;;; Writes the start tag of el (a template element, statements removed) in
;;; context.
(def (emit-start-tag! (h       :- HTMLEmitter)
                      (el      :- XMLElement)
                      (context :- :fixnum)) => :void
  (with-start-tag (h el context) (out name local ns kids class inner)
    (void)))

;;; Counts a noscript element open or closed: the writer checks noscript
;;; content for </noscript, which would end it for a scripting parser.
(def (noscript-count! (h     :- HTMLEmitter)
                      (class :- :fixnum)
                      (delta :- :fixnum)) => :void
  (when (fx= class class-noscript)
    (set! h.noscript (fx+ h.noscript delta))))

;;; Writes the children of el, a template element in namespace ns written
;;; in context, of class class and whose children are in context inner, as
;;; emit-element! writes them, but without the LF after a pre, listing or
;;; textarea start tag, which the start tag writes (compile-statements!).
(def (emit-static-children! (h       :- HTMLEmitter)
                            (el      :- XMLElement)
                            (class   :- :fixnum)
                            (inner   :- :fixnum)
                            (ns      :- :fixnum)
                            (context :- :fixnum)) => :void
  (emit-element-children! h h.out el.name el.name.local ns el.children
                          (fxand class (fxnot class-newline)) context inner #f))

(def (emit-end-tag! (h     :- HTMLEmitter)
                    (el    :- XMLElement)
                    (class :- :fixnum)) => :void
  (emit-element-end-tag! h h.out el.name.local (namespace-code el.name.uri) class))

;;; The class of a start tag of name with attributes attrs in context and
;;; the context of its children, (values class inner); the start tag is
;;; checked, not written.
(def (probe-tag (c       :- TALCompiler)
                (offset  :- :fixnum)
                (name    :- XMLName)
                (attrs   :- :list)
                (context :- :fixnum)) => :values
  (static! c offset (cut start-tag-info <> (unchecked-node XMLElement name attrs '()) context)))

;;; The bytes of attribute name with value value (#f: ' name="', else
;;; ' name="value"') in a start tag of an element in namespace ns (uri).
(def (attribute-bytes (c      :- TALCompiler)
                      (offset :- :fixnum)
                      (ns     :- :fixnum)
                      (uri    :- :string)
                      (name   :- XMLName)
                      (value  :? :string)) => :u8vector
  (flush! c)
  (static! c offset (lambda ((h :- HTMLEmitter)) (emit-attribute! h.out ns uri name value)))
  (static-bytes! c))

;;; statements

;;; The statements of an element: each the value of its tal: attribute, or
;;; #f.
(defstruct TALStatements
  ((define     :? :string)
   (switch     :? :string)
   (condition  :? :string)
   (repeat     :? :string)
   (case       :? :string)
   (content    :? :string)
   (replace    :? :string)
   (attributes :? :string)
   (omit-tag   :? :string)
   (on-error   :? :string))
  final: #t)

(def (element-statements (c      :- TALCompiler)
                         (el     :- XMLElement)
                         (offset :- :fixnum)) => TALStatements
  (let ((table (make-hash-table))
        (local el.name.local))
    (for-each
      (lambda (statement)
        (let (name (car statement))
          (unless (member name statement-names)
            (c.fail offset (string-append "<" local ">: unknown TAL attribute tal:" name)))
          (hash-put! table name (cadr statement))))
      (tal-attributes el))
    (when (and (hash-get table "content") (hash-get table "replace"))
      (c.fail offset (string-append "<" local ">: tal:content and tal:replace together")))
    (apply make-TALStatements (map (cut hash-get table <>) statement-names))))

;;; The forms of str, read as Gerbil data.
(def (read-forms (c      :- TALCompiler)
                 (offset :- :fixnum)
                 (what   :- :string)
                 (str    :- :string)) => :list
  (with-catch
   (lambda (e)
     (c.fail offset (string-append "tal:" what ": cannot read \"" str "\": "
                                   (or (error-message e) "syntax error"))))
   (lambda ()
     (let (port (open-input-string str))
       (let loop ((forms '()))
         (let (form (read port))
           (if (eof-object? form)
             (reverse forms)
             (loop (cons form forms)))))))))

;;; forms as one user expression: "" for none.
(def (user-expression (c      :- TALCompiler)
                      (offset :- :fixnum)
                      (forms  :- :list)) => :t
  (cond
   ((null? forms) "")
   ((null? (cdr forms)) (c.user (car forms) offset))
   (else (cons 'begin (map (cut c.user <> offset) forms)))))

;;; The type keyword and expression of a content, replace or on-error
;;; value: (values type forms).
(def (typed-forms (c      :- TALCompiler)
                  (offset :- :fixnum)
                  (what   :- :string)
                  (str    :- :string)
                  (types  :- :list)) => :values
  (let (forms (read-forms c offset what str))
    (if (and (pair? forms) (memq (car forms) types))
      (values (car forms) (cdr forms))
      (begin
        (when (and (pair? forms) (keyword? (car forms)))
          (c.fail offset (string-append "tal:" what ": unknown type "
                                        (value->string (car forms)))))
        (values text: forms)))))

;;; The runtime call that writes value (a temporary) of type type as the
;;; content of an element named local of class class; raw text (text: and
;;; as-is:, not raw:) is checked for its end tag, and inside a noscript
;;; element for </noscript.
(def (value-writer (c     :- TALCompiler)
                   (type  :- :keyword)
                   (class :- :fixnum)
                   (local :- :string)
                   (value :- :symbol)) => :list
  (cond
   ((eq? type raw:) ['tal-emit-raw! '%r value])
   ((class-has? class class-raw)
    [(if (eq? type as-is:) 'tal-emit-as-is-raw-text! 'tal-emit-raw-text!)
     '%r local (class-has? class class-script) (fx> c.h.noscript 0) value])
   ((eq? type as-is:) ['tal-emit-as-is! '%r value])
   (else ['tal-emit-text! '%r value])))

;;; elements

;;; A tal:attributes item: the attribute's name, its expression, and the
;;; temporary that holds its value.
(defstruct TALAttributeStatement
  ((name :- XMLName)
   (expr :- :t)
   (temp :- :symbol))
  final: #t)

(def (compile-element! (c       :- TALCompiler)
                       (el      :- XMLElement)
                       (context :- :fixnum)
                       (offset  :- :fixnum)) => :void
  (compile-statements! c el (element-statements c el offset) context offset))

;;; Compiles el, an element with statements st.
(def (compile-statements! (c       :- TALCompiler)
                          (el      :- XMLElement)
                          (st      :- TALStatements)
                          (context :- :fixnum)
                          (offset  :- :fixnum)) => :void
  (let* ((local el.name.local)
         (omitted? (tal-element? el))
         (static-attrs (filter (lambda ((attr :- XMLAttribute)) (not (tal-name? attr.name.local)))
                               el.attributes))
         (dynamic-attrs (if st.attributes (attribute-statements c el offset st.attributes) '()))
         (template (unchecked-node XMLElement el.name static-attrs el.children)))
    ;; checked with every attribute it may get
    (defvalues (class inner)
      (if omitted?
        (values 0 context)
        (probe-tag c offset el.name
                   (final-attributes static-attrs dynamic-attrs
                                     (lambda ((dynamic :- TALAttributeStatement) attr)
                                       (unchecked-node XMLAttribute dynamic.name "")))
                   context)))
    (def omit
      (cond
       ((not st.omit-tag) #f)
       ((null? (read-forms c offset "omit-tag" st.omit-tag)) #t)
       (else (temporary! c "omit"))))
    (def (fail-void! what)
      (c.fail offset (string-append "<" local "> is a void element: tal:" what " cannot give it content")))
    (when (and (not omitted?) (class-has? class class-void))
      (when st.content
        (fail-void! "content")))
    ;; Without its tags, the element's content would be read in the
    ;; parent's context: raw text as markup, the children of an integration
    ;; point in another namespace.
    (when (and omit
               (not omitted?)
               (or (class-has? class class-raw)
                   (not (or (fx= inner context)
                            (and (fx= context context-free) (fx= inner context-html))))))
      (c.fail offset (string-append "<" local ">: tal:omit-tag cannot leave out these tags,"
                                    " without which the content is read in another context")))

    ;; start tag, content (added by content!), end tag; dynamic-content?:
    ;; content! may write other than the template's static children
    (def (tags! content! dynamic-content?)
      (def (start!)
        (unless omitted?
          (if (null? dynamic-attrs)
            (static! c offset (cut emit-start-tag! <> template context))
            (dynamic-start-tag! c offset template static-attrs dynamic-attrs))
          ;; The parser drops an LF right after a pre, listing or textarea
          ;; start tag. Whether the content starts with one is known only
          ;; for static content, so any other gets an LF to drop.
          (when (and (class-has? class class-newline)
                     (or dynamic-content? (newline-first? el.children)))
            (static! c offset (lambda ((h :- HTMLEmitter)) (emit-ascii! h.out "\n"))))
          (static! c offset (cut noscript-count! <> class 1))))
      (def (end!)
        (unless omitted?
          (static! c offset (cut noscript-count! <> class -1))
          (static! c offset (cut emit-end-tag! <> template class))))
      (cond
       ((symbol? omit)
        ;; the content compiles once, checked as inside the tags (the
        ;; stricter state: noscript counted open)
        (code! c ['unless omit '(void) (block! c start!) ...])
        (content!)
        (code! c ['unless omit '(void) (block! c end!) ...]))
       ((eq? omit #t) (content!))
       (else (start!) (content!) (end!))))

    (def (children!)
      (compile-children! c template class inner
                         (if omitted? ns-html (namespace-code el.name.uri))
                         context (and omit #t) offset))
    (def dynamic-children? (ormap (cut dynamic? c <>) el.children))

    ;; a value written as the element's content, in its own statement
    (def (content-value! type forms default?)
      (let (v (temporary! c "value"))
        (code! c ['tal-scope '%r
                  ['let [[v ['tal-user '%r (user-expression c offset forms)]]]
                    (if default?
                      ['if ['eq? v default:]
                           ['begin '(void) (block! c children!) ...]
                           (value-writer c type class local v)]
                      (value-writer c type class local v))]])))

    ;; the element's tags and content, or its replacement
    (def (element!)
      (cond
       (st.replace
        (let-values (((type forms) (typed-forms c offset "replace" st.replace [text: as-is: raw:])))
          (let (v (temporary! c "value"))
            (code! c ['let [[v ['tal-user '%r (user-expression c offset forms)]]]
                      ['if ['eq? v default:]
                           ['begin '(void) (block! c (lambda () (tags! children! dynamic-children?))) ...]
                           (value-writer c type 0 local v)]]))))
       (st.content
        (let-values (((type forms) (typed-forms c offset "content" st.content [text: as-is: raw:])))
          (tags! (lambda () (content-value! type forms (not (eq? type raw:)))) #t)))
       (else (tags! children! dynamic-children?))))

    ;; on-error around the tags and content
    (def (guarded!)
      (if st.on-error
        (let-values (((type forms) (typed-forms c offset "on-error" st.on-error
                                                [text: as-is: raw: ignore: 'ignore])))
          (let* ((ignore? (memq type [ignore: 'ignore]))
                 (body (block! c element!))
                 (handler
                  (block! c
                    (lambda ()
                      (cond
                       (ignore?
                        (unless (null? forms)
                          (code! c ['tal-user '%r (user-expression c offset forms)])))
                       ((and (not omitted?) (class-has? class class-void))
                        (fail-void! "on-error"))
                       (else
                        (tags! (lambda () (content-value! type forms #f)) #t)))))))
            (code! c ['tal-on-error-scope '%r (c.user 'err offset)
                      ['begin '(void) body ...]
                      ['begin '(void) handler ...]])))
        (element!)))

    ;; tal:attributes and tal:omit-tag values, evaluated before the tags
    (def (valued!)
      (let (bindings
            (append (map (lambda ((dynamic :- TALAttributeStatement))
                           [dynamic.temp ['tal-user '%r (c.user dynamic.expr offset)]])
                         dynamic-attrs)
                    (if (symbol? omit)
                      [[omit ['tal-user '%r
                              (user-expression c offset (read-forms c offset "omit-tag" st.omit-tag))]]]
                      '())))
        (if (null? bindings)
          (guarded!)
          (code! c ['let* bindings '(void) (block! c guarded!) ...]))))

    (def (case!)
      (if st.case
        (let (forms (read-forms c offset "case" st.case))
          (code! c ['when (if (equal? forms '(else:))
                            '(tal-case-else?)
                            ['tal-case? ['tal-user '%r (user-expression c offset forms)]])
                     '(void)
                     (block! c valued!) ...]))
        (valued!)))

    (def (repeat!)
      (if st.repeat
        (let (forms (read-forms c offset "repeat" st.repeat))
          (unless (and (fx= (length forms) 1) (list? (car forms)) (fx= (length (car forms)) 2)
                       (symbol? (caar forms)))
            (c.fail offset "tal:repeat: expected (name expression)"))
          (let* ((var (caar forms))
                 (iteration (temporary! c "repeat"))
                 (loop (temporary! c "loop"))
                 (repeat-var (string-append "repeat/" (symbol->string var))))
            (code! c ['let* [[iteration ['make-tal-repeat ['tal-user '%r (c.user (cadar forms) offset)]]]
                             [(c.user (string->symbol repeat-var) offset) iteration]
                             (map (lambda (method)
                                    [(c.user (string->symbol (string-append repeat-var "." method)) offset)
                                     ['lambda '() [(string->symbol (string-append "repeat-" method))
                                                   iteration]]])
                                  repeat-methods)
                             ...]
                      ['let loop []
                        ['when ['tal-repeat-next! iteration]
                          ['let [[(c.user var offset) ['tal-repeat-item iteration]]]
                            '(void)
                            (block! c case!) ...]
                          [loop]]]])))
        (case!)))

    (def (condition!)
      (if st.condition
        (let (forms (read-forms c offset "condition" st.condition))
          (code! c ['when ['tal-user '%r (user-expression c offset forms)]
                     '(void)
                     (block! c repeat!) ...]))
        (repeat!)))

    (def (switch!)
      (if st.switch
        (let (forms (read-forms c offset "switch" st.switch))
          (code! c ['parameterize [['current-tal-switch
                                    ['make-TALSwitch ['tal-user '%r (user-expression c offset forms)]
                                                      #f]]]
                     '(void)
                     (block! c condition!) ...]))
        (condition!)))

    ;; define bindings, in order: local ones bind around the rest
    (def (define!)
      (let loop ((bindings (if st.define (define-bindings c offset st.define) '())))
        (if (null? bindings)
          (switch!)
          (let* ((binding (car bindings))
                 (global? (car binding))
                 (pattern (c.user (cadr binding) offset))
                 (value ['tal-user '%r (c.user (caddr binding) offset)]))
            (if global?
              (begin
                (code! c ['set! pattern value])
                (loop (cdr bindings)))
              (code! c ['with* [[pattern value]]
                         '(void)
                         (block! c (lambda () (loop (cdr bindings)))) ...]))))))

    (if (or st.define st.switch st.condition st.repeat st.case st.attributes
            (symbol? omit) st.on-error st.replace)
      (code! c ['tal-scope '%r '(void) (block! c define!) ...])
      (define!))))

;;; The methods of a repeat variable (repeat/<name>.<method>), by name.
(def repeat-methods
  '("index" "number" "even?" "odd?" "start?" "end?" "letter" "Letter" "roman" "Roman"))

;;; The bindings of a tal:define value, in order: (global? pattern
;;; expression) lists; set!: makes the next binding global.
(def (define-bindings (c      :- TALCompiler)
                      (offset :- :fixnum)
                      (str    :- :string)) => :list
  (let loop ((forms (read-forms c offset "define" str)) (global? #f) (result '()))
    (cond
     ((null? forms) (reverse result))
     ((keyword? (car forms))
      (let (kw (car forms))
        (unless (memq kw [set!: local:])
          (c.fail offset (string-append "tal:define: unknown keyword " (value->string kw))))
        (loop (cdr forms) (eq? kw set!:) result)))
     ((and (list? (car forms)) (fx= (length (car forms)) 2))
      (let (binding (car forms))
        (when (and global? (not (symbol? (car binding))))
          (c.fail offset "tal:define: set!: needs a variable"))
        (loop (cdr forms) #f (cons [global? (car binding) (cadr binding)] result))))
     (else
      (c.fail offset (string-append "tal:define: expected (variable expression), got "
                                    (value->string (car forms))))))))

;;; The tal:attributes of el, names checked: TALAttributeStatement list.
(def (attribute-statements (c      :- TALCompiler)
                           (el     :- XMLElement)
                           (offset :- :fixnum)
                           (str    :- :string)) => :list
  (let* ((ns (namespace-code el.name.uri))
         (annotation-xml? (and (string=? el.name.uri mathml-namespace-uri)
                               (string=? el.name.local "annotation-xml"))))
    (map (lambda (form)
           (unless (and (list? form) (fx= (length form) 2) (symbol? (car form)))
             (c.fail offset (string-append "tal:attributes: expected (name expression), got "
                                           (value->string form))))
           (let (name (ascii-downcase (symbol->string (car form))))
             (when (tal-name? name)
               (c.fail offset (string-append "tal:attributes: cannot set " name)))
             ;; Its value decides whether the parser reads the children as
             ;; HTML or MathML, which the template has fixed.
             (when (and annotation-xml? (string=? name "encoding"))
               (c.fail offset "tal:attributes: cannot set encoding of <annotation-xml>"))
             (make-TALAttributeStatement (template-attribute-name ns name)
                                         (cadr form)
                                         (temporary! c "attribute"))))
         (read-forms c offset "attributes" str))))

;;; The attributes of a start tag with the template's attributes static and
;;; tal:attributes dynamic: the first dynamic one of a name replaces the
;;; static one of that name in place, others follow in order; names are the
;;; same when their namespaces, prefixes and ASCII-folded locals are. (item
;;; dynamic attr) gives the entry of a dynamic one; attr is the static one
;;; it replaces, or #f. Names are found in tables, as a start tag may have
;;; any number of attributes (markup-benchmark.ss mode tal-attributes).
(def (final-attributes (static  :- :list)
                       (dynamic :- :list)
                       (item    :- :procedure)) => :list
  (def (key (name :- XMLName)) => :list
    [name.uri name.prefix (ascii-downcase name.local)])
  (let ((dynamic-by-key (make-hash-table))
        (static-keys (make-hash-table)))
    (for-each (lambda ((dynamic :- TALAttributeStatement))
                (let (k (key dynamic.name))
                  (unless (hash-key? dynamic-by-key k)
                    (hash-put! dynamic-by-key k dynamic))))
              dynamic)
    (for-each (lambda ((attr :- XMLAttribute))
                (hash-put! static-keys (key attr.name) #t))
              static)
    (append (map (lambda ((attr :- XMLAttribute))
                   (let (dynamic (hash-get dynamic-by-key (key attr.name)))
                     (if dynamic (item dynamic attr) attr)))
                 static)
            (filter-map (lambda ((dynamic :- TALAttributeStatement))
                          (and (not (hash-key? static-keys (key dynamic.name)))
                               (item dynamic #f)))
                        dynamic))))

;;; Writes the start tag of template, checked as probe-tag checks it, with
;;; tal:attributes dynamic: static attributes as static markup, dynamic ones
;;; from their temporaries.
(def (dynamic-start-tag! (c        :- TALCompiler)
                         (offset   :- :fixnum)
                         (template :- XMLElement)
                         (static   :- :list)
                         (dynamic  :- :list)) => :void
  (let* ((local template.name.local)
         (uri template.name.uri)
         (ns (namespace-code uri)))
    (static! c offset (lambda ((h :- HTMLEmitter))
                        (emit-ascii! h.out "<")
                        (emit-tag-name! h.out local (fx= ns ns-svg))))
    (for-each
      (lambda (entry)
        (if (XMLAttribute? entry)
          (using (attr entry :- XMLAttribute)
            (static! c offset (lambda ((h :- HTMLEmitter))
                                (emit-attribute! h.out ns uri attr.name attr.value))))
          (using ((dynamic (car entry) :- TALAttributeStatement)
                  (attr (cdr entry) :? XMLAttribute))
            (code! c ['tal-emit-attribute! '%r
                      ['quote (attribute-bytes c offset ns uri dynamic.name #f)]
                      (and attr ['quote (attribute-bytes c offset ns uri attr.name attr.value)])
                      dynamic.temp]))))
      (final-attributes static dynamic cons))
    (static! c offset (lambda ((h :- HTMLEmitter)) (emit-ascii! h.out ">")))))

;;; The children of template, a dynamic element in namespace ns written in
;;; context, of class class and whose children are in context inner;
;;; may-omit? when its tags may be left out. Dynamic children compile with
;;; the emitter state that emit-element-children! keeps for write-html
;;; (frameset and template rules for ignored start tags); a tag that may be
;;; left out keeps the outer state. The foreign element rule needs no state
;;; here: the reader gives the top level foreign elements only as svg and
;;; math, whose children are not read as HTML.
(def (compile-children! (c         :- TALCompiler)
                        (template  :- XMLElement)
                        (class     :- :fixnum)
                        (inner     :- :fixnum)
                        (ns        :- :fixnum)
                        (context   :- :fixnum)
                        (may-omit? :- :boolean)
                        (offset    :- :fixnum)) => :void
  (let (kids template.children)
    (cond
     ((not (ormap (cut dynamic? c <>) kids))
      (static! c offset (cut emit-static-children! <> template class inner ns context)))
     ((fx= class class-frameset)
      (set! c.h.ignored (fxmax c.h.ignored ignored-frameset))
      (compile-nodes! c kids inner offset))
     ((fx= class class-template)
      (let (outer c.h.ignored)
        (unless (or may-omit? (fx= outer ignored-frameset))
          (set! c.h.ignored ignored-none))
        (for-each (lambda (kid)
                    (when (writes-column? c.columns kid)
                      (set! c.h.ignored ignored-column-group))
                    (compile-node! c kid inner offset))
                  kids)
        (set! c.h.ignored outer)))
     (else
      (compile-nodes! c kids inner offset)))))

;;; True when node may write a col element where it stands: a col, or a
;;; tal: element or an element with tal:omit-tag holding one (columns, as
;;; mark-elements! fills it).
(def (writes-column? (columns :- HashTable)
                     (node    :- XML)) => :boolean
  (or (column-element? node)
      (hash-get columns node)))
