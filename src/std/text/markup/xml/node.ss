;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Typed XML node structs rooted at XML, whose constructors check their
;;; arguments, the unchecked allocation the readers build trees with
;;; (unchecked-node), and the XML name and namespace rules shared by the
;;; scanner, emitter and constructors. :std/text/markup/xml/types exports
;;; the types and the documented factories.
(import :std/error
        (only-in ../scan-input ascii make-byte-table))
;;; No slot setters: nodes are immutable (./types).
(export XML
        XML::t
        XML?
        XMLName
        XMLName::t
        XMLName?
        make-XMLName
        XMLName-local
        XMLName-uri
        XMLName-prefix
        XMLAttribute
        XMLAttribute::t
        XMLAttribute?
        make-XMLAttribute
        XMLAttribute-name
        XMLAttribute-value
        XMLElement
        XMLElement::t
        XMLElement?
        make-XMLElement
        XMLElement-name
        XMLElement-attributes
        XMLElement-children
        XMLText
        XMLText::t
        XMLText?
        make-XMLText
        XMLText-data
        XMLCData
        XMLCData::t
        XMLCData?
        make-XMLCData
        XMLCData-data
        XMLComment
        XMLComment::t
        XMLComment?
        make-XMLComment
        XMLComment-data
        XMLPI
        XMLPI::t
        XMLPI?
        make-XMLPI
        XMLPI-target
        XMLPI-data
        XMLDoctype
        XMLDoctype::t
        XMLDoctype?
        make-XMLDoctype
        XMLDoctype-name
        XMLDoctype-public-id
        XMLDoctype-system-id
        XMLDocument
        XMLDocument::t
        XMLDocument?
        make-XMLDocument
        XMLDocument-prolog
        XMLDocument-root
        XMLDocument-epilog
        XMLDocument-doctype
        unchecked-node
        xml-node?
        xml-name=?
        xml-namespace-uri
        xmlns-namespace-uri
        xml-space?
        name-other
        name-char
        name-start
        name-high
        name-class
        xml-name-start-code?
        xml-name-code?
        string-same?
        pairwise-attribute-limit
        pairwise-duplicate
        find-duplicate
        xml-name<?
        pubid-code?
        xml-comment-data?
        namespace-binding-error
        namespace-declaration-error
        system-literal-string?)

;;; The root of the XML and HTML node types: a nominal type with no slots.
;;; Context-specific predicates (xml-node?, html-node?) decide what may be
;;; a child; being an XML is not enough.
(defstruct XML ())

;;; The node types check their arguments as they are constructed, by
;;; applying the type, (XMLName local uri prefix), or through the factories
;;; of ./types, aliases of their constructors (make-XMLName), and raise
;;; ContractViolation. Trees built
;;; under the HTML rules share the structs without those conditions, so the
;;; writers trust only the slot types (./types).

;;; (unchecked-node Type field ...): a node of Type, one of the node
;;; structs, its fields in slot order, allocated without the checks of its
;;; constructor. For the readers, the HTML tree builder, TAL and Djot, which
;;; establish what the constructors check as they parse, and for the HTML
;;; factories of ../html/types, which check the HTML rules instead.
(defsyntax (unchecked-node stx)
  (syntax-case stx ()
    ((_ type field ...)
     (let (info (syntax-local-value #'type))
       (unless (fx= (length (!class-type-ordered-slots info)) (length #'(field ...)))
         (raise-syntax-error #f "fields do not match the node type's slots" stx #'type))
       (with-syntax ((type::t (!class-type-descriptor info)))
         #'(:- (##structure type::t field ...) type))))))

;;; The empty string stands for "no namespace" (uri) and "no prefix" (prefix),
;;; as the empty namespace name does in XML Namespaces.
;;; Two names are the same name when their uri and local parts are equal;
;;; the prefix only records the spelling.
(defstruct (XMLName XML)
  ((local  :- :string)
   (uri    :- :string)
   (prefix :- :string))
  constructor: :init!
  final: #t)

;;; A name in Namespaces in XML terms: a prefix needs a namespace. The XML
;;; namespace takes exactly the prefix xml, which is also the default
;;; there; the xmlns namespace only names namespace declarations,
;;; xmlns:local (the default prefix) or xmlns without a prefix, and is
;;; never declared itself.
(defmethod {:init! XMLName}
  (lambda (self
           (local  : :string)
           (uri    : :string := "")
           (prefix : :string := ""))
    (let (prefix (cond
                  ((not (string-empty? prefix)) prefix)
                  ((string=? uri xml-namespace-uri) "xml")
                  ((and (string=? uri xmlns-namespace-uri) (not (string=? local "xmlns"))) "xmlns")
                  (else prefix)))
      (unless (ncname? local)
        (raise-bad-argument XMLName "NCName local part" local))
      (unless (or (string-empty? prefix) (ncname? prefix))
        (raise-bad-argument XMLName "NCName prefix or \"\"" prefix))
      (when (and (string-empty? uri) (not (string-empty? prefix)))
        (raise-bad-argument XMLName "namespace for prefix" prefix))
      (unless (eq? (string=? prefix "xml") (string=? uri xml-namespace-uri))
        (raise-bad-argument XMLName "prefix xml exactly for the XML namespace" prefix uri))
      (unless (eq? (string=? prefix "xmlns")
                   (and (string=? uri xmlns-namespace-uri)
                        (not (and (string-empty? prefix) (string=? local "xmlns")))))
        (raise-bad-argument XMLName "prefix xmlns exactly for namespace declarations"
                            prefix uri))
      (when (and (string=? prefix "xmlns") (string=? local "xmlns"))
        (raise-bad-argument XMLName "declarable prefix" local))
      (set! self.local local)
      (set! self.uri uri)
      (set! self.prefix prefix))))

(defstruct (XMLAttribute XML)
  ((name  :- XMLName)
   (value :- :string))
  constructor: :init!
  final: #t)

;;; Namespace declarations (attributes named in xmlns-namespace-uri) must be
;;; named and bind what Namespaces in XML allows (namespace-declaration-error):
;;; xmlns or xmlns:prefix, a prefix to a non-empty namespace, the xml prefix
;;; only to its namespace, and neither reserved namespace otherwise.
(defmethod {:init! XMLAttribute}
  (lambda (self
           (name  : XMLName)
           (value : :string))
    (let (problem (namespace-declaration-error name.uri name.local name.prefix value))
      (when problem
        (raise-bad-argument XMLAttribute problem name)))
    (set! self.name name)
    (set! self.value value)))

;;; attributes: list of XMLAttribute in document order, including namespace
;;; declarations (named in xmlns-namespace-uri, as in the DOM).
;;; children: list of XMLElement, XMLText, XMLCData, XMLComment, XMLPI.
(defstruct (XMLElement XML)
  ((name       :- XMLName)
   (attributes :- :list)
   (children   :- :list))
  constructor: :init!
  final: #t)

;;; attributes: list of XMLAttribute with distinct names; declarations among
;;; them must agree with the element's own name.
;;; children: list of xml-node? values.
(defmethod {:init! XMLElement}
  (lambda (self
           (name       : XMLName)
           (attributes :~ (list-of? XMLAttribute?) :- :list)
           (children   :~ (list-of? xml-node?)     :- :list))
    (let ((uri name.uri)
          (prefix name.prefix))
      (when (string=? uri xmlns-namespace-uri)
        (raise-bad-argument XMLElement "element name outside xmlns-namespace-uri" name))
      (for-each
       (lambda ((attr :- XMLAttribute))
         (when (and (string=? attr.name.uri xmlns-namespace-uri)
                    (if (string-empty? prefix)
                      (string-empty? attr.name.prefix)
                      (and (string=? attr.name.prefix "xmlns") (string=? attr.name.local prefix)))
                    (not (string=? attr.value uri)))
           (raise-bad-argument XMLElement "declarations agreeing with the element name" name)))
       attributes)
      (let (duplicate (find-duplicate (map (lambda ((attr :- XMLAttribute)) attr.name) attributes)
                                      xml-name<?
                                      xml-name=?))
        (when duplicate
          (raise-bad-argument XMLElement "distinct attribute names" duplicate))))
    (set! self.name name)
    (set! self.attributes attributes)
    (set! self.children children)))

(defstruct (XMLText XML)
  ((data :- :string))
  constructor: :init!
  final: #t)

(defmethod {:init! XMLText}
  (lambda (self (data : :string))
    (set! self.data data)))

(defstruct (XMLCData XML)
  ((data :- :string))
  constructor: :init!
  final: #t)

(defmethod {:init! XMLCData}
  (lambda (self (data : :string))
    (when (string-contains data "]]>")
      (raise-bad-argument XMLCData "data without ]]>" data))
    (set! self.data data)))

(defstruct (XMLComment XML)
  ((data :- :string))
  constructor: :init!
  final: #t)

(defmethod {:init! XMLComment}
  (lambda (self (data : :string))
    (unless (xml-comment-data? data)
      (raise-bad-argument XMLComment "data without -- or a final -" data))
    (set! self.data data)))

(defstruct (XMLPI XML)
  ((target :- :string)
   (data   :- :string))
  constructor: :init!
  final: #t)

;;; target: an NCName other than xml in any case. data: no ?>, and not
;;; starting with whitespace: the space after the target is syntax, so
;;; read-xml could not return it.
(defmethod {:init! XMLPI}
  (lambda (self
           (target : :string)
           (data   : :string))
    (unless (and (ncname? target) (not (string-ci=? target "xml")))
      (raise-bad-argument XMLPI "NCName target other than xml" target))
    (when (string-contains data "?>")
      (raise-bad-argument XMLPI "data without ?>" data))
    (when (and (fx> (string-length data) 0)
               (memv (string-ref data 0) '(#\space #\tab #\newline #\return)))
      (raise-bad-argument XMLPI "data not starting with whitespace" data))
    (set! self.target target)
    (set! self.data data)))

;;; A document type declaration without its internal subset. public-id
;;; requires system-id, as in an ExternalID.
(defstruct (XMLDoctype XML)
  ((name      :- :string)
   (public-id :? :string)
   (system-id :? :string))
  constructor: :init!
  final: #t)

;;; name: a QName; public-id: PubidChar only, and requires system-id;
;;; system-id: cannot contain both " and '. CR in either is written as is and
;;; reads back as LF.
(defmethod {:init! XMLDoctype}
  (lambda (self
           (name      : :string)
           (public-id :? :string := #f)
           (system-id :? :string := #f))
    (unless (qname? name)
      (raise-bad-argument XMLDoctype "QName" name))
    (when public-id
      (unless (and system-id (pubid-string? public-id))
        (raise-bad-argument XMLDoctype
                            "public identifier of PubidChar with a system identifier"
                            public-id)))
    (when system-id
      (unless (system-literal-string? system-id)
        (raise-bad-argument XMLDoctype "system identifier without both quote characters"
                            system-id)))
    (set! self.name name)
    (set! self.public-id public-id)
    (set! self.system-id system-id)))

;;; prolog and epilog: lists of XMLComment and XMLPI around the root element.
;;; doctype: the document type declaration, or #f.
(defstruct (XMLDocument XML)
  ((prolog  :- :list)
   (root    :- XMLElement)
   (epilog  :- :list)
   (doctype :? XMLDoctype))
  constructor: :init!
  final: #t)

;;; The writer puts the document type declaration after the prolog.
(defmethod {:init! XMLDocument}
  (lambda (self
           (prolog  :~ (list-of? xml-misc?) :- :list)
           (root    :  XMLElement)
           (epilog  :~ (list-of? xml-misc?) :- :list)
           (doctype :? XMLDoctype := #f))
    (set! self.prolog prolog)
    (set! self.root root)
    (set! self.epilog epilog)
    (set! self.doctype doctype)))

;;; Child of an element: element, text, CDATA section, comment or processing
;;; instruction.
(def (xml-node? (x : :t)) => :boolean
  (or (XMLElement? x) (XMLText? x) (XMLPI? x) (XMLComment? x) (XMLCData? x)))

;;; Node of a document's prolog or epilog: comment or processing
;;; instruction (the Misc of the XML grammar, without whitespace).
(def (xml-misc? (x : :t)) => :boolean
  (or (XMLComment? x) (XMLPI? x)))

(def xml-namespace-uri "http://www.w3.org/XML/1998/namespace")
(def xmlns-namespace-uri "http://www.w3.org/2000/xmlns/")

(definline (xml-space? (x :- :fixnum)) => :boolean
  (or (fx= x (ascii #\space)) (fx= x (ascii #\newline))
      (fx= x (ascii #\return)) (fx= x (ascii #\tab))))

;;; names

;;; name-class of a byte
(defconst name-other 0)          ; not in a name
(defconst name-char 1)           ; digit . -
(defconst name-start 2)          ; letter _
(defconst name-colon 3)
(defconst name-high 4)           ; byte >= #x80: checked against the XML ranges

(def name-class
  (make-byte-table
   (lambda (b)
     (cond
      ((or (and (fx>= b (ascii #\A)) (fx<= b (ascii #\Z)))
           (and (fx>= b (ascii #\a)) (fx<= b (ascii #\z)))
           (fx= b (ascii #\_)))
       name-start)
      ((or (and (fx>= b (ascii #\0)) (fx<= b (ascii #\9)))
           (fx= b (ascii #\-))
           (fx= b (ascii #\.)))
       name-char)
      ((fx= b (ascii #\:)) name-colon)
      ((fx>= b #x80) name-high)
      (else name-other)))))

;;; XML 1.0 (5th edition) NameStartChar, without the colon.
(def (xml-name-start-code? (c :- :fixnum)) => :boolean
  (if (fx< c #x80)
    (fx= (##u8vector-ref name-class c) name-start)
    (or (and (fx>= c #xc0) (fx<= c #xd6))
        (and (fx>= c #xd8) (fx<= c #xf6))
        (and (fx>= c #xf8) (fx<= c #x2ff))
        (and (fx>= c #x370) (fx<= c #x37d))
        (and (fx>= c #x37f) (fx<= c #x1fff))
        (and (fx>= c #x200c) (fx<= c #x200d))
        (and (fx>= c #x2070) (fx<= c #x218f))
        (and (fx>= c #x2c00) (fx<= c #x2fef))
        (and (fx>= c #x3001) (fx<= c #xd7ff))
        (and (fx>= c #xf900) (fx<= c #xfdcf))
        (and (fx>= c #xfdf0) (fx<= c #xfffd))
        (and (fx>= c #x10000) (fx<= c #xeffff)))))

;;; XML 1.0 (5th edition) NameChar, without the colon.
(def (xml-name-code? (c :- :fixnum)) => :boolean
  (if (fx< c #x80)
    (let (k (##u8vector-ref name-class c))
      (or (fx= k name-char) (fx= k name-start)))
    (or (xml-name-start-code? c)
        (fx= c #xb7)
        (and (fx>= c #x300) (fx<= c #x36f))
        (and (fx>= c #x203f) (fx<= c #x2040)))))

;;; String equality for names, expanded in place: (or (eq? x y) (##string=?
;;; x y)) instead took 56% more instructions and 38% more cycles reading
;;; attribute-heavy XML (markup-benchmark.ss mode xml-read-attributes, SIZE
;;; 1000, ITERATIONS 300), and 28% and 33% more writing HTML (mode
;;; html-write-elements, SIZE 1000, ITERATIONS 300). A macro: as definline
;;; it costs more in the writer.
(defrule (string-same? a b)
  (let ((x a) (y b))
    (or (eq? x y)
        (let (n (##string-length x))
          (and (fx= n (##string-length y))
               (let loop ((k 0))
                 (cond
                  ((fx>= k n) #t)
                  ((eq? (##string-ref x k) (##string-ref y k)) (loop (fx+ k 1)))
                  (else #f))))))))

;;; The most attributes whose names are compared pairwise for duplicates;
;;; more are sorted (find-duplicate). The readers, writers and constructors
;;; share it.
(defconst pairwise-attribute-limit 16)

;;; The first item that same? finds equal to an earlier one, or #f,
;;; comparing each item with every one before it. A position p runs from
;;; start, evaluated once, through next while more? holds, and item is the
;;; item at p; same? compares earlier with later, an item at a later
;;; position. find-duplicate walks a list, (p items (pair? p) (cdr p) (car
;;; p)); the HTML emitter walks indexes. A macro, so that each loop stays
;;; inline: the readers and writers check every start tag's attributes with
;;; it, up to pairwise-attribute-limit, without building a list of names.
(defrule (pairwise-duplicate (p start more? next item) (earlier later same?))
  (let (first start)
    (let outer ((current first))
      (and (let (p current) more?)
           (let (later (let (p current) item))
             (let inner ((before first))
               (if (eq? before current)
                 (outer (let (p current) next))
                 (if (let (earlier (let (p before) item)) same?)
                   later
                   (inner (let (p before) next))))))))))

;;; An item of items that same? finds equal to an earlier one, or #f; less?
;;; is a strict order under which same? items are neither less than the
;;; other. Up to pairwise-attribute-limit items are compared pairwise, and
;;; the first such item is found; more are sorted (list-sort is stable) and
;;; compared with their neighbours, so n items cost O(n log n) whatever they
;;; are: a hash table keyed by strings an attacker chooses can be flooded
;;; with colliding keys.
(def (find-duplicate (items :- :list)
                     (less? :- :procedure)
                     (same? :- :procedure)) => :t
  (if (fx<= (length items) pairwise-attribute-limit)
    (pairwise-duplicate (p items (pair? p) (cdr p) (car p)) (a b (same? a b)))
    (let loop ((sorted (list-sort less? items)))
      (and (pair? sorted)
           (pair? (cdr sorted))
           (if (same? (car sorted) (cadr sorted))
             (cadr sorted)
             (loop (cdr sorted)))))))

;;; Same name: equal local parts and namespaces, whatever the prefixes.
(def (xml-name=? (a : XMLName)
                 (b : XMLName)) => :boolean
  (or (eq? a b)
      (and (string-same? a.local b.local)
           (string-same? a.uri b.uri))))

;;; The order of xml-names by local part, then namespace; names neither
;;; orders before the other are xml-name=?, whatever their prefixes.
(def (xml-name<? (a :- XMLName)
                 (b :- XMLName)) => :boolean
  (let ((a-local a.local)
        (b-local b.local))
    (if (string=? a-local b-local)
      (string<? a.uri b.uri)
      (string<? a-local b-local))))

(def (ncname? (str :- :string)) => :boolean
  (let (n (string-length str))
    (and (fx> n 0)
         (xml-name-start-code? (char->integer (string-ref str 0)))
         (let loop ((k 1))
           (or (fx>= k n)
               (and (xml-name-code? (char->integer (string-ref str k)))
                    (loop (fx+ k 1))))))))

;;; NCName, or two NCNames joined by a colon.
(def (qname? (str :- :string)) => :boolean
  (let (n (string-length str))
    (let loop ((k 0))
      (cond
       ((fx>= k n) (ncname? str))
       ((char=? (string-ref str k) #\:)
        (and (ncname? (substring str 0 k))
             (ncname? (substring str (fx+ k 1) n))))
       (else (loop (fx+ k 1)))))))

;;; XML production [13] PubidChar.
(def (pubid-code? (c :- :fixnum)) => :boolean
  (or (fx= c #x20) (fx= c #xd) (fx= c #xa)
      (and (fx>= c (ascii #\a)) (fx<= c (ascii #\z)))
      (and (fx>= c (ascii #\A)) (fx<= c (ascii #\Z)))
      (and (fx>= c (ascii #\0)) (fx<= c (ascii #\9)))
      (and (fx< c #x80)
           (memv (integer->char c)
                 '(#\- #\' #\( #\) #\+ #\, #\. #\/ #\: #\= #\? #\; #\! #\* #\# #\@ #\$ #\_ #\%))
           #t)))

(def (pubid-string? (str :- :string)) => :boolean
  (let (n (string-length str))
    (let loop ((k 0))
      (or (fx>= k n)
          (and (pubid-code? (char->integer (string-ref str k)))
               (loop (fx+ k 1)))))))

;;; What XML can represent, checked by the node constructors; write-xml
;;; (./emitter), which also writes trees built under HTML rules, checks
;;; comment data (xml-comment-data?) and namespace declarations
;;; (namespace-declaration-error) with them.

;;; Comment data: no -- and no final -.
(def (xml-comment-data? (data :- :string)) => :boolean
  (let (n (string-length data))
    (not (or (string-contains data "--")
             (and (fx> n 0) (char=? (string-ref data (fx- n 1)) #\-))))))

;;; What Namespaces in XML expects instead when a declaration binds prefix
;;; (#f for the default namespace) to the namespace uri, or #f when it
;;; allows the binding: a prefix bound to a non-empty namespace, the xml
;;; prefix only to its namespace and the xmlns prefix never, and no other
;;; prefix and not the default namespace bound to either reserved namespace.
(def (namespace-binding-error (prefix :? :string)
                              (uri    :- :string)) => (Maybe :string)
  (defrule (reserved?)
    (or (string-same? uri xml-namespace-uri) (string-same? uri xmlns-namespace-uri)))
  (def reserved "namespace other than the reserved ones")
  (cond
   ((not prefix)
    (and (reserved?) reserved))
   ((fx= (string-length uri) 0) "non-empty namespace for a prefix")
   ((string-same? prefix "xmlns") "a prefix other than xmlns")
   ((string-same? prefix "xml")
    (and (not (string-same? uri xml-namespace-uri)) "the XML namespace for the xml prefix"))
   ((reserved?) reserved)
   (else #f)))

;;; Why an attribute named local in namespace uri with prefix prefix and value
;;; value is a namespace declaration Namespaces in XML does not allow, or #f.
;;; A declaration is named xmlns or xmlns:prefix in xmlns-namespace-uri (an
;;; attribute named xmlns in no namespace would be read as one) and binds
;;; what namespace-binding-error allows.
(def (namespace-declaration-error (uri    :- :string)
                                  (local  :- :string)
                                  (prefix :- :string)
                                  (value  :- :string)) => (Maybe :string)
  (cond
   ((fx= (string-length uri) 0)
    (and (string-same? local "xmlns")
         "attribute named xmlns in xmlns-namespace-uri, not in no namespace"))
   ((not (string-same? uri xmlns-namespace-uri)) #f)
   ((fx= (string-length prefix) 0)
    (if (string-same? local "xmlns")
      (namespace-binding-error #f value)
      "declaration named xmlns or xmlns:prefix"))
   ((not (string-same? prefix "xmlns")) "declaration named xmlns or xmlns:prefix")
   (else (namespace-binding-error local value))))

;;; A SystemLiteral can be quoted with " or ', so it cannot hold both.
(def (system-literal-string? (str :- :string)) => :boolean
  (not (and (string-index str #\") (string-index str #\'))))
