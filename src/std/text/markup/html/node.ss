;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Typed HTML node structs, derived from XML, whose constructors check
;;; their arguments as those of ../xml/node do; unchecked-node allocates
;;; them without the checks. The HTML rules they follow are in ./rules.
;;; HTML trees reuse the XML node structs for elements, attributes, text,
;;; comments and processing instructions; HTML element and attribute names
;;; are XMLName values in no namespace (uri "", prefix "") whose local part
;;; follows the HTML syntax, not NCName. The parser names SVG and MathML
;;; elements in svg-namespace-uri or mathml-namespace-uri (prefix ""), and
;;; the xlink:, xml: and xmlns attributes of those elements in the XLink,
;;; XML or XMLNS namespace with that prefix ("" for xmlns itself).
(import :std/error
        ../xml/node
        (only-in ./rules
                 svg-namespace-uri
                 mathml-namespace-uri
                 xlink-namespace-uri
                 html-doctype-name-ok?
                 html-doctype-id-ok?))
;;; No slot setters: nodes are immutable (../xml/types).
(export svg-namespace-uri
        mathml-namespace-uri
        xlink-namespace-uri
        HTMLRaw
        HTMLRaw::t
        HTMLRaw?
        make-HTMLRaw
        HTMLRaw-data
        HTMLDoctype
        HTMLDoctype::t
        HTMLDoctype?
        make-HTMLDoctype
        HTMLDoctype-name
        HTMLDoctype-public-id
        HTMLDoctype-system-id
        HTMLDocument
        HTMLDocument::t
        HTMLDocument?
        make-HTMLDocument
        HTMLDocument-children
        html-document-doctype
        html-node?)

;;; Markup written as is: raw, unsanitized HTML, not checked.
(defstruct (HTMLRaw XML)
  ((data :- :string))
  constructor: :init!
  final: #t)

(defmethod {:init! HTMLRaw}
  (lambda (self (data : :string))
    (set! self.data data)))

;;; A DOCTYPE: name ("" when the DOCTYPE has none), and the public and
;;; system identifiers, each #f when absent. Unlike XMLDoctype, a public
;;; identifier needs no system identifier and the name is not a QName.
(defstruct (HTMLDoctype XML)
  ((name      :- :string)
   (public-id :? :string)
   (system-id :? :string))
  constructor: :init!
  final: #t)

;;; name: no whitespace, >, NUL or ASCII upper case (which the parser reads
;;; back in lower case), and not empty with identifiers; identifiers: no >,
;;; NUL, or both quote characters, so each can be written quoted.
(defmethod {:init! HTMLDoctype}
  (lambda (self
           (name      : :string)
           (public-id :? :string := #f)
           (system-id :? :string := #f))
    (unless (html-doctype-name-ok? name (and (or public-id system-id) #t))
      (raise-bad-argument HTMLDoctype
                          "lower case name without whitespace, > or NUL, not empty with identifiers"
                          name))
    (for-each
     (lambda (id)
       (when (and id (not (html-doctype-id-ok? id)))
         (raise-bad-argument HTMLDoctype "identifier without >, NUL or both quotes" id)))
     [public-id system-id])
    (set! self.name name)
    (set! self.public-id public-id)
    (set! self.system-id system-id)))

;;; A document: its top-level nodes in document order, among them at most
;;; one HTMLDoctype, before every element and text node.
(defstruct (HTMLDocument XML)
  ((children :- :list))
  constructor: :init!
  final: #t)

;;; children: list of html-node? values in document order and at most one
;;; HTMLDoctype, after only comments and processing instructions, where the
;;; parser reads a DOCTYPE.
(defmethod {:init! HTMLDocument}
  (lambda (self (children :~ (list-of? html-document-child?) :- :list))
    (let loop ((rest children) (doctype-place? #t))
      (when (pair? rest)
        (let (child (car rest))
          (if (HTMLDoctype? child)
            (begin
              (unless doctype-place?
                (raise-bad-argument HTMLDocument "one DOCTYPE, before elements and text" child))
              (loop (cdr rest) #f))
            (loop (cdr rest) (and doctype-place? (or (XMLComment? child) (XMLPI? child))))))))
    (set! self.children children)))

;;; The DOCTYPE of doc, or #f.
(def (html-document-doctype (doc : HTMLDocument)) => (Maybe HTMLDoctype)
  (find HTMLDoctype? doc.children))

;;; Child of an element or document: element, text, comment, processing
;;; instruction or raw markup.
(def (html-node? (x : :t)) => :boolean
  (or (XMLElement? x) (XMLText? x) (XMLComment? x) (XMLPI? x) (HTMLRaw? x)))

;;; Child of a document: an HTML node or a DOCTYPE.
(def (html-document-child? (x : :t)) => :boolean
  (or (HTMLDoctype? x) (html-node? x)))
