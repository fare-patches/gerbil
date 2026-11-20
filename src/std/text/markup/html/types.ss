;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Typed HTML nodes: the HTML node types and checked constructors. HTML
;;; trees are built from the XML node types of :std/text/markup/xml/types
;;; plus HTMLRaw, HTMLDoctype and HTMLDocument, all derived from XML;
;;; element and attribute names are XMLName values in no namespace, except
;;; that the parser names SVG and MathML elements in svg-namespace-uri and
;;; mathml-namespace-uri, and their xlink:, xml: and xmlns attributes in the
;;; XLink, XML and XMLNS namespaces.
;;;
;;; Nodes are immutable values, as :std/text/markup/xml/types describes.
;;; Applying HTMLRaw, HTMLDoctype or HTMLDocument checks the arguments, as
;;; applying the XML node types does (./node); make-html-raw,
;;; make-html-doctype and make-html-document are their constructors.
(import :std/error
        ../xml/node
        ./node
        ./rules)
(export HTMLRaw
        HTMLRaw?
        make-html-raw
        HTMLRaw-data
        HTMLDoctype
        HTMLDoctype?
        make-html-doctype
        HTMLDoctype-name
        HTMLDoctype-public-id
        HTMLDoctype-system-id
        HTMLDocument
        HTMLDocument?
        make-html-document
        html-document-doctype
        HTMLDocument-children
        html-node?
        make-html-element
        make-html-attribute
        make-html-foreign-attribute
        html-tag-name?
        html-attribute-name?
        svg-namespace-uri
        mathml-namespace-uri
        xlink-namespace-uri)

;;; The factories of HTMLRaw, HTMLDoctype and HTMLDocument are their
;;; constructors, as the make-xml- factories are (../xml/types). Raw markup
;;; is not checked: the writer copies data as is.
(defalias make-html-raw make-HTMLRaw)
(defalias make-html-doctype make-HTMLDoctype)
(defalias make-html-document make-HTMLDocument)

;;; Elements and attributes follow the HTML rules, not those of the XML
;;; constructors: the factories below check them and allocate unchecked.

;;; An element in namespace "" (HTML), svg-namespace-uri or
;;; mathml-namespace-uri, named name, with a list of XMLAttribute and a list
;;; of html-node? children, all as the parser reads them back on this
;;; element. Raises ContractViolation otherwise; html.md gives the rules.
(def (make-html-element (name                 : :string)
                        (attributes           :~ (list-of? XMLAttribute?) :- :list)
                        (children             :~ (list-of? html-node?)    :- :list)
                        namespace: (namespace : :string := "")) => XMLElement
  (when (fx< (namespace-code namespace) 0)
    (raise-bad-argument make-html-element "namespace \"\", SVG or MathML" namespace))
  (unless (and (html-tag-name? name) (element-local-round-trips? namespace name))
    (raise-bad-argument make-html-element "tag name the parser reads back" name))
  (when (and (string-empty? namespace) (member name ["svg" "math"]))
    (raise-bad-argument make-html-element
                        "svg in svg-namespace-uri, math in mathml-namespace-uri" name))
  (let loop ((rest attributes) (written '()))
    (if (pair? rest)
      (using (attr (car rest) :- XMLAttribute)
        (let* ((local attr.name.local)
               (qname
                (or (and (html-attribute-name? local)
                         (written-attribute-name namespace attr.name.uri local attr.name.prefix
                                                 (not (ascii-upper-in? local))))
                    (raise-bad-argument make-html-element
                                        "attribute name the parser reads back on this element"
                                        attr.name))))
          (loop (cdr rest) (cons qname written))))
      (let (duplicate (find-duplicate written string<? string=?))
        (when duplicate
          (raise-bad-argument make-html-element "distinct attribute names" duplicate)))))
  (unchecked-node XMLElement (unchecked-node XMLName name namespace "") attributes children))

;;; An attribute in no namespace; name follows the HTML syntax
;;; (html-attribute-name?), so 123, :x and a:b are names. The parser reads
;;; names back in ASCII lower case, so name has no ASCII upper case, except
;;; in the SVG and MathML spellings the parser adjusts names to (viewBox,
;;; definitionURL), valid on those elements only.
(def (make-html-attribute (name  : :string)
                          (value : :string)) => XMLAttribute
  ;; on some element: no ASCII upper case, or an adjusted SVG or MathML
  ;; spelling
  (unless (and (html-attribute-name? name)
               (or (not (ascii-upper-in? name))
                   (foreign-attribute-local-round-trips? svg-namespace-uri name)
                   (foreign-attribute-local-round-trips? mathml-namespace-uri name)))
    (raise-bad-argument make-html-attribute "HTML attribute name the parser reads back" name))
  (unchecked-node XMLAttribute (unchecked-node XMLName name "" "") value))

;;; A namespaced attribute of an SVG or MathML element, by the name it is
;;; written with: xlink:actuate, xlink:arcrole, xlink:href, xlink:role,
;;; xlink:show, xlink:title, xlink:type (XLink namespace), xml:lang,
;;; xml:space (XML namespace), xmlns and xmlns:xlink (XMLNS namespace), as
;;; the parser names them.
(def (make-html-foreign-attribute (qname : :string)
                                  (value : :string)) => XMLAttribute
  (let (name (hash-get foreign-attribute-names qname))
    (unless name
      (raise-bad-argument make-html-foreign-attribute "xlink:, xml: or xmlns attribute name" qname))
    (unchecked-node XMLAttribute name value)))
