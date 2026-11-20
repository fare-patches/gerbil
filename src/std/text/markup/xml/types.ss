;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Typed XML nodes: types, accessors and factories.
;;;
;;; Nodes are immutable values. After a node is constructed, neither its
;;; slots, nor the lists it holds (attributes, children, prolog, epilog,
;;; document children), nor the strings reachable from it may be modified,
;;; by any thread, including Writer sinks running during a write; nodes may
;;; be shared. Modifying a node, its lists or its strings is an error with
;;; undefined behaviour. Strings passed to TAL output follow the same rule
;;; for the duration of the call.
;;;
;;; Applying a node type, as in (XMLName local uri prefix), constructs a
;;; node and checks its arguments (./node, with the conditions); each
;;; make-xml- factory is the type's constructor and constructs the same
;;; way. The readers and writers rely on the slot types only: trees built
;;; under the HTML rules (../html/types) share the structs without the XML
;;; conditions, so write-xml checks names, comments and namespace
;;; declarations as it writes them.
(import ./node)
(export XML
        XML?
        XMLName
        XMLName?
        make-xml-name
        XMLName-local
        XMLName-uri
        XMLName-prefix
        xml-name=?
        XMLAttribute
        XMLAttribute?
        make-xml-attribute
        XMLAttribute-name
        XMLAttribute-value
        XMLElement
        XMLElement?
        make-xml-element
        XMLElement-name
        XMLElement-attributes
        XMLElement-children
        xml-element-attribute-value
        XMLText
        XMLText?
        make-xml-text
        XMLText-data
        XMLCData
        XMLCData?
        make-xml-cdata
        XMLCData-data
        XMLComment
        XMLComment?
        make-xml-comment
        XMLComment-data
        XMLPI
        XMLPI?
        make-xml-pi
        XMLPI-target
        XMLPI-data
        XMLDoctype
        XMLDoctype?
        make-xml-doctype
        XMLDoctype-name
        XMLDoctype-public-id
        XMLDoctype-system-id
        XMLDocument
        XMLDocument?
        make-xml-document
        XMLDocument-prolog
        XMLDocument-root
        XMLDocument-epilog
        XMLDocument-doctype
        xml-node?
        xml-namespace-uri
        xmlns-namespace-uri)

;;; The factories: each is its type's constructor (make-XMLName for
;;; XMLName), which constructs as applying the type does, through the
;;; type's :init!, the one place of its checks and defaults.
;;; equal? on names also compares prefixes; xml-name=? does not.
(defalias make-xml-name make-XMLName)
(defalias make-xml-attribute make-XMLAttribute)
(defalias make-xml-element make-XMLElement)
(defalias make-xml-text make-XMLText)
(defalias make-xml-cdata make-XMLCData)
(defalias make-xml-comment make-XMLComment)
(defalias make-xml-pi make-XMLPI)
(defalias make-xml-doctype make-XMLDoctype)
(defalias make-xml-document make-XMLDocument)

;;; The value of the attribute of el named local in namespace uri, or #f.
;;; Declarations are named in xmlns-namespace-uri.
(def (xml-element-attribute-value (el    : XMLElement)
                                  (local : :string)
                                  (uri   : :string := "")) => (Maybe :string)
  (let loop ((rest el.attributes))
    (and (pair? rest)
         (using (attr (car rest) :- XMLAttribute)
           (if (and (string-same? attr.name.local local) (string-same? attr.name.uri uri))
             attr.value
             (loop (cdr rest)))))))
