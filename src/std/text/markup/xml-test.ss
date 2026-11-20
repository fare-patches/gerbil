;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/text/markup/xml: the facade gives the types, the reader and the
;;; writer; the modules have their own tests in xml/.
(import :std/test
        :std/error
        :std/text/markup/xml)
(export xml-test)

(def xml-test
  (test-suite "test :std/text/markup/xml"
    (test-case "read, inspect and write a document"
      (using (doc (read-xml "<?xml version='1.0'?><r a=\"1\"><c>t &amp; u</c></r>") :- XMLDocument)
        (using ((root doc.root :- XMLElement)
                (child (car root.children) : XMLElement)
                (text (car child.children) : XMLText))
          (check root.name.local => "r")
          (check (xml-element-attribute-value root "a") => "1")
          (check text.data => "t & u")
          (check (map (lambda ((attr : XMLAttribute)) attr.name.local) root.attributes) => ["a"])
          (check (xml->string doc) => "<r a=\"1\"><c>t &amp; u</c></r>")
          (check (xml->u8vector root) => (string->utf8 "<r a=\"1\"><c>t &amp; u</c></r>"))
          (check (call-with-output-string "" (cut write-xml child <>)) => "<c>t &amp; u</c>"))))

    (test-case "nested dotted access, nullable slots included"
      (using (doc (read-xml "<!DOCTYPE p:r SYSTEM 'r.dtd'><p:r xmlns:p='urn:x'><c/></p:r>")
                  :- XMLDocument)
        (check doc.root.name.local => "r")
        (check doc.root.name.uri => "urn:x")
        (check doc.root.name.prefix => "p")
        (check doc.doctype.name => "p:r")
        (check doc.doctype.system-id => "r.dtd")
        (check doc.doctype.public-id => #f))
      (using (doc (read-xml "<r/>") :- XMLDocument)
        (using (doctype doc.doctype :? XMLDoctype)
          (check (and doctype doctype.name) => #f))))

    (test-case "the generated accessors read the slots dotted access reads"
      (using (doc (read-xml "<!DOCTYPE r SYSTEM 'r.dtd'><p:r xmlns:p='urn:x' a='1'>t<?q d?></p:r>")
                  :- XMLDocument)
        (let* ((root (XMLDocument-root doc))
               (name (XMLElement-name root))
               (attrs (XMLElement-attributes root))
               (kids (XMLElement-children root)))
          (check (eq? root doc.root) => #t)
          (check [(XMLName-local name) (XMLName-uri name) (XMLName-prefix name)] => ["r" "urn:x" "p"])
          (check (map (lambda (attr) (XMLName-local (XMLAttribute-name attr))) attrs) => ["p" "a"])
          (check (XMLAttribute-value (cadr attrs)) => "1")
          (check (XMLText-data (car kids)) => "t")
          (check [(XMLPI-target (cadr kids)) (XMLPI-data (cadr kids))] => ["q" "d"])
          (check (XMLDoctype-system-id (XMLDocument-doctype doc)) => "r.dtd"))))

    (test-case "the node types share the XML root and stay distinct"
      (let* ((name (make-xml-name "e"))
             (attr (make-xml-attribute name "v"))
             (el (make-xml-element name [attr] []))
             (nodes [name attr el (make-xml-text "t") (make-xml-cdata "c") (make-xml-comment "m")
                     (make-xml-pi "p" "d") (make-xml-doctype "e") (make-xml-document [] el [])])
             (predicates [XMLName? XMLAttribute? XMLElement? XMLText? XMLCData? XMLComment?
                          XMLPI? XMLDoctype? XMLDocument?]))
        (check (andmap XML? nodes) => #t)
        (check (XML? "e") => #f)
        (check (map (lambda (pred node) (pred node)) predicates nodes)
               => (make-list (length nodes) #t))
        (check (map (lambda (node) (length (filter (lambda (pred) (pred node)) predicates))) nodes)
               => (make-list (length nodes) 1))
        (check (map xml-node? nodes) => [#f #f #t #t #t #t #t #f #f])))

    (test-case "names, attributes, doctypes and documents are not children"
      (let* ((name (make-xml-name "e"))
             (attr (make-xml-attribute name "v"))
             (el (make-xml-element name [] []))
             (doctype (make-xml-doctype "e"))
             (doc (make-xml-document [] el [])))
        (for-each
         (lambda (x)
           (check-exception (make-xml-element name [] [x]) contract-violation-error?)
           (check-exception (make-xml-document [x] el []) contract-violation-error?)
           (check-exception (make-xml-document [] el [x]) contract-violation-error?))
         [name attr doctype doc])
        (check-exception (make-xml-element name [name] []) contract-violation-error?)
        (for-each (lambda (x) (check-exception (xml->string x) contract-violation-error?))
                  [name attr doctype])))

    (test-case "constructors check, the reader raises XMLParseError"
      (let (el (make-xml-element (make-xml-name "e" "urn:x" "p")
                                 [(make-xml-attribute (make-xml-name "k") "<&\"")]
                                 [(make-xml-text "a") (make-xml-cdata "b") (make-xml-comment "c")
                                  (make-xml-pi "t" "d")]))
        (check (xml->string el)
               => "<p:e xmlns:p=\"urn:x\" k=\"&lt;&amp;&quot;\">a<![CDATA[b]]><!--c--><?t d?></p:e>"))
      (check-exception (make-xml-comment "a--b") contract-violation-error?)
      (check-exception (read-xml "<r>") xml-parse-error?))))
