;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/text/markup/xml/types
        :std/text/markup/html/types)
(export types-test)

(def types-test
  (test-suite "test :std/text/markup/html/types"
    (test-case "elements: HTML tag names in no namespace"
      (using (el (make-html-element "svg-x:y" [(make-html-attribute "class" "a")]
                                    [(make-xml-text "t") (make-html-raw "<b>")])
                 : XMLElement)
        (check el.name.local => "svg-x:y")
        (check el.name.uri => "")
        (check el.name.prefix => "")
        (check (xml-element-attribute-value el "class") => "a")
        (using (raw (cadr el.children) : HTMLRaw)
          (check raw.data => "<b>")))
      (for-each (lambda (name)
                  (check-exception (make-html-element name [] []) contract-violation-error?))
                ["" "1p" ":p" "_p" "a b" "a/b" "a>b" (string #\a #\nul) "P" "dIv" "image"])
      (using (el (make-html-element "image" [] [] namespace: svg-namespace-uri) : XMLElement)
        (check el.name.local => "image")))

    (test-case "SVG and MathML elements and their attributes"
      (using (el (make-html-element "foreignObject"
                                    [(make-html-attribute "viewBox" "0 0 1 1")
                                     (make-html-foreign-attribute "xlink:href" "#a")
                                     (make-html-foreign-attribute "xmlns" "x")]
                                    [] namespace: svg-namespace-uri)
                 :- XMLElement)
        (check el.name.uri => svg-namespace-uri)
        (check (map (lambda ((attr : XMLAttribute))
                      [attr.name.local attr.name.uri attr.name.prefix])
                    el.attributes)
               => [["viewBox" "" ""] ["href" xlink-namespace-uri "xlink"]
                   ["xmlns" xmlns-namespace-uri ""]]))
      (using (el (make-html-element "mi" [(make-html-attribute "definitionURL" "u")] []
                                    namespace: mathml-namespace-uri)
                 :- XMLElement)
        (check el.name.local => "mi"))
      ;; names the parser would read back differently
      (for-each (lambda (args)
                  (check-exception (apply make-html-element args) contract-violation-error?))
                [["foreignobject" [] [] namespace: svg-namespace-uri]
                 ["Circle" [] [] namespace: svg-namespace-uri]
                 ["mI" [] [] namespace: mathml-namespace-uri]
                 ["p" [] [] namespace: "urn:x"]
                 ["svg" [] []]
                 ["math" [] []]
                 ["svg" [(make-html-attribute "viewbox" "")] [] namespace: svg-namespace-uri]
                 ["svg" [(make-html-attribute "xlink:href" "")] [] namespace: svg-namespace-uri]
                 ["math" [(make-html-attribute "definitionurl" "")] [] namespace: mathml-namespace-uri]
                 ["p" [(make-html-foreign-attribute "xlink:href" "")] []]])
      (check-exception (make-html-foreign-attribute "xlink:foo" "") contract-violation-error?))

    (test-case "elements with many attributes: duplicates past 16"
      (def (attrs n) (map (lambda (k) (make-html-attribute (string-append "a" (number->string k)) "v")) (iota n)))
      (check-exception (make-html-element "p" (append (attrs 20) [(make-html-attribute "a5" "w")]) [])
                       contract-violation-error?)
      (using (el (make-html-element "p" (attrs 16000) []) : XMLElement)
        (check (length el.attributes) => 16000)))

    (test-case "name predicates check their argument"
      (for-each (lambda (x)
                  (check-exception (html-tag-name? x) contract-violation-error?)
                  (check-exception (html-attribute-name? x) contract-violation-error?))
                [5 'p (make-u8vector 3 65)]))

    (test-case "attributes: HTML attribute names, distinct"
      (for-each (lambda (name)
                  (using (attr (make-html-attribute name "v") : XMLAttribute)
                    (check [attr.name.local attr.value] => [name "v"])))
                ["123" ":x" "a:b" "data-x" "<" "\xe9;" "viewBox" "definitionURL"])
      (for-each (lambda (name)
                  (check-exception (make-html-attribute name "v") contract-violation-error?))
                ["" "a b" "a=b" "\"" "'" "a>" "a/" (string #\a #\x7f) (string #\xfdd0)])
      (check-exception (make-html-element "p" [(make-html-attribute "a" "1")
                                               (make-html-attribute "a" "2")]
                                          [])
                       contract-violation-error?)
      ;; the parser reads attribute names in lower case
      (check-exception (make-html-element "p" [(make-html-attribute "a" "1")
                                               (make-html-attribute "A" "2")]
                                          [])
                       contract-violation-error?)
      ;; ASCII upper case only in the SVG and MathML spellings the parser
      ;; adjusts names to, on those elements
      (for-each (lambda (name)
                  (check-exception (make-html-attribute name "v") contract-violation-error?))
                ["Foo" "onClick" "viewbOx" "DefinitionURL"])
      (for-each (lambda (args)
                  (check-exception (apply make-html-element args) contract-violation-error?))
                [["span" [(make-xml-attribute (make-xml-name "onClick" "" "") "x")] []]
                 ["span" [(make-html-attribute "viewBox" "x")] []]
                 ["svg" [(make-html-attribute "definitionURL" "x")] [] namespace: svg-namespace-uri]])
      (check-exception (make-html-element "p" [(make-xml-attribute (make-xml-name "a" "urn:x" "x") "1")]
                                          [])
                       contract-violation-error?)
      (check-exception (make-html-element "p" ['a] []) contract-violation-error?))

    (test-case "children: elements, text, comments, processing instructions, raw markup"
      (check-exception (make-html-element "p" [] [(make-xml-cdata "x")]) contract-violation-error?)
      (check-exception (make-html-element "p" [] ["x"]) contract-violation-error?)
      ;; a proper list
      (check-exception (make-html-element "p" [] (cons (make-xml-text "t") (make-xml-text "u")))
                       contract-violation-error?)
      (check (html-node? (make-xml-pi "php" "x")) => #t)
      (check (html-node? (make-xml-comment "c")) => #t))

    (test-case "documents hold any number of top-level nodes"
      (using ((doc (make-html-document [(make-xml-comment "c") (make-html-doctype "html")
                                        (make-html-element "p" [] []) (make-xml-text "t")])
                   : HTMLDocument)
              (doctype (html-document-doctype doc) : HTMLDoctype))
        (check (length doc.children) => 4)
        (check doctype.name => "html"))
      (check (html-document-doctype (make-html-document [])) => #f)
      (check-exception (make-html-document [(make-xml-cdata "x")]) contract-violation-error?)
      ;; one DOCTYPE, after only comments and processing instructions
      (check-exception (make-html-document [(make-html-doctype "html")
                                            (make-html-doctype "html")])
                       contract-violation-error?)
      (check-exception (make-html-document [(make-xml-text "t")
                                            (make-html-doctype "html")])
                       contract-violation-error?)
      (check-exception (make-html-document [(make-html-raw "<!-- x -->")
                                            (make-html-doctype "html")])
                       contract-violation-error?))

    (test-case "DOCTYPE: public identifier without system identifier"
      (def (doctype-parts (doctype : HTMLDoctype))
        [doctype.name doctype.public-id doctype.system-id])
      (check (doctype-parts (make-html-doctype "html" "-//W3C//DTD HTML 4.01//EN"))
             => ["html" "-//W3C//DTD HTML 4.01//EN" #f])
      (check (doctype-parts (make-html-doctype "")) => ["" #f #f])
      (check (doctype-parts (make-html-doctype "html" #f "a'b")) => ["html" #f "a'b"])
      (for-each (lambda (args)
                  (check-exception (apply make-html-doctype args) contract-violation-error?))
                [["a b"] ["a>"] ["html" "a>"] ["html" #f "a\"b'"] ["html" (string #\nul)]
                 ["HTML"] ["" "x"] ["" #f "y"]]))

    (test-case "applying an HTML node type checks its arguments as its factory does"
      (check-exception (HTMLDoctype "HTML") contract-violation-error?)
      (check-exception (HTMLDocument [(make-xml-text "t") (HTMLDoctype "html")])
                       contract-violation-error?)
      (check-exception (HTMLRaw 42) contract-violation-error?)
      (using (doc (HTMLDocument [(HTMLDoctype "html") (HTMLRaw "<p>")]) : HTMLDocument)
        (check (length doc.children) => 2)))))
