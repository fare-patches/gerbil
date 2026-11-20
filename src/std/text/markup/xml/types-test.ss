;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/text/markup/xml/types)
(export types-test)

(def xmlns xmlns-namespace-uri)

(def (attribute local value (uri "") (prefix ""))
  (make-xml-attribute (make-xml-name local uri prefix) value))

(def (rejects? thunk)
  (with-catch contract-violation-error? (lambda () (thunk) #f)))

(def (name-parts (n : XMLName))
  [n.local n.uri n.prefix])

(def (attribute-parts (a : XMLAttribute))
  [(name-parts a.name) a.value])

(def types-test
  (test-suite "test :std/text/markup/xml/types"
    (test-case "names"
      (let (n (make-xml-name "item" "urn:a" "p"))
        (check (name-parts n) => ["item" "urn:a" "p"])
        (check (xml-name=? n (make-xml-name "item" "urn:a")) => #t)
        (check (xml-name=? n (make-xml-name "item" "urn:b" "p")) => #f)
        (check (equal? n (make-xml-name "item" "urn:a")) => #f))
      (check (name-parts (make-xml-name "r")) => ["r" "" ""])
      (check (name-parts (make-xml-name "\xe9;l\xe9;ment")) => ["\xe9;l\xe9;ment" "" ""])
      (check (name-parts (make-xml-name "lang" xml-namespace-uri "xml")) => ["lang" xml-namespace-uri "xml"])
      ;; the reserved namespaces default their only possible prefix
      (check (name-parts (make-xml-name "lang" xml-namespace-uri)) => ["lang" xml-namespace-uri "xml"])
      (check (name-parts (make-xml-name "p" xmlns)) => ["p" xmlns "xmlns"])
      (check (name-parts (make-xml-name "xmlns" xmlns)) => ["xmlns" xmlns ""])
      (for-each
       (lambda (args)
         (check (cons args (rejects? (lambda () (apply make-xml-name args)))) => (cons args #t)))
       [[""] ["a:b"] ["1a"] ["a b"] ["\xd7;"] ["a" "" "p"] ["a" "urn:a" "1p"]
        ["a" "urn:a" "xml"] ["a" "urn:a" "xmlns"]
        ;; the XML namespace takes exactly the prefix xml
        ["r" xml-namespace-uri "p"]
        ;; the xmlns namespace only names declarations, and xmlns is not declarable
        ["foo" xmlns "p"] ["xmlns" xmlns "xmlns"]]))

    (test-case "namespace declarations"
      (check (attribute-parts (attribute "p" "urn:p" xmlns "xmlns")) => [["p" xmlns "xmlns"] "urn:p"])
      (check (attribute-parts (attribute "xml" xml-namespace-uri xmlns "xmlns"))
             => [["xml" xmlns "xmlns"] xml-namespace-uri])
      (check (attribute-parts (attribute "xmlns" "" xmlns)) => [["xmlns" xmlns ""] ""])
      (for-each
       (lambda (args)
         (check (cons args (rejects? (lambda () (apply attribute args)))) => (cons args #t)))
       [;; a no-namespace attribute spelled xmlns would declare a default namespace
        ["xmlns" "urn:x"]
        ;; a prefix cannot be undeclared, or bound to a reserved namespace
        ["p" "" xmlns "xmlns"] ["p" xml-namespace-uri xmlns "xmlns"] ["p" xmlns xmlns "xmlns"]
        ["xml" "urn:x" xmlns "xmlns"]
        ["xmlns" xml-namespace-uri xmlns] ["xmlns" xmlns xmlns]]))

    (test-case "elements check their members"
      (let* ((a (attribute "a" "1"))
             (r (make-xml-name "r")))
        (using ((el (make-xml-element r [a] [(make-xml-text "t")]) : XMLElement)
                (t (car el.children) : XMLText))
          (check el.attributes => [a])
          (check t.data => "t"))
        (for-each
         (lambda (thunk) (check (rejects? thunk) => #t))
         [(lambda () (make-xml-element r [a a] []))
          (lambda () (make-xml-element r [a (attribute "a" "2")] []))
          (lambda () (make-xml-element r ["a"] []))
          (lambda () (make-xml-element r [a "x"] []))
          (lambda () (make-xml-element r [] ["text"]))
          (lambda () (make-xml-element "r" [] []))
          ;; element names are never in the xmlns namespace
          (lambda () (make-xml-element (make-xml-name "x" xmlns "xmlns") [] []))
          (lambda () (make-xml-element (make-xml-name "xmlns" xmlns) [] []))
          ;; own declarations must agree with the element name
          (lambda () (make-xml-element (make-xml-name "r" "urn:a") [(attribute "xmlns" "" xmlns)] []))
          (lambda () (make-xml-element (make-xml-name "r" "urn:a" "p")
                                       [(attribute "p" "urn:b" xmlns "xmlns")] []))])
        (check (XMLElement? (make-xml-element (make-xml-name "r" "urn:a" "p")
                                               [(attribute "p" "urn:a" xmlns "xmlns")] []))
               => #t)))

    (test-case "elements with many attributes: duplicates past 16"
      (def (attrs n) (map (lambda (k) (attribute (string-append "a" (number->string k)) "v")) (iota n)))
      (let (r (make-xml-name "r"))
        (check (rejects? (lambda () (make-xml-element r (append (attrs 20) [(attribute "a5" "w")]) [])))
               => #t)
        ;; the same expanded name with different prefixes
        (check (rejects? (lambda ()
                           (make-xml-element r (append (attrs 20) [(attribute "a" "1" "urn:p" "p")
                                                                   (attribute "a" "2" "urn:p" "q")])
                                             [])))
               => #t)
        (using (el (make-xml-element r (append (attrs 20) [(attribute "a" "1") (attribute "a" "2" "urn:p" "p")])
                                     [])
                   : XMLElement)
          (check (length el.attributes) => 22))
        (using (el (make-xml-element r (attrs 16000) []) : XMLElement)
          (check (length el.attributes) => 16000))))

    (test-case "attribute lookup by local name and namespace"
      (let (el (make-xml-element (make-xml-name "r")
                                 [(attribute "a" "1")
                                  (attribute "a" "2" "urn:x" "p")
                                  (attribute "p" "urn:x" xmlns "xmlns")]
                                 []))
        (check (xml-element-attribute-value el "a") => "1")
        (check (xml-element-attribute-value el "a" "urn:x") => "2")
        (check (xml-element-attribute-value el "p" xmlns) => "urn:x")
        (check (xml-element-attribute-value el "b") => #f)
        (check (xml-element-attribute-value el "p") => #f)))

    (test-case "character data constructors reject content their syntax cannot hold"
      (using (cdata (make-xml-cdata "a]]b") : XMLCData)
        (check cdata.data => "a]]b"))
      (check-exception (make-xml-cdata "a]]>b") contract-violation-error?)
      (check-exception (make-xml-comment "a--b") contract-violation-error?)
      (check-exception (make-xml-comment "a-") contract-violation-error?)
      (check-exception (make-xml-pi "xml" "") contract-violation-error?)
      (check-exception (make-xml-pi "p" "a?>b") contract-violation-error?)
      (check-exception (make-xml-pi "p" "  x") contract-violation-error?)
      (using (pi (make-xml-pi "p" "x") : XMLPI)
        (check [pi.target pi.data] => ["p" "x"])))

    (test-case "documents"
      (def (doctype-parts (dt : XMLDoctype))
        [dt.name dt.public-id dt.system-id])
      (let (root (make-xml-element (make-xml-name "r") [] []))
        (using (doc (make-xml-document [(make-xml-comment "c")] root []) : XMLDocument)
          (check doc.root => root)
          (check doc.doctype => #f))
        (let (dt (make-xml-doctype "html"))
          (using (doc (make-xml-document [] root [] dt) : XMLDocument)
            (check doc.doctype => dt)))
        (check (doctype-parts (make-xml-doctype "r" "-//X//EN" "r.dtd")) => ["r" "-//X//EN" "r.dtd"])
        (check (doctype-parts (make-xml-doctype "p:r" #f "a\"b")) => ["p:r" #f "a\"b"])
        (for-each
         (lambda (args)
           (check (cons args (rejects? (lambda () (apply make-xml-doctype args)))) => (cons args #t)))
         [["1r"] ["a b"] ["r" "-//X//EN"] ["r" "a\"b" "r.dtd"] ["r" #f "a\"b'"]])
        (check-exception (make-xml-document [(make-xml-text "t")] root []) contract-violation-error?)))

    (test-case "applying a node type checks its arguments as its factory does"
      (check-exception (XMLCData "]]>") contract-violation-error?)
      (check-exception (XMLName "1a") contract-violation-error?)
      (check-exception (XMLName "a" "" "p") contract-violation-error?)
      (check-exception (XMLAttribute (XMLName "xmlns") "urn:a") contract-violation-error?)
      (check-exception (XMLElement (XMLName "r") ["x"] []) contract-violation-error?)
      (check-exception (XMLElement (XMLName "r") [] ["x"]) contract-violation-error?)
      ;; the lists must be proper
      (check-exception (XMLElement (XMLName "r") [] (cons (XMLText "t") (XMLText "u")))
                       contract-violation-error?)
      (check-exception (XMLDocument (cons (XMLComment "c") #f) (XMLElement (XMLName "r") [] []) [])
                       contract-violation-error?)
      (check-exception (XMLText 42) contract-violation-error?)
      (check-exception (XMLComment "a--b") contract-violation-error?)
      (check-exception (XMLPI "xml" "") contract-violation-error?)
      (check-exception (XMLDoctype "r" "-//X//EN") contract-violation-error?)
      (check-exception (XMLDocument [(XMLText "t")] (XMLElement (XMLName "r") [] []) [])
                       contract-violation-error?)
      (check (name-parts (XMLName "lang" xml-namespace-uri)) => ["lang" xml-namespace-uri "xml"])
      (using ((el (XMLElement (XMLName "r") [(attribute "a" "1")] [(XMLCData "x")]) : XMLElement)
              (doc (XMLDocument [] el [] (XMLDoctype "r")) : XMLDocument))
        (check (equal? el (make-xml-element (make-xml-name "r") [(attribute "a" "1")]
                                            [(make-xml-cdata "x")]))
               => #t)
        (check doc.root => el)))))
