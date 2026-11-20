;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/text/markup/html: the facade gives the HTML types, the reader and
;;; the writer; trees are read with the XML node types' dotted access.
;;; The modules have their own tests in html/.
(import :std/test
        :std/error
        :std/text/markup/xml
        :std/text/markup/html)
(export html-test)

(def html-test
  (test-suite "test :std/text/markup/html"
    (test-case "read, inspect and write a document"
      (using (doc (read-html "<!DOCTYPE html><title>T</title><p class=x>a &amp; b<br>") :- HTMLDocument)
        (using ((html (cadr doc.children) : XMLElement)
                (body (cadr html.children) : XMLElement)
                (p (car body.children) : XMLElement)
                (doctype (html-document-doctype doc) :? HTMLDoctype))
          (check (and doctype doctype.name) => "html")
          (check (and doctype doctype.public-id) => #f)
          (check p.name.local => "p")
          (check p.name.uri => "")
          (check (xml-element-attribute-value p "class") => "x")
          (check (html->string doc)
                 => "<!DOCTYPE html><html><head><title>T</title></head><body><p class=\"x\">a &amp; b<br></p></body></html>")
          (check (html->u8vector p) => (string->utf8 "<p class=\"x\">a &amp; b<br></p>"))
          (check (call-with-output-string "" (cut write-html p <>)) => "<p class=\"x\">a &amp; b<br></p>")))
      (using (doctype (html-document-doctype (read-html "<p>x")) :? HTMLDoctype)
        (check (and doctype doctype.name) => #f)))

    (test-case "the HTML node types share the XML root and stay distinct"
      (let ((raw (make-html-raw "<b>"))
            (doctype (make-html-doctype "html"))
            (doc (make-html-document [])))
        (check (andmap XML? [raw doctype doc]) => #t)
        (check (map HTMLRaw? [raw doctype doc]) => [#t #f #f])
        (check (map HTMLDoctype? [raw doctype doc]) => [#f #t #f])
        (check (map HTMLDocument? [raw doctype doc]) => [#f #f #t])
        (check (XMLDoctype? doctype) => #f)
        (check (map html-node? [raw doctype doc]) => [#t #f #f])))

    (test-case "names, attributes, doctypes and documents are not HTML children"
      (let* ((name (make-xml-name "p"))
             (attr (make-html-attribute "class" "x"))
             (xml-doctype (make-xml-doctype "html"))
             (doctype (make-html-doctype "html"))
             (doc (make-html-document [])))
        (for-each
         (lambda (x)
           (check-exception (make-html-element "p" [] [x]) contract-violation-error?)
           (check-exception (html->string [x]) contract-violation-error?))
         [name attr xml-doctype doctype doc])
        ;; a fragment is a proper list
        (check-exception (html->string (cons (make-xml-text "t") (make-xml-text "u")))
                         contract-violation-error?)
        (for-each
         (lambda (x) (check-exception (make-html-document [x]) contract-violation-error?))
         [name attr xml-doctype doc])))

    (test-case "fragments, constructors and html-escape"
      (check (html->string (read-html-fragment "<td>1<td>2" context: "tr")) => "<td>1</td><td>2</td>")
      (check (html->string [(make-html-element "svg" [(make-html-attribute "viewBox" "0 0 1 1")]
                                               [(make-html-raw "<g/>")]
                                               namespace: svg-namespace-uri)
                            (make-xml-text "<&")])
             => "<svg viewBox=\"0 0 1 1\"><g/></svg>&lt;&amp;")
      (check (html-escape "<a href='x'>&\"") => "&lt;a href=&#39;x&#39;&gt;&amp;&quot;")
      (check-exception (make-html-element "svg" [] []) contract-violation-error?)
      (check-exception (html->string (make-html-element "script" [] [(make-xml-text "</script>")]))
                       contract-violation-error?)
      (check-exception (read-html (u8vector #xff)) html-parse-error?))))
