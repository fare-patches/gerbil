;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        (only-in :std/io open-buffered-reader)
        :std/text/markup/xml/types
        :std/text/markup/html/types
        :std/text/markup/html/reader)
(export reader-test)

;;; A node as an s-expression: (name attribute ... child ...) with
;;; attributes as (@ name value) and namespaced names as "prefix:local" for
;;; SVG (svg), MathML (math) and attribute namespaces (their prefix).
(def (shape node)
  (def (name-string (name : XMLName))
    (let ((uri name.uri)
          (local name.local)
          (prefix name.prefix))
      (cond
       ((string=? uri "") local)
       ((string=? uri svg-namespace-uri) (string-append "svg:" local))
       ((string=? uri mathml-namespace-uri) (string-append "math:" local))
       (else (string-append "{" uri "}" prefix ":" local)))))
  (cond
   ((XMLElement? node)
    (using (node :- XMLElement)
      (append [(name-string node.name)]
              (map (lambda ((attr : XMLAttribute))
                     ['@ (name-string attr.name) attr.value])
                   node.attributes)
              (map shape node.children))))
   ((XMLText? node)
    (using (node :- XMLText) node.data))
   ((XMLComment? node)
    (using (node :- XMLComment) ['! node.data]))
   ((XMLPI? node)
    (using (node :- XMLPI) ['? node.target node.data]))
   ((HTMLDoctype? node)
    (using (node :- HTMLDoctype)
      ['!DOCTYPE node.name node.public-id node.system-id]))
   (else node)))

(def (document input . options)
  (using (doc (apply read-html input options) :- HTMLDocument)
    (map shape doc.children)))

(def (body input . options)
  (let (html (car (apply document input options)))
    (cdr (caddr html))))

(def (fragment input . options)
  (map shape (apply read-html-fragment input options)))

(def xlink "{http://www.w3.org/1999/xlink}")

(def reader-test
  (test-suite "test :std/text/markup/html/reader"
    (test-case "documents: html, head and body are created"
      (check (document "") => '(("html" ("head") ("body"))))
      (check (document "<!--a--><p>x") => '((! "a") ("html" ("head") ("body" ("p" "x")))))
      (check (document "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\"><title>t</title>")
             => '((!DOCTYPE "html" "-//W3C//DTD HTML 4.01//EN" #f)
                  ("html" ("head" ("title" "t")) ("body"))))
      ;; in document order, as in the DOM
      (check (document "<!--a--><!DOCTYPE html><!--b--><p>")
             => '((! "a") (!DOCTYPE "html" #f #f) (! "b") ("html" ("head") ("body" ("p")))))
      (check (html-document-doctype (read-html "<p>")) => #f)
      (check (document "<?php x?>a") => '((? "php" "x") ("html" ("head") ("body" "a")))))

    (test-case "recovery as browsers do it"
      (check (body "<p>a<p>b") => '(("p" "a") ("p" "b")))
      (check (body "<b>1<i>2</b>3</i>") => '(("b" "1" ("i" "2")) ("i" "3")))
      (check (body "<table>x<tr><td>a</table>") => '("x" ("table" ("tbody" ("tr" ("td" "a"))))))
      (check (body "<ul><li>a<li>b</ul>") => '(("ul" ("li" "a") ("li" "b"))))
      (check (body "a</span>&amp;&notin;&#x80;") => '("a&\x2209;\x20ac;"))
      (check (body "<p a=1 a=2 B=3>") => '(("p" (@ "a" "1") (@ "b" "3"))))
      (check (body "<pre>\nx</pre><textarea>\n\ny</textarea>") => '(("pre" "x") ("textarea" "\ny")))
      (check (body "<select><option>a<option>b</select>")
             => '(("select" ("option" "a") ("option" "b")))))

    (test-case "byte, string, port input"
      (check (document (u8vector #xef #xbb #xbf #x3c #x70 #x3e #xc3 #xa9))
             => (document "<p>\xe9;"))
      (check (document (open-input-string "<b>x")) => (document "<b>x"))
      (check (document (open-input-u8vector (u8vector #x3c #x62 #x3e #x78))) => (document "<b>x"))
      (check (document (open-buffered-reader (u8vector #xef #xbb #xbf #x3c #x62 #x3e #x78)))
             => (document "<b>x"))
      (check (document (open-input-string "")) => (document ""))
      ;; a byte port that characters were read from is rejected by Gambit
      (let (port (open-input-u8vector (string->utf8 "x<b>")))
        (read-char port)
        (check-exception (read-html port) (lambda (e) (not (html-parse-error? e)))))
      (check (document (open-input-u8vector (u8vector))) => (document ""))
      ;; more than one 64 KB chunk through every kind of source
      (let* ((input (apply string-append (make-list 5000 "<p a='\xe9;'>t\xe9;\x1F600;</p>")))
             (bytes (string->utf8 input))
             (expected (document input)))
        (check (> (u8vector-length bytes) 65536) => #t)
        (check (document bytes) => expected)
        (check (document (open-input-string input)) => expected)
        (check (document (open-input-u8vector bytes)) => expected)
        (check (document (open-buffered-reader bytes)) => expected))
      (check (with-catch (lambda (e) (and (html-parse-error? e) (HTMLParseError-offset e)))
                         (lambda () (read-html (u8vector #x3c #x70 #x3e #x61 #xff))))
             => 4)
      (check-exception (read-html 'x) contract-violation-error?))

    (test-case "a lone surrogate in string input reads as U+FFFD"
      ;; Gambit's UTF-8 port decoder returns U+D800 for the bytes ED A0 80
      (let (str (read-line (open-input-u8vector [char-encoding: 'UTF-8
                                                 init: (u8vector #x3c #x70 #x3e #x61 #xed #xa0 #x80)])
                           #f))
        (check (char->integer (string-ref str 4)) => #xd800)
        (check (fragment str) => '(("p" "a\xfffd;")))
        (check (fragment (open-input-string str)) => '(("p" "a\xfffd;")))
        ;; only the surrogate is replaced, not a character above U+FFFF before it
        (check (fragment (string-append "<p>" (string (integer->char #x2de2f)) (substring str 3 5)))
               => `(("p" ,(string (integer->char #x2de2f) #\a (integer->char #xfffd)))))))

    (test-case "scripting flag: noscript content"
      (check (body "<body><noscript><p>x</noscript>") => '(("noscript" "<p>x")))
      (check (body "<body><noscript><p>x</noscript>" scripting?: #f) => '(("noscript" ("p" "x"))))
      (check (document "<head><noscript><link></noscript>" scripting?: #f)
             => '(("html" ("head" ("noscript" ("link"))) ("body")))))

    (test-case "foreign content: names and namespaces"
      (check (body "<svg viewbox='0 0 1 1' xlink:href=a xml:lang=en><foreignobject><p>x</svg>")
             => `(("svg:svg" (@ "viewBox" "0 0 1 1") (@ ,(string-append xlink "xlink:href") "a")
                   (@ "{http://www.w3.org/XML/1998/namespace}xml:lang" "en")
                   ("svg:foreignObject" ("p" "x")))))
      (check (body "<svg xmlns=s xmlns:xlink=l>")
             => '(("svg:svg" (@ "{http://www.w3.org/2000/xmlns/}:xmlns" "s")
                   (@ "{http://www.w3.org/2000/xmlns/}xmlns:xlink" "l"))))
      (check (body "<math definitionurl=u><mi>x</mi><b>y")
             => '(("math:math" (@ "definitionURL" "u") ("math:mi" "x")) ("b" "y")))
      (check (body "<svg><![CDATA[<x>]]></svg><![CDATA[y]]>")
             => '(("svg:svg" "<x>") (! "[CDATA[y]]")))
      (check (body "<p xlink:href=a>") => '(("p" (@ "xlink:href" "a")))))

    (test-case "template contents are the template's children"
      (check (document "<template><tr><td>a</template>")
             => '(("html" ("head" ("template" ("tr" ("td" "a")))) ("body")))))

    (test-case "fragments in context"
      (check (fragment "<p>a<td>b") => '(("p" "ab")))
      (check (fragment "<td>a<td>b" context: "tr") => '(("td" "a") ("td" "b")))
      (check (fragment "<tr><td>a" context: "TEMPLATE") => '(("tr" ("td" "a"))))
      (check (fragment "<b>x</textarea>" context: "textarea") => '("<b>x</textarea>"))
      (check (fragment "<head><body>x" context: "html") => '(("head") ("body" "x")))
      (check (fragment "<p>x" context: (make-xml-element (make-xml-name "desc" svg-namespace-uri "") [] []))
             => '(("p" "x")))
      (check (fragment "<p>x" context: (make-xml-element (make-xml-name "g" svg-namespace-uri "") [] []))
             => '(("p" "x")))
      (check (fragment "<g>x" context: (make-xml-element (make-xml-name "g" svg-namespace-uri "") [] []))
             => '(("svg:g" "x")))
      (let (annotation (lambda (attributes)
                         (make-xml-element (make-xml-name "annotation-xml" mathml-namespace-uri "")
                                           attributes [])))
        (check (fragment "<div>x" context: (annotation []))
               => '(("div" "x")))
        (check (fragment "<foo>x" context: (annotation []))
               => '(("math:foo" "x")))
        (check (fragment "<foo>x" context: (annotation [(make-xml-attribute (make-xml-name "encoding" "" "")
                                                                            "TEXT/HTML")]))
               => '(("foo" "x"))))
      ;; an invalid context, by type, name or namespace, raises before
      ;; anything is read from the source
      (for-each
       (lambda (context)
         (let (port (open-input-string "<p>x"))
           (check-exception (read-html-fragment port context: context) contract-violation-error?)
           (check (read-line port) => "<p>x")))
       ["1p" 'p 42
        (make-xml-element (make-xml-name "_p" svg-namespace-uri "") [] [])
        (make-xml-element (make-xml-name "p" "urn:x" "x") [] [])]))

    (test-case "malformed markup never raises"
      (for-each (lambda (input)
                  (check (pair? (document input)) => #t))
                ["<" "</" "<!" "<!-" "<?" "<a" "<a b='" "&#" "<table><td><svg><desc><td>"
                 "<template><frameset>" "<math><annotation-xml><svg><foreignObject><table></math>"
                 "<select><select><input><keygen><hr><option><optgroup>"
                 "<b><p><i><u><s></b></i></u></s>"
                 ;; foster parenting while the adoption agency rearranges the stack
                 "<table><a><o><ol><a>"
                 (string #\a #\nul #\b #\< #\x #\nul #\>)]))

    (test-case "text of many character runs"
      (def (repeat str n)
        (string-concatenate (make-list n str)))
      ;; runs split by ignored end tags, NUL and table text: more than the
      ;; argument limit of apply
      (check (body (string-append "<p>" (repeat "a</x>" 10000)))
             => [["p" (make-string 10000 #\a)]])
      (check (body (string-append "<p>" (repeat (string #\a #\nul) 10000)))
             => [["p" (make-string 10000 #\a)]])
      (check (body (string-append "<table>" (repeat (string #\a #\nul) 8200)))
             => [(make-string 8200 #\a) ["table"]]))

    (test-case "many attributes: Noah's Ark and html attribute merging"
      (let* ((attributes (call-with-output-string
                          "" (lambda (out)
                               (let loop ((k 0))
                                 (when (fx< k 20)
                                   (write-string " a" out)
                                   (write-string (number->string k) out)
                                   (write-string "=v" out)
                                   (loop (fx+ k 1)))))))
             (b (string-append "<b" attributes ">"))
             (tree (body (string-append "<p>" b b b b "</p>x"))))
        ;; of four identical b, three are reopened
        (check (let loop ((node (cadr tree)) (depth 0))
                 (if (string? node) depth (loop (last node) (fx+ depth 1))))
               => 3))
      (let (html (car (document (string-append "<html" (call-with-output-string
                                                       "" (lambda (out)
                                                            (let loop ((k 0))
                                                              (when (fx< k 20)
                                                                (write-string " a" out)
                                                                (write-string (number->string k) out)
                                                                (loop (fx+ k 1))))))
                                               "><html a0=x b=y>"))))
        (check (length (filter (lambda (x) (and (pair? x) (eq? (car x) '@))) html)) => 21)
        (check (last (filter (lambda (x) (and (pair? x) (eq? (car x) '@))) html)) => '(@ "b" "y"))))

    (test-case "one token reopens fewer than 512 formatting elements"
      (def (count-nodes nodes)
        (let loop ((nodes nodes) (n 0))
          (if (null? nodes)
            n
            (let (node (car nodes))
              (loop (cdr nodes)
                    (+ n 1 (if (XMLElement? node)
                             (using (node :- XMLElement)
                               (count-nodes node.children))
                             0)))))))
      ;; 500 distinct formatting elements closed by </p>, then 100 paragraphs
      ;; whose text token reopens all of them: html, head, body, the first p
      ;; with its b elements, then p, 500 b and the text 100 times
      (let (input (call-with-output-string
                   "" (lambda (out)
                        (write-string "<p>" out)
                        (let loop ((k 0))
                          (when (fx< k 500)
                            (write-string "<b id=" out)
                            (write-string (number->string k) out)
                            (write-string ">" out)
                            (loop (fx+ k 1))))
                        (write-string "</p>" out)
                        (let loop ((k 0))
                          (when (fx< k 100)
                            (write-string "<p>x</p>" out)
                            (loop (fx+ k 1)))))))
        (using (doc (read-html input) : HTMLDocument)
          (check (count-nodes doc.children)
                 => (+ 3 1 500 (* 100 (+ 1 500 1)))))))))
