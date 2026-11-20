;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; WHATWG tree construction: documents and fragments as read-html and
;;; read-html-fragment build them, and the write-html round trip of each.
(import :std/test
        (only-in :std/error contract-violation-error?)
        :std/text/markup/xml/types
        :std/text/markup/html/types
        :std/text/markup/html/reader
        :std/text/markup/html/writer)
(export tree-test)

;;; A node as an s-expression: (name (@ name value) ... child ...), text as
;;; a string, (! data) a comment, (? target data) a processing instruction,
;;; (!DOCTYPE name public-id system-id). As html5lib writes them, SVG and
;;; MathML elements are named "svg name" and "math name", and attributes in
;;; a namespace "xlink name", "xml name" and "xmlns name".
(def (shape node)
  (def (prefixed (name : XMLName))
    (let ((uri name.uri)
          (local name.local))
      (cond
       ((string=? uri svg-namespace-uri) (string-append "svg " local))
       ((string=? uri mathml-namespace-uri) (string-append "math " local))
       ((string=? uri xlink-namespace-uri) (string-append "xlink " local))
       ((string=? uri xml-namespace-uri) (string-append "xml " local))
       ((string=? uri xmlns-namespace-uri) (string-append "xmlns " local))
       (else local))))
  (cond
   ((XMLElement? node)
    (using (node :- XMLElement)
      (append [(prefixed node.name)]
              (map (lambda ((attr : XMLAttribute))
                     ['@ (prefixed attr.name) attr.value])
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

;;; A tree case: (input expected option ...), options
;;;   context: c       a fragment in context c, an HTML tag name or an
;;;                    html5lib context such as "svg desc" or "math mi";
;;;                    without it a document
;;;   document: #t     expected is the document's nodes, not the body's
;;;   scripting: #f    the scripting flag is unset
;;;   write: reshaped  the tree is not the one its markup reads as, so it
;;;                    does not round trip: the adoption agency and foster
;;;                    parenting nest elements as no markup does, CR reads
;;;                    back as LF
;;;   write: escaped   a fragment in a raw text context, which write-html
;;;                    escapes as text for an HTML context
;;;   write: rejected  write-html raises ContractViolation, as documented
(def (tree-case-option tree-case key default)
  (cond
   ((memq key (cddr tree-case)) => cadr)
   (else default)))

(def (tree-case-context tree-case)
  (let (context (tree-case-option tree-case context: #f))
    (cond
     ((not context) #f)
     ((string-index context #\space)
      => (lambda (space)
           (make-xml-element (make-xml-name (substring context (fx+ space 1)
                                                       (string-length context))
                                            (if (string-prefix? "svg" context)
                                              svg-namespace-uri
                                              mathml-namespace-uri)
                                            "")
                             [] [])))
     (else context))))

(def (tree-case-scripting? tree-case)
  (tree-case-option tree-case scripting: #t))

;;; The case's document or fragment nodes read from input.
(def (tree-case-read tree-case input)
  (let ((context (tree-case-context tree-case))
        (scripting? (tree-case-scripting? tree-case)))
    (if context
      (read-html-fragment input context: context scripting?: scripting?)
      (read-html input scripting?: scripting?))))

;;; The shape of a case's tree as expected compares it.
(def (tree-case-shape tree-case tree)
  (cond
   ((list? tree) (map shape tree))
   (else
    (using (doc tree : HTMLDocument)
      (if (tree-case-option tree-case document: #f)
        (map shape doc.children)
        (let* ((html (find (lambda (node) (and (pair? node) (equal? (car node) "html")))
                           (map shape doc.children)))
               (body (find (lambda (node) (and (pair? node) (equal? (car node) "body"))) html)))
          (cdr body)))))))

(def (check-trees cases)
  (for-each (lambda (tree-case)
              (let (tree (tree-case-read tree-case (car tree-case)))
                (check (cons (car tree-case) (tree-case-shape tree-case tree))
                       => (cons (car tree-case) (cadr tree-case)))))
            cases))

;;; The tree of input written with write-html and read again in the same way.
(def (round-trip tree-case)
  (let (tree (tree-case-read tree-case (car tree-case)))
    (tree-case-read tree-case (html->string tree scripting?: (tree-case-scripting? tree-case)))))

(def (writer-rejects? tree-case)
  (with-catch contract-violation-error?
              (lambda ()
                (html->string (tree-case-read tree-case (car tree-case))
                              scripting?: (tree-case-scripting? tree-case))
                #f)))

;;; The body's nodes of the document read from input.
(def (body input)
  (tree-case-shape [input #f] (read-html input)))

;;; The shapes of the nodes of a fragment in a body.
(def (fragment input)
  (map shape (read-html-fragment input)))

;;; The offset of the HTMLParseError thunk raises, or #f.
(def (parse-error-offset thunk)
  (with-catch (lambda (e) (and (html-parse-error? e) (HTMLParseError-offset e)))
              (lambda () (thunk) #f)))

;;; n elements named name nested around the nodes more, as a list of one.
(def (nested name n more)
  (let loop ((k 0) (tree more))
    (if (fx= k n) tree (loop (fx+ k 1) [(cons name tree)]))))

(def (repeat str n)
  (string-concatenate (make-list n str)))

(def implied-cases
  '(("" (("html" ("head") ("body"))) document: #t)
    ("x" (("html" ("head") ("body" "x"))) document: #t)
    ("<title>t</title>x" (("html" ("head" ("title" "t")) ("body" "x"))) document: #t)
    ("<!--a--><!DOCTYPE html><html><!--b--><head></head> <body>"
     ((! "a") (!DOCTYPE "html" #f #f) ("html" (! "b") ("head") " " ("body"))) document: #t)
    ("<html> <head> </head> <body>" (("html" ("head" " ") " " ("body"))) document: #t)
    ("<html a=1><body b=2><html c=3 a=4><body d=5 b=6>"
     (("html" (@ "a" "1") (@ "c" "3") ("head") ("body" (@ "b" "2") (@ "d" "5")))) document: #t)
    ("<p>a</p></body></html><!--x--> y" (("html" ("head") ("body" ("p" "a") " y")) (! "x"))
     document: #t)
    ("<meta charset=utf-8><link><script>a</script><style>b</style><p>"
     (("html" ("head" ("meta" (@ "charset" "utf-8")) ("link") ("script" "a") ("style" "b"))
       ("body" ("p"))))
     document: #t)
    ("</head><link>" (("html" ("head" ("link")) ("body"))) document: #t)
    ("<?php x?>a<?a b?>" ((? "php" "x") ("html" ("head") ("body" "a" (? "a" "b")))) document: #t)))

(def body-cases
  '(("<p>a<p>b" (("p" "a") ("p" "b")))
    ("<p>a<div>b</div>c" (("p" "a") ("div" "b") "c"))
    ("<p>a</p></p>" (("p" "a") ("p")))
    ("<p><button><p>" (("p" ("button" ("p")))))
    ("<ul><li>a<li>b<ol><li>c</ul>d" (("ul" ("li" "a") ("li" "b" ("ol" ("li" "c")))) "d"))
    ("<li>a<div><li>b" (("li" "a" ("div")) ("li" "b")))
    ("<dl><dt>a<dd>b<dt>c</dl>" (("dl" ("dt" "a") ("dd" "b") ("dt" "c"))))
    ("<option>a<option>b" (("option" "a") ("option" "b")))
    ("<h1>a<h2>b</h1>c" (("h1" "a") ("h2" "b") "c"))
    ("<h1><div><h2>" (("h1" ("div" ("h2")))))
    ("<p><h1>a</p>b" (("p") ("h1" "a" ("p") "b")))
    ("<ruby><rb>a<rt>b<rp>c</ruby>" (("ruby" ("rb" "a") ("rt" "b") ("rp" "c"))))
    ("<pre>\n\na</pre><listing>\nb</listing><textarea>\nc</textarea>"
     (("pre" "\na") ("listing" "b") ("textarea" "c")))
    ("a<br/>b</br>c<image src=x>" ("a" ("br") "b" ("br") "c" ("img" (@ "src" "x"))))
    ("<xmp><b>&amp;</xmp><iframe><i></iframe>" (("xmp" "<b>&amp;") ("iframe" "<i>")))
    ("a<title><b>&amp;</title>" ("a" ("title" "<b>&")))
    ("<plaintext></plaintext>&amp;" (("plaintext" "</plaintext>&amp;")))
    ("<form><form><input></form>x" (("form" ("input")) "x"))
    ("a<td>b<tr>c</td>" ("abc"))
    ("a\x0;b&#0;" ("ab\xfffd;"))
    ("a&#13;b" ("a\rb") write: reshaped)))

(def formatting-cases
  '(("<a>1<a>2" (("a" "1") ("a" "2")))
    ("<nobr>1<nobr>2" (("nobr" "1") ("nobr" "2")))
    ("<b>1<p>2</b>3</p>" (("b" "1") ("p" ("b" "2") "3")))
    ("<b>1<i>2</b>3</i>" (("b" "1" ("i" "2")) ("i" "3")))
    ("<b><p>a</b>b<i>c</p>d" (("b") ("p" ("b" "a") "b" ("i" "c")) ("i" "d")))
    ;; Noah's Ark: at most three equal entries; b x=1 is another element
    ("<p><b><b><b><b></p>x" (("p" ("b" ("b" ("b" ("b"))))) ("b" ("b" ("b" "x")))))
    ("<p><b><b x=1><b><b></p>x"
     (("p" ("b" ("b" (@ "x" "1") ("b" ("b")))))
      ("b" ("b" (@ "x" "1") ("b" ("b" "x"))))))
    ;; the inner loop clones at most three formatting elements: b is left out
    ("<a><b><i><u><s><div>x</a>y"
     (("a" ("b" ("i" ("u" ("s"))))) ("i" ("u" ("s" ("div" ("a" "x") "y"))))))
    ("<a><p>x</a>y" (("a") ("p" ("a" "x") "y")))
    ("<p><table></p>" (("p" ("p") ("table"))) write: reshaped)
    ("<a><table><a>" (("a" ("a") ("table"))) write: reshaped)))

(def table-cases
  '(("<table><tr><td>a</td></tr></table>" (("table" ("tbody" ("tr" ("td" "a"))))))
    ("<table><td>a<td>b<tr><th>c"
     (("table" ("tbody" ("tr" ("td" "a") ("td" "b")) ("tr" ("th" "c"))))))
    ("<table> <tr> </table>" (("table" " " ("tbody" ("tr" " ")))))
    ("<table>a<b>b</b><tr><td>c</table>" ("a" ("b" "b") ("table" ("tbody" ("tr" ("td" "c"))))))
    ("<table><tr>a <td>b" ("a " ("table" ("tbody" ("tr" ("td" "b"))))))
    ("<table><caption>a<td>b</table>" (("table" ("caption" "a") ("tbody" ("tr" ("td" "b"))))))
    ("<table><colgroup><col><col></colgroup><col><tr>"
     (("table" ("colgroup" ("col") ("col")) ("colgroup" ("col")) ("tbody" ("tr")))))
    ("<table><input type=hidden><input>" (("input") ("table" ("input" (@ "type" "hidden")))))
    ("<table><form><tr>" (("table" ("form") ("tbody" ("tr")))))
    ("<table><thead><tr><tbody><tr><tfoot>"
     (("table" ("thead" ("tr")) ("tbody" ("tr")) ("tfoot"))))
    ("<table><tr><td><p>a</table>b" (("table" ("tbody" ("tr" ("td" ("p" "a"))))) "b"))
    ("<table><td><table></table>x</td></table>"
     (("table" ("tbody" ("tr" ("td" ("table") "x"))))))
    ("<table><tr><td>a</tr>b" ("b" ("table" ("tbody" ("tr" ("td" "a"))))))))

(def select-cases
  '(("<select><option>a<option>b<hr><optgroup><option>c</select>"
     (("select" ("option" "a") ("option" "b") ("hr") ("optgroup" ("option" "c")))))
    ("<select><div>a</div><b>b</select>c" (("select" ("div" "a") ("b" "b")) ("b" "c")))
    ("<select><select>a" (("select") "a"))
    ("<select><option>a<input>" (("select" ("option" "a")) ("input")))))

(def template-cases
  '(("<template><tr><td>a</template>" (("html" ("head" ("template" ("tr" ("td" "a")))) ("body")))
     document: #t)
    ("<body><template><td>x</td></template>" (("template" ("td" "x"))))
    ("<body><template><table><tr></template>" (("template" ("table" ("tbody" ("tr"))))))
    ("<body><template>a<template>b</template>c</template>" (("template" "a" ("template" "b") "c")))
    ("<table><template><td>x</template></table>" (("table" ("template" ("td" "x")))))
    ("<body><template><col><frameset></template></template>" (("template" ("col"))))))

(def foreign-cases
  '(("<svg viewbox=0 foo=1><foreignobject><p>x</p></foreignobject></svg>"
     (("svg svg" (@ "viewBox" "0") (@ "foo" "1") ("svg foreignObject" ("p" "x")))))
    ("<svg><clippath><feblend/><path/>x</svg>"
     (("svg svg" ("svg clipPath" ("svg feBlend") ("svg path") "x"))))
    ("<svg xlink:href=a xml:lang=b xmlns:xlink=c xmlns=d x:y=e>"
     (("svg svg" (@ "xlink href" "a") (@ "xml lang" "b") (@ "xmlns xlink" "c") (@ "xmlns xmlns" "d")
       (@ "x:y" "e"))))
    ("<math definitionurl=x><mi><b>y</b><mglyph></mi></math>"
     (("math math" (@ "definitionURL" "x") ("math mi" ("b" "y") ("math mglyph")))))
    ("<svg><b>x</b></svg>y" (("svg svg") ("b" "x") "y"))
    ("<svg><font color=red><font>" (("svg svg") ("font" (@ "color" "red") ("font"))))
    ("<svg><font><p>" (("svg svg" ("svg font")) ("p")))
    ("<svg><style><b>x</b></style>" (("svg svg" ("svg style")) ("b" "x")))
    ("<svg><script>a&amp;</script>b" (("svg svg" ("svg script" "a&") "b")))
    ("<svg><desc><p>x</p></desc>y</svg>" (("svg svg" ("svg desc" ("p" "x")) "y")))
    ("<math><annotation-xml encoding=text/html><div>x"
     (("math math" ("math annotation-xml" (@ "encoding" "text/html") ("div" "x")))))
    ("<math><annotation-xml><div>" (("math math" ("math annotation-xml")) ("div")))
    ("<math><annotation-xml><svg>" (("math math" ("math annotation-xml" ("svg svg")))))
    ("<svg><![CDATA[a<b>]]></svg><![CDATA[c]]>" (("svg svg" "a<b>") (! "[CDATA[c]]")))
    ("<svg>\x0;x</svg>" (("svg svg" "\xfffd;x")))
    ;; tr is not a breakout tag
    ("<table><svg><tr>" (("svg svg" ("svg tr")) ("table")))))

(def frameset-cases
  '(("<frameset><frame></frameset>" (("html" ("head") ("frameset" ("frame")))) document: #t)
    ("<frameset><frameset><frame></frameset><noframes>x</noframes></frameset>"
     (("html" ("head") ("frameset" ("frameset" ("frame")) ("noframes" "x")))) document: #t)
    ("<div><frameset>" (("html" ("head") ("frameset"))) document: #t)
    ("<p>x<frameset>" (("html" ("head") ("body" ("p" "x")))) document: #t)
    ("<frameset></frameset> x <!--y-->" (("html" ("head") ("frameset") "  " (! "y")))
     document: #t)))

(def noscript-cases
  '(("<head><noscript><link><p>x" (("html" ("head" ("noscript" "<link><p>x")) ("body")))
     document: #t)
    ("<head><noscript><link><p>x" (("html" ("head" ("noscript" ("link"))) ("body" ("p" "x"))))
     document: #t scripting: #f)
    ("<body><noscript><p>x</noscript>" (("noscript" "<p>x")))
    ("<body><noscript><p>x</noscript>" (("noscript" ("p" "x"))) scripting: #f)))

;;; A p is closed by a table except in quirks mode.
(def quirks-cases
  '(("<p><table>" (("p" ("table"))))
    ("<!DOCTYPE html><p><table>" (("p") ("table")))
    ("<!DOCTYPE><p><table>" (("p" ("table"))))
    ("<!DOCTYPE foo><p><table>" (("p" ("table"))))
    ("<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"><p><table>"
     (("p" ("table"))))
    ("<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><p><table>"
     (("p") ("table")))
    ("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"><p><table>"
     (("p") ("table")))
    ("<!DOCTYPE html SYSTEM \"http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd\"><p><table>"
     (("p" ("table"))))))

(def fragment-cases
  '(("a<p>b" ("a" ("p" "b")) context: "body")
    ("<title>t</title>x" (("head" ("title" "t")) ("body" "x")) context: "html")
    ("<tr><td>a" (("tbody" ("tr" ("td" "a")))) context: "table")
    ("x<td>" ("x" ("tbody" ("tr" ("td")))) context: "table")
    ("<td>a<tr><td>b" (("td" "a") ("td" "b")) context: "tr")
    ("<p>a</td>b" (("p" "ab")) context: "td")
    ("<option>a<select>b<input>" (("option" "ab")) context: "select")
    ("<optgroup><option>x" (("optgroup" ("option" "x"))) context: "select")
    ("<td>a<td>b" (("td" "a") ("td" "b")) context: "template")
    ("<b>&amp;</title>" ("<b>&</title>") context: "title")
    ("\nx" ("\nx") context: "textarea")
    ("<!--</script>-->&amp;" ("<!--</script>-->&amp;") context: "script" write: escaped)
    ("<b>&amp;" ("<b>&amp;") context: "style" write: escaped)
    ("</plaintext>&amp;" ("</plaintext>&amp;") context: "plaintext" write: escaped)
    ("<circle/>x" (("svg circle") "x") context: "svg g")
    ("<b>x" (("b" "x")) context: "svg desc")
    ("<mi>x" (("math mi" "x")) context: "math math")
    ("<mglyph/><div>" (("math mglyph") ("div")) context: "math mi")
    ("<![CDATA[x]]>" ("x") context: "svg svg")
    ("<![CDATA[x]]>" ((! "[CDATA[x]]")) context: "body")))

;;; Trees write-html rejects.
(def rejected-cases
  '(;; plaintext is not the last node: everything after <plaintext> is its text
    ("<table><plaintext><td>" (("plaintext" "<td>") ("table")) write: rejected)
    ;; with scripting off, noscript holds data containing </noscript
    ("<noscript><!--</noscript>X<noscript>--></noscript>"
     (("html" ("head" ("noscript" (! "</noscript>X<noscript>"))) ("body")))
     document: #t scripting: #f write: rejected)
    ;; script text ending in the double escaped state never ends
    ("<script><!--<script " (("html" ("head" ("script" "<!--<script ")) ("body")))
     document: #t write: rejected)))

(def tree-cases
  (append implied-cases body-cases formatting-cases table-cases select-cases template-cases
          foreign-cases frameset-cases noscript-cases quirks-cases fragment-cases rejected-cases))

(def tree-test
  (test-suite "test :std/text/markup/html tree construction"
    (test-case "html, head and body are implied" (check-trees implied-cases))

    (test-case "html and body start tags add the attributes their element lacks, in order"
      (check-trees '(("<body><body a=1><body a=2 b=3><html c=4><html c=5>"
                      (("html" (@ "c" "4") ("head") ("body" (@ "a" "1") (@ "b" "3"))))
                      document: #t)))
      ;; 2000 of each, adding one attribute and repeating x
      (let (names (map (lambda (k) (string-append "a" (number->string k))) (iota 2000)))
        (check-trees
         [[(string-append "<html><body x=1>"
                          (string-concatenate
                           (map (lambda (name) (string-append "<html " name "=h><body " name "=b x=2>"))
                                names)))
           [(append ["html"]
                    (map (lambda (name) ['@ name "h"]) names)
                    [["head"]
                     (append ["body" ['@ "x" "1"]] (map (lambda (name) ['@ name "b"]) names))])]
           document: #t]])))
    (test-case "implied end tags, headings, text elements" (check-trees body-cases))
    (test-case "formatting elements: adoption agency and Noah's Ark" (check-trees formatting-cases))

    (test-case "Noah's Ark compares elements with more than 16 attributes"
      ;; a b start tag with attributes a0 to a16, a16's value last; reversed?
      ;; lists them in reverse, more? adds a17
      (def (b last (reversed? #f) (more? #f))
        (let* ((attrs (map (lambda (k) (string-append " a" (number->string k) "=v")) (iota 16)))
               (attrs (append attrs [(string-append " a16=" last)] (if more? [" a17=v"] []))))
          (string-append "<b" (apply string-append (if reversed? (reverse attrs) attrs)) ">")))
      ;; the depth of the b elements reopened around x after </p>
      (def (reopened . tags)
        (let loop ((node (last (body (string-append "<p>" (apply string-append tags) "</p>x"))))
                   (depth 0))
          (if (equal? node "x") depth (loop (last node) (fx+ depth 1)))))
      (check (reopened (b "1") (b "1") (b "1") (b "1")) => 3)
      (check (reopened (b "1") (b "1" #t) (b "1") (b "1" #t)) => 3)
      (check (reopened (b "1") (b "2") (b "1") (b "1") (b "1")) => 4)
      (check (reopened (b "1") (b "1") (b "1") (b "1" #f #t)) => 4)
      (check (reopened (b "1" #f #t) (b "1" #f #t) (b "1" #f #t) (b "1")) => 4))

    (test-case "the adoption agency runs its outer loop at most eight times"
      ;; each run moves one div out of the a, cloned into it; the eighth
      ;; clone keeps the rest
      (check (body (string-append "<a>" (repeat "<div>" 10) "</a>x"))
             => (cons '("a")
                      (let loop ((k 1))
                        (if (fx= k 8)
                          '(("div" ("a" ("div" ("div" "x")))))
                          [["div" '("a") (car (loop (fx+ k 1)))]])))))

    (test-case "tables: implied elements, foster parenting" (check-trees table-cases))
    (test-case "select" (check-trees select-cases))
    (test-case "template contents" (check-trees template-cases))
    (test-case "foreign content" (check-trees foreign-cases))
    (test-case "frameset" (check-trees frameset-cases))
    (test-case "noscript with scripting on and off" (check-trees noscript-cases))
    (test-case "quirks mode from the DOCTYPE" (check-trees quirks-cases))
    (test-case "fragments in context" (check-trees fragment-cases))

    (test-case "searches of the stack of open elements are exact"
      ;; end tags find their element 500 entries down
      (check (fragment (string-append "<div>" (repeat "<span>" 500) "</div><p>after</p>"))
             => [(cons "div" (nested "span" 500 '())) '("p" "after")])
      (check (fragment (string-append "<ul><li>" (repeat "<span>" 500) "</li></ul><p>"))
             => [["ul" (cons "li" (nested "span" 500 '()))] '("p")])
      (check (fragment (string-append "<table><tr><td>" (repeat "<div>" 500) "</table><p>"))
             => [["table" ["tbody" ["tr" (cons "td" (nested "div" 500 '()))]]] '("p")])
      (check (fragment (string-append "<button>" (repeat "<span>" 500) "<button>"))
             => [(cons "button" (nested "span" 500 '())) '("button")])
      (check (body (string-append "<p>" (repeat "<span>" 500) "</p>x"))
             => [(cons "p" (nested "span" 500 '())) "x"]))

    (test-case "a p in button scope follows the changes of the stack"
      ;; 500 entries up, a start tag closes the p unless a button is between
      (check (body (string-append "<p>" (repeat "<span>" 500) "<div>x"))
             => [(cons "p" (nested "span" 500 '())) '("div" "x")])
      (check (body (string-append "<p><button>" (repeat "<span>" 500) "<div>x"))
             => [["p" (cons "button" (nested "span" 500 '(("div" "x"))))]])
      (check (body (string-append "<p><button>" (repeat "<span>" 500) "</p>x"))
             => [["p" (cons "button" (nested "span" 500 '(("p") "x")))]])
      ;; the adoption agency's eighth run moves the p and leaves a clone of
      ;; the b open above it
      (check (body (string-append "<b>" (repeat "<div>" 7) "<p>x</b>y<div>z"))
             => (cons '("b")
                      (let loop ((k 0) (kids '(("p" ("b" "xy")) ("div" ("b" "z")))))
                        (if (fx= k 7) kids (loop (fx+ k 1) [(cons* "div" '("b") kids)])))))
      (check (body "<p><b><button>x</b>y<div>z")
             => '(("p" ("b") ("button" ("b" "x") "y" ("div" "z")))))
      ;; a form end tag removes the form below the open p
      (check (body "<form><p><span>x</form>y<div>z")
             => '(("form" ("p" ("span" "xy"))) ("div" "z"))))

    (test-case "opening a 513th open element or formatting entry raises"
      ;; html, body and 510 elements; a fragment has its root html element
      (check (body (repeat "<div>" 510)) => (nested "div" 510 '()))
      (check (parse-error-offset (lambda () (read-html (repeat "<div>" 511)))) => 2550)
      (check (length (read-html-fragment (repeat "<div>" 511))) => 1)
      (check (parse-error-offset (lambda () (read-html-fragment (repeat "<div>" 512)))) => 2555)
      ;; a void element is pushed too
      (check (parse-error-offset (lambda () (read-html (string-append (repeat "<div>" 510) "<br>"))))
             => 2550)
      ;; characters for string input, bytes for byte input
      (check (parse-error-offset (lambda () (read-html (string-append "\xe9;" (repeat "<div>" 511)))))
             => 2551)
      (check (parse-error-offset
              (lambda () (read-html (string->bytes (string-append "\xe9;" (repeat "<div>" 511))))))
             => 2552)
      ;; reopening formatting elements raises at the token that reopens them
      (let (before (string-append "<p>"
                                  (apply string-append
                                         (map (lambda (k) (string-append "<b id=" (number->string k) ">"))
                                              (iota 500)))
                                  "</p>" (repeat "<div>" 20)))
        (check (parse-error-offset (lambda () (read-html-fragment (string-append before "x"))))
               => (string-length before)))
      ;; text in a table reopens them when the token after it is read, but
      ;; raises where it starts
      (let (before (string-append (repeat "<div>" 508) "<p><b>x</p><div><table>"))
        (check (parse-error-offset (lambda () (read-html (string-append before "yy</table>"))))
               => (string-length before))
        (check (parse-error-offset (lambda () (read-html (string-append before " y<i>"))))
               => (string-length before)))
      ;; the list of active formatting elements outgrows the stack when a
      ;; <table> start tag in table mode pops object elements across their
      ;; markers
      (check (parse-error-offset (lambda () (read-html (repeat "<table><object>" 600))))
             => (+ (* 15 512) 7)))

    (test-case "trees nested 512 deep round trip; deeper ones do not read back"
      (let* ((n 510)
             (input (string-append (repeat "<div>" n) "x" (repeat "</div>" n)))
             (tree-case [input #f])
             (expected (nested "div" n '("x"))))
        (check (body input) => expected)
        (check (tree-case-shape tree-case (round-trip tree-case)) => expected))
      (let (deep (let loop ((k 0) (node (make-xml-text "x")))
                   (if (fx= k 600)
                     node
                     (loop (fx+ k 1) (make-html-element "div" [] [node])))))
        (check (parse-error-offset (lambda () (read-html-fragment (html->string deep)))) => 2555)))

    (test-case "write-html rejects what would not read back as written"
      (check-trees rejected-cases)
      (for-each (lambda (tree-case)
                  (check (cons (car tree-case) (writer-rejects? tree-case))
                         => (cons (car tree-case) #t)))
                rejected-cases))

    (test-case "trees round trip through write-html"
      (for-each (lambda (tree-case)
                  (let ((input (car tree-case))
                        (expected (cadr tree-case)))
                    (case (tree-case-option tree-case write: #f)
                      ((#f)
                       (check (cons input (tree-case-shape tree-case (round-trip tree-case)))
                              => (cons input expected)))
                      ((reshaped escaped)
                       (check (cons input (equal? (tree-case-shape tree-case (round-trip tree-case))
                                                  expected))
                              => (cons input #f))))))
                tree-cases))))
