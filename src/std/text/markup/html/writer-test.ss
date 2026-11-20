;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/io
        :std/text/markup/xml/types
        (only-in :std/text/markup/xml/node unchecked-node)
        :std/text/markup/html/types
        :std/text/markup/html/reader
        :std/text/markup/html/writer)
(export writer-test)

(def (element name attrs . children)
  (make-html-element name (map (lambda (a) (make-html-attribute (car a) (cdr a))) attrs) children))

(def (svg name . children)
  (make-xml-element (make-xml-name name svg-namespace-uri "") [] children))

(def (math name . children)
  (make-xml-element (make-xml-name name mathml-namespace-uri "") [] children))

;;; A name, attribute and element built without checks, as the internal
;;; producers of trees build them.
(def (raw-name local uri prefix)
  (unchecked-node XMLName local uri prefix))

(def (raw-attribute local uri prefix value)
  (make-xml-attribute (raw-name local uri prefix) value))

(def (raw-element local uri attrs children)
  (make-xml-element (raw-name local uri "") attrs children))

;;; A comment or processing instruction with data the XML constructors
;;; reject.
(def (comment data)
  (unchecked-node XMLComment data))

(def (pi target data)
  (unchecked-node XMLPI target data))

(def (rejects? node . options)
  (with-catch contract-violation-error?
              (lambda () (apply html->string node options) #f)))

;;; The output of read-html, written, read and written again.
(def (rewrite input)
  (html->string (read-html (html->string (read-html input)))))

(def writer-test
  (test-suite "test :std/text/markup/html/writer"
    (test-case "documents: DOCTYPE and comments in document order"
      (check (html->string (read-html "<!--a--><!DOCTYPE html><p>x"))
             => "<!--a--><!DOCTYPE html><html><head></head><body><p>x</p></body></html>")
      (check (html->string (make-html-document [(make-html-doctype "html" "-//W3C//DTD HTML 4.01//EN")]))
             => "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">")
      (check (html->string (make-html-document [(make-html-doctype "html" #f "a\"b")]))
             => "<!DOCTYPE html SYSTEM 'a\"b'>")
      (check (html->string (make-html-document [(make-html-doctype "html" "p" "s")]))
             => "<!DOCTYPE html PUBLIC \"p\" \"s\">")
      (check (html->string (make-html-document [(make-html-doctype "")])) => "<!DOCTYPE >"))

    (test-case "escaping: text & < >, attribute values also \"; NBSP, TAB, LF, CR raw"
      (check (html->string (element "p" '(("title" . "a<b>&\"'\xa0;\t"))
                                    (make-xml-text "<x> & \"y\" '\xa0;\t\n\r")))
             => "<p title=\"a&lt;b&gt;&amp;&quot;'\xa0;\t\">&lt;x&gt; &amp; \"y\" '\xa0;\t\n\r</p>")
      (check (html->string (element "input" '(("disabled" . "") ("123" . "1") (":x" . "2"))))
             => "<input disabled=\"\" 123=\"1\" :x=\"2\">")
      (check (html->string (make-html-raw "<b>&nbsp;</b>")) => "<b>&nbsp;</b>")
      (check (html->string [(make-xml-text "a") (make-xml-comment " c ") (make-xml-pi "php" "x ?")])
             => "a<!-- c --><?php x ??>")
      ;; processing instruction data keeps NUL, as the tokenizer reads it
      (check (html->string (pi "x" (string #\a #\nul)))
             => (string-append "<?x a" (string #\nul) "?>")))

    (test-case "void, raw text, RCDATA and plaintext elements"
      (check (html->string (element "div" '() (element "br" '()) (element "img" '(("src" . "x")))))
             => "<div><br><img src=\"x\"></div>")
      (check (html->string (element "command" '() (make-xml-text "a"))) => "<command>a</command>")
      (check (html->string (element "script" '() (make-xml-text "if (a<b && c>d) x='</scrip'")))
             => "<script>if (a<b && c>d) x='</scrip'</script>")
      (check (html->string (element "script" '() (make-xml-text "<!--<script></script>-->")))
             => "<script><!--<script></script>--></script>")
      (check (html->string (element "style" '() (make-xml-text "a>b{}</styles>")))
             => "<style>a>b{}</styles></style>")
      (check (html->string (element "title" '() (make-xml-text "a<b"))) => "<title>a&lt;b</title>")
      (check (html->string (element "textarea" '() (make-xml-text "\nx")))
             => "<textarea>\n\nx</textarea>")
      (check (html->string (element "pre" '() (make-xml-text "\nx"))) => "<pre>\n\nx</pre>")
      ;; a leading CR reads as LF, and empty text nodes are skipped
      (check (html->string (read-html-fragment "<pre>&#13;x</pre>")) => "<pre>\n\rx</pre>")
      (check (html->string (read-html-fragment "<textarea>&#13;x</textarea>"))
             => "<textarea>\n\rx</textarea>")
      (check (html->string (read-html-fragment "<listing>&#13;&#10;x</listing>"))
             => "<listing>\n\r\nx</listing>")
      (let (out (html->string (element "pre" '() (make-xml-text "") (make-xml-text "\nab"))))
        (check out => "<pre>\n\nab</pre>")
        (using ((pre (car (read-html-fragment out)) : XMLElement)
                (text (car pre.children) : XMLText))
          (check text.data => "\nab")))
      (check (html->string (element "div" '() (element "plaintext" '() (make-xml-text "</div>a"))))
             => "<div><plaintext></div>a")
      (check (html->string (element "template" '() (element "tr" '()))) => "<template><tr></tr></template>")
      ;; more text children than a procedure takes arguments
      (let (many (make-list 10000 (make-xml-text "a")))
        (check (html->string (make-html-element "script" [] many))
               => (string-append "<script>" (make-string 10000 #\a) "</script>"))
        (check (html->string (make-html-element "plaintext" [] many))
               => (string-append "<plaintext>" (make-string 10000 #\a)))))

    (test-case "foreign content"
      (check (html->string (read-html-fragment
                            "<svg viewBox='0 0 1 1' xlink:href=a xmlns:xlink=x><foreignObject><b>x</b></foreignObject><script>a&lt;b</script></svg><math><mi><b>y</b></mi></math>"))
             => "<svg viewBox=\"0 0 1 1\" xlink:href=\"a\" xmlns:xlink=\"x\"><foreignObject><b>x</b></foreignObject><script>a&lt;b</script></svg><math><mi><b>y</b></mi></math>")
      (check (html->string (svg "circle")) => "<circle></circle>")
      ;; read as HTML when the fragment is inserted into a body: a foreign
      ;; element named like an HTML raw text element must not end early
      (check (html->string (svg "style" (make-xml-text "a{}") (make-xml-comment "c")))
             => "<style>a{}<!--c--></style>")
      (check (html->string (svg "g" (svg "svg" (svg "style" (make-xml-comment "</style><img>")))))
             => "<g><svg><style><!--</style><img>--></style></svg></g>")
      (check (html->string (math "math" (math "style" (make-xml-comment "</style>"))))
             => "<math><style><!--</style>--></style></math>")
      ;; below the top level, svg and math stay in the namespace around them
      (check (html->string (svg "svg" (svg "math" (svg "style" (make-xml-text "a<b")))))
             => "<svg><math><style>a&lt;b</style></math></svg>")
      (check (html->string (read-html-fragment "<svg><math><style>a&lt;b</style></math></svg>"))
             => "<svg><math><style>a&lt;b</style></math></svg>")
      (for-each
       (lambda (node)
         (check (cons (object->string node) (rejects? node)) => (cons (object->string node) #t)))
       [(svg "style" (make-xml-comment "</style><img src=x onerror=alert(1)>"))
        (svg "g" (svg "title" (svg "title") (make-xml-comment "<img src=x onerror=alert(1)>")))
        (svg "script" (pi "x" "<!--<script ") (svg "g"))
        (math "mrow" (math "style" (make-xml-comment "</style>")))
        [(svg "g")
         (make-html-element "g" []
                            [(make-html-element "iframe" [] [(make-html-raw "</iframe><img>")]
                                                namespace: svg-namespace-uri)]
                            namespace: svg-namespace-uri)]]))

    (test-case "parsed documents round trip"
      (for-each (lambda (input)
                  (let (out (html->string (read-html input)))
                    (check (rewrite input) => out)))
                ["<!DOCTYPE html><title>a&amp;b</title><p class=x>Hi &lt;there&gt; &nbsp;<br>"
                 "<table><tr><td>a<td>b</table><pre>\n\nx</pre><textarea>\n\ny</textarea>"
                 "<svg><desc><p>x</p></desc><g><rect/></g></svg><math><annotation-xml encoding=text/html><p>y</annotation-xml></math>"
                 "<script>a<!--<script>x</script>--></script><style>a</sty</style>"
                 "<p>a<!-- <!-- b -->c<?x y?>"
                 "<p><?x a\x0;b?>"]))

    (test-case "rejects what the parser would not read back as written"
      (for-each
       (lambda (node)
         (check (cons (object->string node) (rejects? node)) => (cons (object->string node) #t)))
       [;; names
        (raw-element "P" "" [] [])
        (raw-element "1p" "" [] [])
        (raw-element "a b" "" [] [])
        (raw-element "foreignobject" svg-namespace-uri [] [])
        (raw-element "p" "urn:x" [] [])
        (make-xml-element (raw-name "p" "" "h") [] [])
        (raw-element "p" "" [(raw-attribute "a b" "" "" "")] [])
        (raw-element "p" "" [(raw-attribute "a=b" "" "" "")] [])
        (raw-element "p" "" [(raw-attribute "a" "" "" "") (raw-attribute "A" "" "" "")] [])
        ;; the parser reads HTML attribute names in lower case
        (raw-element "div" "" [(raw-attribute "onClick" "" "" "")] [])
        (raw-element "div" "" [(raw-attribute "viewBox" "" "" "")] [])
        (raw-element "math" mathml-namespace-uri [(raw-attribute "viewBox" "" "" "")] [])
        (raw-element "p" "" [(raw-attribute "href" xlink-namespace-uri "xlink" "")] [])
        (raw-element "svg" svg-namespace-uri [(raw-attribute "href" xlink-namespace-uri "xl" "")] [])
        (raw-element "svg" svg-namespace-uri [(raw-attribute "viewbox" "" "" "")] [])
        ;; namespaces the parser would not give
        (svg "svg" (element "script" '() (make-xml-text "<img src=x onerror=alert(1)>")))
        (svg "svg" (element "div" '()))
        (svg "svg" (svg "p"))
        (element "div" '() (svg "circle"))
        (math "math" (svg "svg"))
        ;; svg and math in the HTML namespace, at the top level too: the
        ;; parser reads <svg><style> as SVG, so the style text would be markup
        (raw-element "svg" "" []
                     [(element "style" '() (make-xml-text "x<img src=x onerror=alert(1)>"))])
        (raw-element "math" "" []
                     [(element "xmp" '() (make-xml-text "<img src=x onerror=alert(1)>"))])
        [(element "p" '()) (raw-element "svg" "" [] [(element "xmp" '() (make-xml-text "<img>"))])]
        ;; and in the other foreign namespace (the HTML writer fuzzer's
        ;; finds): <math> is read as MathML, <svg> as SVG
        (svg "math" (svg "foreignObject"
                         (element "xmp" '() (make-xml-text "<template><x-inj></template>"))))
        (math "svg" (math "mi" (element "iframe" '() (make-xml-text "<img src=x data-inj=1>"))))
        (math "svg" (make-xml-element (make-xml-name "annotation-xml" mathml-namespace-uri "")
                                      [(make-html-attribute "encoding" "text/html")]
                                      [(element "xmp" '() (make-xml-text "<body data-inj=1>"))]))
        [(element "p" '()) (svg "math")]
        ;; void, raw text, RCDATA, plaintext
        (element "br" '() (make-xml-text "x"))
        (element "script" '() (make-xml-text "</script><img>"))
        (element "script" '() (make-xml-text "<!--<script>"))
        (element "style" '() (make-xml-text "</STYLE >"))
        (element "script" '() (element "b" '()))
        (element "title" '() (element "b" '()))
        (element "div" '() (element "plaintext" '()) (make-xml-text "x"))
        [(element "plaintext" '()) (make-xml-text "x")]
        ;; comments, processing instructions, NUL, DOCTYPE
        (comment ">")
        (comment "->x")
        (comment "a-->b")
        (comment "a--!>b")
        (comment (string #\a #\nul))
        (make-xml-text (string #\a #\nul))
        (element "p" (list (cons "a" (string #\nul))))
        (make-xml-text (string (##integer->char #xd800)))
        (pi "xml" "x")
        (pi "XML-Stylesheet" "x")
        (pi "1x" "x")
        (pi "x" "a>b")
        (pi "x" " a")
        ;; read back as img
        (raw-element "image" "" [] [])
        ;; an XML node HTML has no syntax for
        (make-xml-element (make-xml-name "p" "" "") [] [(make-xml-cdata "x")])]))

    (test-case "many attributes: duplicates at and past 16"
      (def (attrs n) (map (lambda (k) (make-html-attribute (string-append "a" (number->string k)) "v")) (iota n)))
      ;; an element with n attributes, the last a duplicate of the first
      (def (duplicate-last n)
        (unchecked-node XMLElement (make-xml-name "p" "" "")
                                              (append (attrs (fx- n 1)) [(make-html-attribute "a0" "w")])
                                              []))
      (for-each (lambda (n)
                  (check (cons n (rejects? (duplicate-last n))) => (cons n #t))
                  (check (cons n (rejects? (make-html-element "p" (attrs n) []))) => (cons n #f)))
                [16 17 21])
      (check (string? (html->string (make-html-element "p" (attrs 16000) []))) => #t))

    (test-case "raw text elements where the tree builder ignores their start tags"
      (let ((payload (make-xml-text "<frameset onload=alert(1)>"))
            (html (lambda kids (make-html-document [(apply element "html" '() kids)]))))
        (for-each
         (lambda (raw)
           (for-each
            (lambda (tree)
              (check (cons raw (rejects? tree)) => (cons raw #t)))
            [(html (element "head" '()) (element "frameset" '() (element raw '() payload)))
             (html (element "head" '()) (element "frameset" '()) (element raw '() payload))
             (element "template" '() (element "col" '()) (element raw '() payload))
             (element "template" '() (element "col" '()) (element "div" '() (element raw '() payload)))]))
         ["script" "style" "xmp" "iframe" "noembed" "noscript" "plaintext"])
        (check (rejects? (element "template" '() (element "col" '()) (element "noframes" '() payload)))
               => #t)
        ;; noframes is read in frameset modes; a new template starts afresh
        (check (html->string (html (element "head" '())
                                   (element "frameset" '() (element "noframes" '() (make-xml-text "<b>")))))
               => "<html><head></head><frameset><noframes><b></noframes></frameset></html>")
        (check (html->string [(element "template" '() (element "col" '())
                                       (element "template" '() (element "script" '() (make-xml-text "a<b"))))
                              (element "script" '() (make-xml-text "c<d"))])
               => "<template><col><template><script>a<b</script></template></template><script>c<d</script>")))

    (test-case "noscript: raw text when scripting, checked data otherwise"
      (let (tree (read-html-fragment "<noscript><p>x</p><!--c--></noscript>" scripting?: #f))
        (check (html->string tree scripting?: #f) => "<noscript><p>x</p><!--c--></noscript>")
        (check (rejects? tree) => #t))
      (check (html->string (read-html-fragment "<noscript><p>x</noscript>"))
             => "<noscript><p>x</noscript>")
      (check (rejects? (element "noscript" '() (make-xml-comment "</noscript><img>")) scripting?: #f)
             => #t)
      (check (rejects? (element "noscript" '() (element "style" '() (make-xml-text "</NOSCRIPT>")))
                       scripting?: #f)
             => #t)
      (check (rejects? (element "noscript" '() (element "noscript" '()) (element "img" '()))
                       scripting?: #f)
             => #t)
      (check (rejects? (element "noscript" '() (svg "svg" (svg "noscript"))) scripting?: #f)
             => #t))

    (test-case "sinks: Writer, BufferedWriter, byte and character ports"
      (let* ((big (element "p" '() (make-xml-text (make-string 200000 #\xe9))))
             (expected (html->u8vector big)))
        (check (u8vector-length expected) => 400007)
        (check (utf8->string expected) => (html->string big))
        (check (let (out (open-output-u8vector)) (write-html big out) (get-output-u8vector out))
               => expected)
        (check (call-with-output-string "" (lambda (out) (write-html big out)))
               => (html->string big))
        (let (w (open-buffered-writer #f))
          (write-html big w)
          (check (get-memory-output-u8vector w) => expected))))

    (test-case "html-escape"
      (check (html-escape "a<b>&\"'c\xe9;") => "a&lt;b&gt;&amp;&quot;&#39;c\xe9;")
      (check (html-escape "") => "")
      (check (html-escape "plain") => "plain"))))
