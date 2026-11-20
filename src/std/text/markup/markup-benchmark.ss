;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import ./xml
        ./html
        ./djot
        ./tal
        (only-in ./tal/reader read-tal-template tal-offset-locator)
        (only-in ./tal/compiler compile-tal-template)
        (only-in :std/io/tempfile call-with-temporary-file-name)
        (only-in :std/io/counter open-output-length-writer))
(export main)
(extern namespace: #f time)

;;; Time only the repeated operation; input generation happens in main. A
;;; copy of djot-benchmark.ss's: each tool is a standalone program.
(def (benchmark (operation  : :procedure)
                (iterations : :fixnum)) => :void
  (##gc)
  (time
    (let loop ((i 0 : :fixnum)) => :void
      (when (fx< i iterations)
        (operation)
        (loop (fx+ i 1))))))

;;; inputs, generated from size

(def (repeat (str : :string)
             (n   : :fixnum)) => :string
  (string-concatenate (make-list n str)))

;;; open n times, then inner, then close n times.
(def (nested (open  : :string)
             (inner : :string)
             (close : :string)
             (n     : :fixnum)) => :string
  (string-append (repeat open n) inner (repeat close n)))

;;; (make k) for k "0" to SIZE - 1, concatenated.
(def (numbered (n    : :fixnum)
               (make : :procedure)) => :string
  (let loop ((k (fx- n 1)) (out []))
    (if (fx< k 0)
      (string-concatenate out)
      (loop (fx- k 1) (cons (make (number->string k)) out)))))

;;; An a:r root around SIZE nested a:e elements, each declaring one more
;;; prefix.
(def (xml-nested-declarations-document (n : :fixnum)) => :string
  (string-append
   "<a:r xmlns:a='urn:a'>"
   (numbered n (lambda (k) (string-append "<a:e xmlns:b" k "='urn:b" k "'>")))
   (repeat "</a:e>" n)
   "</a:r>"))

;;; One element with SIZE namespace declarations, each prefix naming an
;;; attribute.
(def (xml-wide-declarations-document (n : :fixnum)) => :string
  (string-append
   "<r"
   (numbered n (lambda (k) (string-append " xmlns:p" k "='urn:p" k "' p" k ":a='1'")))
   "/>"))

;;; SIZE nested elements, each binding one more prefix to urn:u, around
;;; one that binds them all to urn:v and holds SIZE children with an
;;; attribute in urn:u, which no prefix in scope names there. Built from the
;;; node types: read-xml gives every attribute a prefix that resolves.
(def (xml-rebound-prefixes-element (n : :fixnum)) => XMLElement
  (let* ((prefixes (map (lambda (k) (string-append "p" (number->string k))) (iota n)))
         (declarations (lambda (uri)
                         (map (lambda (prefix) (XMLAttribute (XMLName prefix xmlns-namespace-uri) uri))
                              prefixes)))
         (child (XMLElement (XMLName "c") [(XMLAttribute (XMLName "a" "urn:u") "1")] []))
         (inner (XMLElement (XMLName "i") (declarations "urn:v") (make-list n child))))
    (foldr (lambda (declaration tree) (XMLElement (XMLName "e") [declaration] [tree]))
           inner
           (declarations "urn:u"))))

;;; SIZE elements, each with 8 attributes, two of them namespaced.
(def (xml-attributes-document (n : :fixnum)) => :string
  (string-append
   "<doc xmlns:a='urn:a' xmlns:b='urn:b'>"
   (repeat "<item id='i' name='n' class='c' title='t' lang='en' dir='ltr' a:x='1' b:y='2'/>" n)
   "</doc>"))

;;; SIZE paragraphs of text with character references.
(def (xml-text-document (n : :fixnum)) => :string
  (string-append "<doc>" (repeat "<p>alpha &amp; beta &lt; gamma &#233; delta</p>\n" n) "</doc>"))

;;; A small document using four namespace prefixes.
(def xml-namespaces-document
  (string-append
   "<a:doc xmlns:a='urn:a' xmlns:b='urn:b' xmlns:c='urn:c' xmlns:d='urn:d'>"
   "<b:item c:x='1'><d:name>n</d:name></b:item><a:item b:y='2'><c:v>v</c:v></a:item>"
   "</a:doc>"))

;;; SIZE paragraphs of non-ASCII text.
(def (html-text-document (n : :fixnum)) => :string
  (string-append "<!DOCTYPE html><body>"
                 (repeat "<p>Größe, café, naïve — “quoted” text, 日本語 and more.</p>\n" n)))

;;; SIZE table rows of elements with attributes and text.
(def (html-elements-document (n : :fixnum)) => :string
  (string-append
   "<!DOCTYPE html><table>"
   (repeat (string-append "<tr class=row><td id=a title=t lang=en dir=ltr data-x=1>alpha</td>"
                          "<td><a href=/x rel=next>beta</a> <b>gamma</b> <i>delta</i></td></tr>")
           n)
   "</table>"))

;;; Text of SIZE characters, some of which html-escape escapes.
(def (escape-text (n : :fixnum)) => :string
  (let (unit "Fish & chips <cheap> at \"Joe's\" for everyone. ")
    (substring (repeat unit (fx+ (fxquotient n (string-length unit)) 1)) 0 n)))

(define-TAL (repeat-lists lists)
  "<ul tal:repeat=\"(l lists)\"><li tal:repeat=\"(x l)\" tal:content=\"x\">x</li></ul>")

(define-TAL (small-page title)
  "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title tal:content=\"title\">Title</title></head><body><header><h1 tal:content=\"title\">Title</h1><nav><a href=\"/\">Home</a> <a href=\"/docs\">Docs</a> <a href=\"/about\">About</a></nav></header><main><p>Mostly static markup: the literal chunks are written as they were compiled, and the title is escaped twice.</p><p>Gerbil is a meta-dialect of Scheme with post-modern features.</p></main><footer><p>&copy; Gerbil contributors</p></footer></body></html>")

;;; The TAL reader and compiler, as define-TAL runs them at expansion time,
;;; locating the offset of each user expression and variable.
(def (tal-fail (offset  : :fixnum)
               (message : :string)) => :void
  (error message offset))

(def (compile-tal (text : :string)) => :list
  (let (locate (tal-offset-locator text))
    (compile-tal-template (read-tal-template text tal-fail)
                          tal-fail
                          (lambda (datum offset)
                            (locate offset)
                            datum))))

;;; With this checkout's stdlib built, compile from its root:
;;; out=$(mktemp -d)
;;; gxc -O -exe -d "$out" -o "$out/markup-benchmark" src/std/text/markup/markup-benchmark.ss
;;; Use ./run.sh gxc instead of gxc in a local build environment.
;;; Usage: "$out/markup-benchmark" MODE SIZE ITERATIONS (positive fixnums).
;;; Every input is generated from SIZE. Scaling modes: run them at doubling
;;; sizes; the time per iteration should double with SIZE, as each element
;;; costs the same at any depth (a little more for tal-dynamic-lines, which
;;; is O(SIZE log SIZE)).
;;;   tal-nested-spans: read and compile a TAL template of SIZE nested
;;;     span elements (whether a p is open, checked per start tag).
;;;   tal-items-in-divs: the same with SIZE li start tags inside SIZE
;;;     nested div elements (the list item search).
;;;   tal-dynamic-spans: SIZE nested span elements around a tal:content.
;;;   tal-template-columns: SIZE nested template elements, each with a
;;;     tal:omit-tag (whether a child may write a col, found once).
;;;   tal-dynamic-lines: a div around SIZE lines, each an element with a
;;;     tal:content (locating each expression).
;;;   tal-attributes: an element with SIZE attributes, each replaced
;;;     through its tal:attributes.
;;;   html-read-nested-spans, html-read-nested-divs: read-html of SIZE nested
;;;     span or div elements; SIZE at most 510 (with html and body, 512 open
;;;     elements), past which read-html raises.
;;;   html-read-merged-body: read-html of a body start tag and SIZE more,
;;;     each adding one attribute to the body element.
;;;   html-read-attributes, html-write-attributes: read-html of a start
;;;     tag with SIZE attributes, html->string of its element.
;;;   xml-read-nested: read-xml of SIZE nested elements.
;;;   xml-read-wide-attributes, xml-write-wide-attributes: read-xml of an
;;;     element with SIZE attributes, xml->string of it.
;;;   xml-write-nested-declarations: xml->string of SIZE nested elements,
;;;     each declaring one more prefix, inside a root whose prefix they use.
;;;   xml-write-wide-declarations: xml->string of one element with SIZE
;;;     namespace declarations, each prefix naming an attribute.
;;;   xml-write-rebound-prefixes: xml->string of SIZE nested elements, each
;;;     binding one more prefix to a namespace, around one that binds them
;;;     all to another and holds SIZE children with an attribute in the
;;;     first (the prefixes since bound again, passed over).
;;;   djot-openers: string->djot of SIZE runs of emphasis, highlight and
;;;     link openers that nothing closes.
;;;   djot-headings: djot->html of SIZE headings of the same text, each
;;;     given its own identifier.
;;;   djot-references, djot-notes: djot->html of SIZE reference links or
;;;     footnote references and their SIZE definitions.
;;; Workload modes, named by the comments on code kept for speed. Each such
;;; comment gives a mode, SIZE and ITERATIONS, the alternative measured, and
;;; how many more user-space instructions and cycles per iteration it took:
;;; perf stat -e instructions:u,cycles:u of a run at ITERATIONS and of one
;;; at twice ITERATIONS, the difference divided by ITERATIONS, so that
;;; generating the input cancels out. The time printed also counts the
;;; collector and the page faults of its heap, which can outweigh such
;;; differences either way.
;;;   xml-read-attributes: read-xml of SIZE elements with 8 attributes.
;;;   xml-write-attributes: xml->string of that document.
;;;   xml-read-text: read-xml of SIZE paragraphs with character references.
;;;   xml-read-file: read-xml of the xml-read-text document from a file
;;;     port, the file written to a temporary file once.
;;;   xml-write-writer: write-xml of that document to a Writer that counts
;;;     the bytes.
;;;   xml-read-namespaces: read-xml of SIZE small documents with four
;;;     namespace prefixes.
;;;   xml-write-namespaces: xml->string of that document, SIZE times.
;;;   html-read-string: read-html of a string of SIZE paragraphs of
;;;     non-ASCII text.
;;;   html-write-elements: html->string of SIZE table rows of elements with
;;;     attributes.
;;;   html-read-fragments: read-html-fragment of SIZE small fragments.
;;;   html-escape: html-escape of SIZE characters.
;;;   tal-repeat: a TAL template rendering SIZE tal:repeat lists of 3 items.
;;;   tal-small-page: SIZE renders of a mostly static 0.5 KB page. Its
;;;     comment gives the collector's time per render from the time printed
;;;     and kernel cycles (perf stat -e cycles:k), which instruction counts
;;;     do not show.
(def (main (mode       : :string)
           (size       : :string)
           (iterations : :string)) => :void
  (let ((n (string->number size))
        (count (string->number iterations)))
    (unless (and (fixnum? n) (fx> n 0))
      (error "Expected a positive fixnum size" size))
    (unless (and (fixnum? count) (fx> count 0))
      (error "Expected a positive fixnum iteration count" iterations))
    (case mode
      (("tal-nested-spans")
       (let (text (nested "<span>" "x" "</span>" n))
         (benchmark (lambda () (compile-tal text)) count)))
      (("tal-items-in-divs")
       (let (text (nested "<div>" (repeat "<li>x" n) "</div>" n))
         (benchmark (lambda () (compile-tal text)) count)))
      (("tal-dynamic-spans")
       (let (text (nested "<span>" "<b tal:content=\"x\">x</b>" "</span>" n))
         (benchmark (lambda () (compile-tal text)) count)))
      (("tal-template-columns")
       (let (text (nested "<template tal:omit-tag=\"\">" "x" "</template>" n))
         (benchmark (lambda () (compile-tal text)) count)))
      (("tal-dynamic-lines")
       (let (text (string-append "<div>" (repeat "<b tal:content=\"x\">x</b>\n" n) "</div>"))
         (benchmark (lambda () (compile-tal text)) count)))
      (("tal-attributes")
       (let (text (string-append "<b" (numbered n (lambda (k) (string-append " a" k "=\"x\"")))
                                 " tal:attributes=\""
                                 (numbered n (lambda (k) (string-append "(a" k " v) ")))
                                 "\">x</b>"))
         (benchmark (lambda () (compile-tal text)) count)))
      (("html-read-nested-spans")
       (let (text (nested "<span>" "x" "</span>" n))
         (benchmark (lambda () (read-html text)) count)))
      (("html-read-nested-divs")
       (let (text (nested "<div>" "x" "</div>" n))
         (benchmark (lambda () (read-html text)) count)))
      (("html-read-merged-body")
       (let (text (string-append "<body>" (numbered n (lambda (k) (string-append "<body a" k ">")))))
         (benchmark (lambda () (read-html text)) count)))
      (("html-read-attributes")
       (let (text (string-append "<b" (numbered n (lambda (k) (string-append " a" k "=x"))) ">x</b>"))
         (benchmark (lambda () (read-html text)) count)))
      (("html-write-attributes")
       (let (doc (read-html (string-append "<b" (numbered n (lambda (k) (string-append " a" k "=x")))
                                           ">x</b>")))
         (benchmark (lambda () (html->string doc)) count)))
      (("xml-read-nested")
       (let (text (nested "<e>" "x" "</e>" n))
         (benchmark (lambda () (read-xml text)) count)))
      (("xml-read-wide-attributes")
       (let (text (string-append "<r" (numbered n (lambda (k) (string-append " a" k "='x'"))) "/>"))
         (benchmark (lambda () (read-xml text)) count)))
      (("xml-write-wide-attributes")
       (let (el (read-xml (string-append "<r" (numbered n (lambda (k) (string-append " a" k "='x'")))
                                         "/>")))
         (benchmark (lambda () (xml->string el)) count)))
      (("djot-openers")
       (let (text (repeat "_a *b {=c [d " n))
         (benchmark (lambda () (string->djot text)) count)))
      (("djot-headings")
       (let (text (repeat "# Same\n\n" n))
         (benchmark (lambda () (djot->html (string->djot text))) count)))
      (("djot-references")
       (let (text (string-append (numbered n (lambda (k) (string-append "[a][r" k "] ")))
                                 "\n\n"
                                 (numbered n (lambda (k) (string-append "[r" k "]: /x\n")))))
         (benchmark (lambda () (djot->html (string->djot text))) count)))
      (("djot-notes")
       (let (text (string-append (numbered n (lambda (k) (string-append "x[^n" k "] ")))
                                 "\n\n"
                                 (numbered n (lambda (k) (string-append "[^n" k "]: note\n\n")))))
         (benchmark (lambda () (djot->html (string->djot text))) count)))
      (("xml-write-nested-declarations")
       (let (doc (read-xml (xml-nested-declarations-document n)))
         (benchmark (lambda () (xml->string doc)) count)))
      (("xml-write-wide-declarations")
       (let (doc (read-xml (xml-wide-declarations-document n)))
         (benchmark (lambda () (xml->string doc)) count)))
      (("xml-write-rebound-prefixes")
       (let (el (xml-rebound-prefixes-element n))
         (benchmark (lambda () (xml->string el)) count)))
      (("xml-read-attributes")
       (let (bytes (string->utf8 (xml-attributes-document n)))
         (benchmark (lambda () (read-xml bytes)) count)))
      (("xml-write-attributes")
       (let (doc (read-xml (xml-attributes-document n)))
         (benchmark (lambda () (xml->string doc)) count)))
      (("xml-read-text")
       (let (bytes (string->utf8 (xml-text-document n)))
         (benchmark (lambda () (read-xml bytes keep-space?: #t)) count)))
      (("xml-read-file")
       (call-with-temporary-file-name "markup-benchmark"
         (lambda (path)
           (call-with-output-file path
             (lambda (port) (write-string (xml-text-document n) port)))
           (benchmark (lambda () (call-with-input-file path read-xml)) count))))
      (("xml-write-writer")
       (let (doc (read-xml (xml-text-document n) keep-space?: #t))
         (benchmark (lambda () (write-xml doc (open-output-length-writer))) count)))
      (("xml-read-namespaces")
       (let (bytes (string->utf8 xml-namespaces-document))
         (benchmark (lambda ()
                      (let loop ((k 0))
                        (when (fx< k n)
                          (read-xml bytes)
                          (loop (fx+ k 1)))))
                    count)))
      (("xml-write-namespaces")
       (let (doc (read-xml xml-namespaces-document))
         (benchmark (lambda ()
                      (let loop ((k 0))
                        (when (fx< k n)
                          (xml->string doc)
                          (loop (fx+ k 1)))))
                    count)))
      (("html-read-string")
       (let (text (html-text-document n))
         (benchmark (lambda () (read-html text)) count)))
      (("html-write-elements")
       (let (doc (read-html (html-elements-document n)))
         (benchmark (lambda () (html->string doc)) count)))
      (("html-read-fragments")
       (benchmark (lambda ()
                    (let loop ((k 0))
                      (when (fx< k n)
                        (read-html-fragment "<p class=x>alpha <b>beta</b> gamma</p>")
                        (loop (fx+ k 1)))))
                  count))
      (("html-escape")
       (let (text (escape-text n))
         (benchmark (lambda () (html-escape text)) count)))
      (("tal-repeat")
       (let (lists (make-list n ["alpha" "beta <gamma>" "delta"]))
         (benchmark (lambda ()
                      (call-with-output-u8vector #u8()
                        (lambda (port)
                          (parameterize ((current-tal-output-port port))
                            (repeat-lists lists)))))
                    count)))
      (("tal-small-page")
       (benchmark (lambda ()
                    (let loop ((k 0))
                      (when (fx< k n)
                        (call-with-output-u8vector #u8()
                          (lambda (port)
                            (parameterize ((current-tal-output-port port))
                              (small-page "A <small> & static page"))))
                        (loop (fx+ k 1)))))
                  count))
      (else
       (error "Unknown mode" mode)))))
