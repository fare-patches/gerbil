(export tal-test)

(import :std/test
        :std/error
        :std/misc/process
        (only-in :std/io/tempfile call-with-temporary-directory)
        :std/source
        :std/text/markup/tal
        (only-in :std/text/markup/xml XMLElement XMLElement? XMLText XMLText?)
        (only-in :std/text/markup/html read-html-fragment)
        "tal/testdata/hygiene")

; define-TAL creates a top-level function that writes to current-tal-output-port.
; All define-TAL calls must be at module top-level.

(define-TAL (render-static)
  "<p>Hello, world!</p>")

(define-TAL (render-content greeting)
  "<p><span tal:content=\"greeting\">placeholder</span></p>")

(define-TAL (render-escaped markup)
  "<p tal:content=\"markup\">x</p>")

(define-TAL (render-raw markup)
  "<p tal:content=\"raw: markup\">x</p>")

(define-TAL (render-replace name)
  "<span tal:replace=\"name\">x</span>")

(define-TAL (render-when flag)
  "<p tal:condition=\"flag\">shown</p>")

(define-TAL (render-define)
  "<p tal:define=\"(x 42)\" tal:content=\"x\">y</p>")

(define-TAL (render-error)
  "<p tal:content=\"(error &quot;oops&quot;)\">x</p>")

(def (capture-tal thunk)
  (utf8->string
   (call-with-output-u8vector #u8()
     (lambda (port)
       (parameterize ((current-tal-output-port port))
         (thunk))))))


;;; Templates of the statement, fix, markup and hygiene tests below.

(define-TAL (content-value v) "<div tal:content=\"v\"> Default</div>")
(define-TAL (content-as-is v) "<div tal:content=\"as-is: v\"> Default</div>")
(define-TAL (content-raw v) "<div tal:content=\"raw: v\"> Default</div>")
(define-TAL (content-empty) "<div tal:content=\"\">x</div>")
(define-TAL (content-default-kids v)
  "<div tal:content=\"v\"><b tal:content=\"(error 'never)\">x</b> default kids</div>")
(define-TAL (replace-value v) "<p>a<span tal:replace=\"v\">x</span>b</p>")
(define-TAL (replace-raw v) "<p>a<span tal:replace=\"raw: v\">x</span>b</p>")
(define-TAL (omit-when v) "<p tal:omit-tag=\"v\">in <b>x</b></p>")
(define-TAL (omit-always) "<p tal:omit-tag=\"\">in</p>")
(define-TAL (omit-content v) "<p tal:omit-tag=\"v\" tal:content=\"'C\">in</p>")
(define-TAL (condition-omit v) "<p tal:condition=\"v\" tal:omit-tag=\"\">x</p>")
(define-TAL (define-set x y)
  "<div tal:define=\"(foo (+ x 20)) (bar (* foo y))\"><b tal:content=\"bar\"></b><i tal:define=\"set!: (bar 1)\" tal:content=\"bar\"></i><u tal:content=\"bar\"></u></div>")
(define-TAL (define-repeat items)
  "<p tal:define=\"(n (length items))\" tal:repeat=\"(i items)\" tal:content=\"(list n i)\">x</p>")
(def tal-test-global 0)
(define-TAL (define-global) "<p tal:define=\"set!: (tal-test-global 5)\">x</p>")
(define-TAL (define-order) "<p tal:define=\"(a 1) set!: (tal-test-global a) (b (+ tal-test-global 1))\" tal:content=\"b\">x</p>")
(define-TAL (switch-case item)
  "<div tal:switch=\"item\"><p tal:case=\"'foo\">foo</p><p tal:case=\"'bar\">bar</p><p tal:case=\"else:\">else</p></div>")
(define-TAL (case-outside) "<p tal:case=\"1\">outside</p>")
(define-TAL (repeat-methods seq)
  "<b tal:repeat=\"(i seq)\" tal:content=\"(list (repeat/i.index) (repeat/i.number) (repeat/i.even?) (repeat/i.odd?) (repeat/i.start?) (repeat/i.end?) (repeat/i.letter) (repeat/i.Letter) (repeat/i.roman) (repeat/i.Roman) i)\"></b>")
(define-TAL (repeat-letters n) "<b tal:repeat=\"(i (iota n))\" tal:content=\"(repeat/i.letter)\"></b>")
(define-TAL (repeat-roman n) "<b tal:repeat=\"(i (iota n))\" tal:content=\"(repeat/i.Roman)\"></b>")
(define-TAL (repeat-nested seq)
  "<b tal:repeat=\"(i seq)\"><i tal:repeat=\"(i '(z))\" tal:content=\"(list i (repeat/i.number))\"></i></b>")
(define-TAL (repeat-condition seq)
  "<div tal:repeat=\"(item seq)\"><p tal:condition=\"(repeat/item.even?)\">Even</p><p tal:condition=\"(repeat/item.odd?)\">Odd</p></div>")
(define-TAL (error-content thunk) "<ul>\n<li tal:content=\"(thunk)\">x</li>\n</ul>")
(define-TAL (error-partial thunk)
  "<p>before</p><ul><li tal:content=\"(begin (tal:write 'partial) (thunk))\">x</li></ul>")
(define-TAL (error-partial-port thunk)
  "<p>before</p><ul><li tal:content=\"(begin (write-string &quot;partial&quot; (current-tal-output-port)) (thunk))\">x</li></ul>")
(define-TAL (on-error-text thunk) "<ul tal:on-error=\"'|Got|\"><li tal:content=\"(thunk)\">x</li></ul>")
(define-TAL (on-error-ignore thunk) "<ul tal:on-error=\"ignore\"><li tal:content=\"(thunk)\">x</li></ul>")
(define-TAL (on-error-ignore-err thunk)
  "<ul tal:on-error=\"ignore: (tal:write (error-message err))\"><li tal:content=\"(thunk)\">x</li></ul>")
(define-TAL (on-error-repeat thunk)
  "<ul tal:on-error=\"as-is: '|<li>E</li>|\"><li tal:repeat=\"(i '(1 2 3))\" tal:content=\"(if (= i 2) (thunk) i)\">x</li></ul>")
(define-TAL (on-error-nested thunk)
  "<div tal:on-error=\"'outer\"><ul tal:on-error=\"'inner\"><li tal:content=\"(thunk)\">x</li></ul></div>")
(define-TAL (on-error-same thunk) "<p tal:on-error=\"'H\" tal:content=\"(thunk)\">x</p>")
(define-TAL (on-error-handler-fails) "<ul tal:on-error=\"(error 'handler)\"><b tal:content=\"(error 'x)\">x</b></ul>")
(define-TAL (on-error-raw thunk) "<ul tal:on-error=\"raw: (inner-template)\"><li tal:content=\"(thunk)\">x</li></ul>")
(define-TAL (inner-template) "<hr>")
(define-TAL (nested-raw thunk) "<div tal:content=\"raw: (thunk)\"></div>")
(define-TAL (nested-replace thunk) "<div tal:replace=\"raw: (thunk)\"></div>")
(define-TAL (attributes-link href text) "<a href=\"#\" tal:attributes=\"(href href)\" tal:content=\"text\"> text </a>")
(define-TAL (attributes-select items)
  "<select name=\"examiner\"><option tal:repeat=\"(i items)\" tal:attributes=\"(value (car i))\" tal:content=\"(cdr i)\"></option></select>")
(define-TAL (attributes-textarea (rows 80) (cols 20))
  "<textarea rows=\"0\" cols=\"0\" tal:attributes=\"(rows rows) (cols cols)\"></textarea>")
(define-TAL (attributes-values v)
  "<input type=\"text\" value=\"t&quot;\" tal:attributes=\"(value v) (data-x v)\">")
(define-TAL (attributes-omit v) "<p class=\"c\" tal:attributes=\"(class v)\" tal:omit-tag=\"(not v)\">x</p>")
(define-TAL (script-content v) "<script tal:content=\"v\">var x;</script><style tal:content=\"v\"></style>")
(define-TAL (title-content v) "<title tal:content=\"v\">t</title><textarea tal:content=\"v\">x</textarea>")
(define-TAL (block-element v) "<tal:block tal:repeat=\"(i v)\">[<b tal:content=\"i\">x</b>]</tal:block>")
(define-TAL (entity-attribute v) "<p tal:content=\"(string-append v &quot;&amp;&lt;&quot;)\">x</p>")
(define-TAL (markup-static)
  "<!-- c --><!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<p>&copy; a &amp; b &lt; &nbsp;é</p><br/><div/><input disabled value=''><?php x ?>")
(define-TAL (markup-raw-text)
  "<script>if (a < b && c) x()</script><style>p > a {}</style><title>a &amp; b</title><textarea>\n\nx</textarea><pre>\nx</pre>")
(define-TAL (markup-pre v) "<pre tal:define=\"(w v)\">\n\ny<b tal:content=\"w\">x</b></pre>")
(define-TAL (markup-svg v) "<svg viewbox=\"0 0 1 1\"><foreignobject><p tal:content=\"v\">x</p></foreignobject><circle r=\"1\"/></svg>")
(define-TAL (markup-rows rows)
  "<tr tal:repeat=\"(r rows)\"><td tal:content=\"r\">x</td></tr>")
(define-TAL (markup-implied v)
  "<ul><li>a<li tal:content=\"v\">b</li></ul><p>x<div>y</div>")
(define-TAL (markup-template v)
  "<template><style tal:content=\"v\"></style><col><p tal:content=\"v\">x</p></template><style tal:content=\"v\"></style>")
(define-TAL (markup-frameset v) "<frameset><noframes tal:content=\"v\"></noframes></frameset>")
(define-TAL (omit-allowed v)
  "<p tal:omit-tag=\"v\">a</p><div><b tal:omit-tag=\"\" tal:content=\"v\">x</b></div><svg><g tal:omit-tag=\"\"><circle/></g></svg>")
(define-TAL (noscript-raw v)
  "<noscript><style tal:content=\"v\"></style></noscript><div><noscript><b><xmp tal:content=\"v\"></xmp></b></noscript></div>")

;;; The message of the syntax error that expanding a define-TAL of template
;;; raises, or #f.
(def (template-error template)
  (with-catch
   (lambda (e) (or (error-message e) e))
   (lambda ()
     (eval `(begin (import :std/text/markup/tal)
                   (define-TAL (tal-test-template x) ,template)))
     #f)))

;;; The output of thunk, a template call, with handler as current-tal:on-error.
(def (capture-with-handler handler thunk)
  (parameterize ((current-tal:on-error handler))
    (capture-tal thunk)))

;;; hygiene.ss's results when it is compiled with gxc -O and loaded by gxi,
;;; both of the running installation, or a string saying why the test is
;;; skipped. gxc -O needs the compiled TAL modules' optimizer metadata (the
;;; templates' expansions access TAL's structs), which source-only modules
;;; over an installed Gerbil lack.
(def (compiled-hygiene-results)
  (let* ((fixture (path-expand "tal/testdata/hygiene.ss" (path-directory (this-source-file))))
         (gxc (path-expand "~~bin/gxc"))
         (gxi (path-expand "~~bin/gxi"))
         (metadata (find (lambda (dir)
                           (file-exists? (path-expand "std/text/markup/tal/runtime.ssxi.ss" dir)))
                         (load-path))))
    (cond
     ((not (and (file-exists? gxc) (file-exists? gxi)))
      (string-append "no gxc and gxi in " (path-expand "~~bin")))
     ((not metadata)
      "std/text/markup/tal/runtime.ssxi.ss (compiled TAL) is not on the load path")
     (else
      (call-with-temporary-directory "tal-hygiene-"
        (lambda (dir)
          (let (environment
                (cons* (string-append "GERBIL_PATH=" dir)
                       (string-append "GERBIL_LOADPATH=" (string-join (cons dir (load-path)) ":"))
                       (filter (lambda (binding)
                                 (not (or (string-prefix? "GERBIL_PATH=" binding)
                                          (string-prefix? "GERBIL_LOADPATH=" binding))))
                               (map (lambda (pair) (string-append (car pair) "=" (cdr pair)))
                                    (get-environment-variables)))))
            (run-process [gxc "-O" "-d" dir fixture] environment: environment
                         stderr-redirection: #t)
            (call-with-input-string
             (run-process [gxi "-e" "(import :std/text/markup/tal/testdata/hygiene) (write (hygiene-results))"]
                          environment: environment)
             read))))))))

;;; The text of the first node of HTML fragment str, as the parser reads it.
(def (fragment-text str)
  (let recur ((node (car (read-html-fragment str))))
    (cond
     ((XMLText? node)
      (using (node :- XMLText) node.data))
     ((XMLElement? node)
      (using (node :- XMLElement) (string-concatenate (map recur node.children))))
     (else ""))))

;;; The output of a template with parameter x, defined by eval, called with x.
(def (template-output template x)
  (let (render (eval `(begin (import :std/text/markup/tal)
                             (define-TAL (tal-test-template x) ,template)
                             tal-test-template)))
    (capture-tal (cut render x))))

(def hygiene-expected
  ["<div><p title=\"tal-user\"><i>(p 1)</i><i>(t 2)</i><s>tal-scoperendermarkdepthusing</s><u>%r</u><script>u8v</script>let<q>if</q><a>html-escapetal:write</a><b>&lt;y&gt;</b></p></div>"
   "<b>(MINE MINE2 MINE3 MINE4)</b>"
   "<b>E</b>"])

(def tal-test
  (test-suite "test :std/text/markup/tal"
    (test-case "static template produces literal html"
      (check (capture-tal render-static) => "<p>Hello, world!</p>"))

    (test-case "tal:content substitutes element body"
      (check (capture-tal (cut render-content "hi")) => "<p><span>hi</span></p>")
      ; numbers are stringified
      (check (capture-tal (cut render-content 42)) => "<p><span>42</span></p>"))

    (test-case "tal:content escapes html by default"
      (check (capture-tal (cut render-escaped "<b>bold</b>"))
             => "<p>&lt;b&gt;bold&lt;/b&gt;</p>"))

    (test-case "tal:content raw: skips escaping"
      (check (capture-tal (cut render-raw "<b>bold</b>"))
             => "<p><b>bold</b></p>"))

    (test-case "tal:replace replaces entire element"
      (check (capture-tal (cut render-replace "Alice")) => "Alice"))

    (test-case "tal:condition renders element only when true"
      (check (capture-tal (cut render-when #t)) => "<p>shown</p>")
      (check (capture-tal (cut render-when #f)) => ""))

    (test-case "tal:define binds local variables"
      (check (capture-tal render-define) => "<p>42</p>"))

    (test-case "current-tal:on-error catches template errors"
      (let (errors [])
        (parameterize ((current-tal:on-error
                        (lambda (e) (set! errors (cons (error-message e) errors)))))
          (let (out (capture-tal render-error))
            ; on-error handler called, not the default error output
            (check errors => '("oops"))))))

    (test-case "tal:write writes to current-tal-output-port"
      (check (capture-tal (lambda ()
                            (tal:write "hello")
                            (tal:write " ")
                            (tal:write "world")))
             => "hello world"))

    ;; statements, as legacy TAL renders them
    (test-case "tal:content values"
      (check (capture-tal (cut content-value default:)) => "<div> Default</div>")
      (check (capture-tal (cut content-value #f)) => "<div></div>")
      (check (capture-tal (cut content-value #t)) => "<div>#t</div>")
      (check (capture-tal (cut content-value 'a<b)) => "<div>a&lt;b</div>")
      (check (capture-tal (cut content-value 3.5)) => "<div>3.5</div>")
      (check (capture-tal (cut content-value '(1 "a<"))) => "<div>(1 a&lt;)</div>")
      (check (capture-tal (cut content-value (string->utf8 "<u8>"))) => "<div>#u8(60 117 56 62)</div>")
      (check (capture-tal (cut content-value "'\"")) => "<div>&#39;&quot;</div>")
      (check (capture-tal (cut content-as-is "<b>&</b>")) => "<div><b>&</b></div>")
      (check (capture-tal (cut content-as-is default:)) => "<div> Default</div>")
      (check (capture-tal (cut content-as-is 7)) => "<div>7</div>")
      (check (capture-tal (cut content-raw "<b>")) => "<div><b></div>")
      (check (capture-tal content-empty) => "<div></div>")
      (check (capture-tal (cut content-default-kids default:))
             => "<div><b>ERROR: never</b> default kids</div>"))

    (test-case "tal:replace values"
      (check (capture-tal (cut replace-value "<i>")) => "<p>a&lt;i&gt;b</p>")
      (check (capture-tal (cut replace-value #f)) => "<p>ab</p>")
      (check (capture-tal (cut replace-raw "<i>")) => "<p>a<i>b</p>"))

    (test-case "tal:omit-tag and tal:condition"
      (check (capture-tal (cut omit-when #f)) => "<p>in <b>x</b></p>")
      (check (capture-tal (cut omit-when 1)) => "in <b>x</b>")
      (check (capture-tal omit-always) => "in")
      (check (capture-tal (cut omit-content #t)) => "C")
      (check (capture-tal (cut omit-content #f)) => "<p>C</p>")
      (check (capture-tal (cut condition-omit #t)) => "x")
      ;; a conditional tal:omit-tag compiles its content once, not once per
      ;; outcome: 14 levels used to take a minute
      (let* ((depth 14)
             (template (string-append
                        (apply string-append (make-list depth "<b tal:omit-tag=\"x\">"))
                        "y"
                        (apply string-append (make-list depth "</b>")))))
        (check (template-output template #t) => "y")
        (check (template-output template #f)
               => (string-append (apply string-append (make-list depth "<b>")) "y"
                                 (apply string-append (make-list depth "</b>"))))))

    (test-case "tal:define binds in order and set!: assigns"
      (check (capture-tal (cut define-set 1 2)) => "<div><b>42</b><i>1</i><u>1</u></div>")
      (check (capture-tal (cut define-repeat '(a b))) => "<p>(2 a)</p><p>(2 b)</p>")
      (capture-tal define-global)
      (check tal-test-global => 5)
      (check (capture-tal define-order) => "<p>2</p>")
      (check tal-test-global => 1))

    (test-case "tal:switch and tal:case"
      (check (capture-tal (cut switch-case 'foo)) => "<div><p>foo</p></div>")
      (check (capture-tal (cut switch-case 'bar)) => "<div><p>bar</p></div>")
      (check (capture-tal (cut switch-case 'zz)) => "<div><p>else</p></div>")
      (check (capture-tal case-outside) => ""))

    (test-case "tal:repeat and its repeat variable"
      (check (capture-tal (cut repeat-methods '(x y)))
             => "<b>(0 1 #t #f #t #f a A i I x)</b><b>(1 2 #f #t #f #t b B ii II y)</b>")
      (check (capture-tal (cut repeat-methods #(1))) => "<b>(0 1 #t #f #t #t a A i I 1)</b>")
      (check (capture-tal (cut repeat-methods '())) => "")
      (check (capture-tal (cut repeat-methods (let (h (make-hash-table)) (hash-put! h 'k 'v) h)))
             => "<b>(0 1 #t #f #t #t a A i I (k . v))</b>")
      (check (capture-tal (cut repeat-nested '(1 2))) => "<b><i>(z 1)</i></b><b><i>(z 1)</i></b>")
      (check (capture-tal (cut repeat-condition '(a s d)))
             => "<div><p>Even</p></div><div><p>Odd</p></div><div><p>Even</p></div>")
      (check (capture-tal (cut repeat-roman 4)) => "<b>I</b><b>II</b><b>III</b><b>IV</b>")
      ;; methods are bound whatever the spelling that refers to them
      (check (template-output "<b tal:repeat=\"(i x)\" tal:content=\"(|repeat/i.number|)\"></b>" '(a b))
             => "<b>1</b><b>2</b>"))

    (test-case "errors: default handler, discarded output, tal:on-error"
      (check (capture-tal (cut error-content (cut error "msg <x>" 'irr)))
             => "<ul>\n<li>ERROR: msg &lt;x&gt;</li>\n</ul>")
      (check (capture-tal (cut error-content (cut raise 'sym)))
             => "<ul>\n<li>ERROR: This object was raised: sym\n</li>\n</ul>")
      (check (capture-tal (cut error-partial (cut error "e5")))
             => "<p>before</p><ul><li>ERROR: e5</li></ul>")
      (check (capture-tal (cut error-partial-port (cut error "e5")))
             => "<p>before</p><ul><li>ERROR: e5</li></ul>")
      (check (capture-tal (cut error-partial-port (lambda () "ok")))
             => "<p>before</p><ul><li>partialok</li></ul>")
      (check (capture-tal (cut on-error-text (cut error "e"))) => "<ul>Got</ul>")
      (check (capture-tal (cut on-error-text (lambda () "fine"))) => "<ul><li>fine</li></ul>")
      (check (capture-tal (cut on-error-ignore (cut error "e"))) => "")
      (check (capture-tal (cut on-error-ignore-err (cut error "e4msg"))) => "e4msg")
      (check (capture-tal (cut on-error-repeat (cut error "e6"))) => "<ul><li>E</li></ul>")
      (check (capture-tal (cut on-error-nested (cut error "e7"))) => "<div><ul>inner</ul></div>")
      (check (capture-tal (cut on-error-same (cut error "e8"))) => "<p>H</p>")
      (check (capture-tal on-error-handler-fails) => "<ul>ERROR: handler</ul>")
      (check (capture-tal (cut on-error-raw (cut error "e"))) => "<ul><hr></ul>")
      (check (capture-with-handler (lambda (e) (tal:write "Nothing wrong here!"))
                                   (cut error-content (cut error "x")))
             => "<ul>\n<li>Nothing wrong here!</li>\n</ul>"))

    (test-case "templates nest through the output port"
      (check (capture-tal (cut nested-raw inner-template)) => "<div><hr></div>")
      (check (capture-tal (cut nested-replace inner-template)) => "<hr>")
      (check (capture-tal (cut nested-raw (lambda () (inner-template) (inner-template))))
             => "<div><hr><hr></div>"))

    ;; legacy bugs, fixed to the documented semantics
    (test-case "fixed: replace default:, raw:, as-is: #f"
      (check (capture-tal (cut replace-value default:)) => "<p>a<span>x</span>b</p>")
      (check (capture-tal (cut content-raw default:)) => "<div></div>")
      (check (capture-tal (cut content-raw #f)) => "<div></div>")
      (check (capture-tal (cut content-as-is #f)) => "<div></div>"))

    (test-case "fixed: repeat over strings, letter and Letter"
      (check (capture-tal (cut repeat-methods "ab"))
             => "<b>(0 1 #t #f #t #f a A i I a)</b><b>(1 2 #f #t #f #t b B ii II b)</b>")
      (check (capture-tal (cut repeat-letters 28))
             => (string-append (apply string-append
                                      (map (lambda (c) (string-append "<b>" (string c) "</b>"))
                                           (string->list "abcdefghijklmnopqrstuvwxyz")))
                               "<b>aa</b><b>ab</b>")))

    (test-case "fixed: tal:attributes"
      (check (capture-tal (cut attributes-link "https://duckduckgo.com" "Search"))
             => "<a href=\"https://duckduckgo.com\">Search</a>")
      (check (capture-tal (cut attributes-link #f "No Anchor!")) => "<a>No Anchor!</a>")
      (check (capture-tal (cut attributes-select [[1 . "President"] [2 . "Vice"]]))
             => "<select name=\"examiner\"><option value=\"1\">President</option><option value=\"2\">Vice</option></select>")
      (check (capture-tal attributes-textarea) => "<textarea rows=\"80\" cols=\"20\"></textarea>")
      (check (capture-tal (cut attributes-textarea 10 42)) => "<textarea rows=\"10\" cols=\"42\"></textarea>")
      (check (capture-tal (cut attributes-values "a\"<&"))
             => "<input type=\"text\" value=\"a&quot;&lt;&amp;\" data-x=\"a&quot;&lt;&amp;\">")
      (check (capture-tal (cut attributes-values default:)) => "<input type=\"text\" value=\"t&quot;\">")
      (check (capture-tal (cut attributes-values #t)) => "<input type=\"text\" value=\"\" data-x=\"\">")
      (check (capture-tal (cut attributes-values #f)) => "<input type=\"text\">")
      (check (capture-tal (cut attributes-omit "d")) => "<p class=\"d\">x</p>")
      (check (capture-tal (cut attributes-omit #f)) => "x")
      ;; 500 attributes, the even ones replaced in place, case folded, the
      ;; first of two settings winning; then two new ones, in order
      (let* ((names (map (lambda (k) (string-append "a" (number->string k))) (iota 500)))
             (evens (filter (lambda (name) (even? (string->number (substring name 1 (string-length name)))))
                            names))
             (attributes (lambda (value)
                           (string-concatenate
                            (map (lambda (name)
                                   (string-append " " name "=\""
                                                  (if (member name evens) value "s") "\""))
                                 names)))))
        (check (template-output
                (string-append "<b" (attributes "s") " tal:attributes=\""
                               (string-concatenate
                                (map (lambda (name) (string-append "(" (string-upcase name) " x) "))
                                     evens))
                               "(a0 'no) (n1 x) (n2 x)\">y</b>")
                "v")
               => (string-append "<b" (attributes "v") " n1=\"v\" n2=\"v\">y</b>"))))

    (test-case "tal:attributes on SVG elements get the parser's names"
      (check (template-output "<svg viewBox=\"0 0 1 1\" tal:attributes=\"(viewbox x)\"></svg>" "v")
             => "<svg viewBox=\"v\"></svg>")
      (check (template-output "<svg><a xlink:href=\"#\" tal:attributes=\"(xlink:href x)\"></a></svg>" "u")
             => "<svg><a xlink:href=\"u\"></a></svg>"))

    (test-case "fixed: content in script and style is checked raw text"
      (check (capture-tal (cut script-content "a<b && c"))
             => "<script>a<b && c</script><style>a<b && c</style>")
      (check (capture-tal (cut script-content "x</script>y"))
             => "<script>ERROR: text would end &lt;script&gt; early</script><style>x</script>y</style>")
      (check (capture-tal (cut script-content "x</STYLE y"))
             => "<script>x</STYLE y</script><style>ERROR: text would end &lt;style&gt; early</style>")
      ;; as-is: is checked there too, as write-html checks HTMLRaw
      (let (script-as-is "<script tal:content=\"as-is: x\"></script><style tal:content=\"as-is: x\"></style>")
        (check (template-output script-as-is "a<b && c")
               => "<script>a<b && c</script><style>a<b && c</style>")
        (check (template-output script-as-is (string->utf8 "\xe9;<"))
               => "<script>\xe9;<</script><style>\xe9;<</style>")
        (check (template-output script-as-is "</script><img src=x onerror=alert(1)>")
               => "<script>ERROR: text would end &lt;script&gt; early</script><style></script><img src=x onerror=alert(1)></style>")
        (check (template-output script-as-is (string->utf8 "</script><img src=x onerror=alert(1)>"))
               => "<script>ERROR: text would end &lt;script&gt; early</script><style></script><img src=x onerror=alert(1)></style>")
        (check (template-output script-as-is "</STYLE><img src=x onerror=alert(1)>")
               => "<script></STYLE><img src=x onerror=alert(1)></script><style>ERROR: text would end &lt;style&gt; early</style>")
        (check (string-prefix? "<script>ERROR: " (template-output script-as-is (u8vector 97 #xff)))
               => #t)
        (check (template-output "<noscript><style tal:content=\"as-is: x\"></style></noscript>"
                                "</noscript><img src=x onerror=alert(1)>")
               => "<noscript><style>ERROR: text would end &lt;noscript&gt; early</style></noscript>"))
      (check (capture-tal (cut title-content "a<&"))
             => "<title>a&lt;&amp;</title><textarea>\na&lt;&amp;</textarea>"))

    (test-case "fixed: <tal:...> elements are omitted"
      (check (capture-tal (cut block-element '(1 2))) => "[<b>1</b>][<b>2</b>]"))

    ;; markup
    (test-case "markup is written by the HTML writer"
      (check (capture-tal (cut entity-attribute "a")) => "<p>a&amp;&lt;</p>")
      (check (capture-tal markup-static)
             => "<!-- c --><!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<p>© a &amp; b &lt; \xa0;é</p><br><div></div><input disabled=\"\" value=\"\"><?php x ?>")
      (check (capture-tal markup-raw-text)
             => "<script>if (a < b && c) x()</script><style>p > a {}</style><title>a &amp; b</title><textarea>\n\nx</textarea><pre>x</pre>")
      (check (capture-tal (cut markup-pre "v")) => "<pre>\n\ny<b>v</b></pre>")
      (check (capture-tal (cut markup-svg "v"))
             => "<svg viewBox=\"0 0 1 1\"><foreignObject><p>v</p></foreignObject><circle r=\"1\"></circle></svg>")
      (check (capture-tal (cut markup-rows '(1 2))) => "<tr><td>1</td></tr><tr><td>2</td></tr>")
      (check (capture-tal (cut markup-implied "v")) => "<ul><li>a</li><li>v</li></ul><p>x</p><div>y</div>"))

    (test-case "the writer's frameset, template and noscript rules apply to TAL elements"
      (check (capture-tal (cut markup-template "a<b"))
             => "<template><style>a<b</style><col><p>a&lt;b</p></template><style>a<b</style>")
      (check (capture-tal (cut markup-frameset "a<b")) => "<frameset><noframes>a<b</noframes></frameset>")
      (check (template-error "<frameset><style tal:content=\"x\"></style></frameset>")
             => "<template>:1:11: cannot be written as HTML: expected no raw text element in or after a frameset, or after col in a template, got style")
      (check (template-error "<frameset tal:condition=\"x\"></frameset><style tal:content=\"x\"></style>")
             => "<template>:1:40: cannot be written as HTML: expected no raw text element in or after a frameset, or after col in a template, got style")
      (check (template-error "<template><tal:block><col></tal:block><style tal:content=\"x\"></style></template>")
             => "<template>:1:39: cannot be written as HTML: expected no raw text element in or after a frameset, or after col in a template, got style")
      (check (template-error "<template><col><template tal:omit-tag=\"x\"><style tal:content=\"x\"></style></template></template>")
             => "<template>:1:43: cannot be written as HTML: expected no raw text element in or after a frameset, or after col in a template, got style")
      (check (template-error "<template><template tal:omit-tag=\"x\"><tal:block><col></tal:block></template><style tal:content=\"x\"></style></template>")
             => "<template>:1:77: cannot be written as HTML: expected no raw text element in or after a frameset, or after col in a template, got style")
      (check (template-error "<template><col><template><style tal:content=\"x\"></style></template></template>") => #f)
      (check (template-error "<noscript><noscript tal:content=\"x\"></noscript></noscript>")
             => "<template>:1:11: cannot be written as HTML: expected no noscript inside noscript, got noscript"))

    (test-case "tal:omit-tag cannot move content into another context"
      (def omit-message "tal:omit-tag cannot leave out these tags, without which the content is read in another context")
      (check (capture-tal (cut omit-allowed "t")) => "a<div>t</div><svg><circle></circle></svg>")
      (check (template-error "<div><script tal:omit-tag=\"\" tal:content=\"x\"></script></div>")
             => (string-append "<template>:1:6: <script>: " omit-message))
      (check (template-error "<style tal:omit-tag=\"(not x)\" tal:content=\"x\"></style>")
             => (string-append "<template>:1:1: <style>: " omit-message))
      (check (template-error "<xmp tal:omit-tag=\"\" tal:on-error=\"x\" tal:content=\"(error 'e)\"></xmp>")
             => (string-append "<template>:1:1: <xmp>: " omit-message))
      (check (template-error "<svg><foreignObject tal:omit-tag=\"\"><style tal:content=\"x\"></style></foreignObject></svg>")
             => (string-append "<template>:1:6: <foreignObject>: " omit-message))
      (check (template-error "<math><mi tal:omit-tag=\"\"><style tal:content=\"x\"></style></mi></math>")
             => (string-append "<template>:1:7: <mi>: " omit-message)))

    (test-case "raw text inside noscript cannot end it"
      (check (capture-tal (cut noscript-raw "a</b>"))
             => "<noscript><style>a</b></style></noscript><div><noscript><b><xmp>a</b></xmp></b></noscript></div>")
      (check (capture-tal (cut noscript-raw "</NOSCRIPT><img src=x onerror=alert(1)>"))
             => "<noscript><style>ERROR: text would end &lt;noscript&gt; early</style></noscript><div><noscript><b><xmp>ERROR: text would end &lt;noscript&gt; early</xmp></b></noscript></div>"))

    (test-case "dynamic content after a pre, listing or textarea start tag keeps its first LF"
      ;; each: template, x, output, the text the parser reads from it
      (for-each
        (match <>
          ([template x output text]
           (let (result (template-output template x))
             (check result => output)
             (check (fragment-text result) => text))))
        [["<pre tal:content=\"x\">y</pre>" "\nA" "<pre>\n\nA</pre>" "\nA"]
         ["<pre tal:content=\"x\">y</pre>" "A" "<pre>\nA</pre>" "A"]
         ["<textarea tal:content=\"x\">y</textarea>" "\nA" "<textarea>\n\nA</textarea>" "\nA"]
         ["<listing tal:content=\"as-is: x\">y</listing>" "\nA" "<listing>\n\nA</listing>" "\nA"]
         ["<pre><span tal:replace=\"x\">y</span>z</pre>" "\nA" "<pre>\n\nAz</pre>" "\nAz"]
         ["<pre tal:on-error=\"x\" tal:replace=\"(error 'e)\">y</pre>" "\nA" "<pre>\n\nA</pre>" "\nA"]
         ["<div><pre tal:omit-tag=\"x\">\n\nabc</pre></div>" #f "<div><pre>\n\nabc</pre></div>" "\nabc"]
         ["<div><pre tal:omit-tag=\"x\">\n\nabc</pre></div>" #t "<div>\nabc</div>" "\nabc"]
         ["<div><pre tal:omit-tag=\"x\"><b tal:replace=\"x\"></b></pre></div>" "\nA" "<div>\nA</div>" "\nA"]
         ["<pre><b tal:omit-tag=\"\" tal:content=\"x\">y</b></pre>" "\nA" "<pre>\n\nA</pre>" "\nA"]
         ["<listing><tal:block tal:content=\"x\">y</tal:block></listing>" "\nA" "<listing>\n\nA</listing>" "\nA"]
         ["<pre><b tal:condition=\"x\">y</b>\nfoo</pre>" #f "<pre>\n\nfoo</pre>" "\nfoo"]
         ["<pre><b tal:condition=\"x\">y</b>\nfoo</pre>" #t "<pre>\n<b>y</b>\nfoo</pre>" "y\nfoo"]
         ["<textarea tal:content=\"x\">\n\ny</textarea>" default: "<textarea>\n\ny</textarea>" "\ny"]
         ["<pre tal:content=\"x\"><b tal:content=\"'B\"></b></pre>" default: "<pre>\n<b>B</b></pre>" "B"]
         ["<pre tal:attributes=\"(title x)\">y</pre>" "t" "<pre title=\"t\">y</pre>" "y"]
         ["<pre tal:attributes=\"(title x)\">\n\ny</pre>" "t" "<pre title=\"t\">\n\ny</pre>" "\ny"]]))

    (test-case "start tags that end an open p end it if its end tag may be left out"
      (def (p-error tag column)
        (string-append "<template>:1:" (number->string column) ": <" tag "> inside an open <p>,"
                       " which the parser ends here; close the <p> first"))
      ;; every start tag the parser ends a p in button scope on
      (for-each (lambda (tag)
                  (check (template-error (string-append "<p><b><" tag ">")) => (p-error tag 7)))
                ["address" "article" "aside" "blockquote" "center" "details" "dialog" "dir"
                 "div" "dl" "fieldset" "figcaption" "figure" "footer" "form" "h1" "h2" "h3"
                 "h4" "h5" "h6" "header" "hgroup" "hr" "li" "dd" "dt" "listing" "main" "menu"
                 "nav" "ol" "p" "pre" "search" "section" "summary" "table" "ul" "xmp"])
      ;; the end tag of a p without tal: may be left out before them, as
      ;; the parser ends the p there
      (check (template-output "<p>x<div>y</div>" #f) => "<p>x</p><div>y</div>")
      (check (template-output "<ul><li>a<p>b<li>c</ul>" #f) => "<ul><li>a<p>b</p></li><li>c</li></ul>")
      (check (template-output "<div><p>a<center>b</center></div>" #f)
             => "<div><p>a</p><center>b</center></div>")
      (check (template-output "<dl><dt><p>a<dd>b</dl>" #f) => "<dl><dt><p>a</p></dt><dd>b</dd></dl>")
      ;; that of a p with tal: may not
      (check (template-error "<div><p tal:condition=\"x\"><xmp>y</xmp></p></div>")
             => "<template>:1:6: <p> with tal: attributes needs an explicit </p>")
      (check (template-error "<p tal:condition=\"x\">a<center>b</center></p>")
             => "<template>:1:1: <p> with tal: attributes needs an explicit </p>")
      ;; others stay inside, as do all inside an element that bounds button
      ;; scope
      (for-each (lambda (template)
                  (check (template-output template #f) => template))
                ["<p><b>x</b><span>y</span><a>z</a><img><input><select></select><textarea></textarea></p>"
                 "<p><button><div>x</div></button></p>"
                 "<p><object><div>x</div></object></p>"
                 "<p><svg><foreignObject><div>x</div></foreignObject></svg></p>"
                 "<p><math><mi><ul><li>x</li></ul></mi></math></p>"]))

    (test-case "start tags that end a colgroup end it, but col and template"
      ;; the tree builder reads template in a colgroup with the in head rules
      (for-each (lambda (template)
                  (check (template-output template #f) => template))
                ["<table><colgroup><template><col></template></colgroup></table>"
                 "<table><colgroup><col><col></colgroup></table>"])
      (check (template-output "<table><colgroup><col><tbody><tr><td>x</td></tr></tbody></table>" #f)
             => "<table><colgroup><col></colgroup><tbody><tr><td>x</td></tr></tbody></table>"))

    (test-case "rb and rtc start tags end an open rtc; rt and rp stay inside it"
      (check (template-output "<ruby>a<rtc>b<rb>c<rtc>d<rt>e<rp>f</ruby>" #f)
             => "<ruby>a<rtc>b</rtc><rb>c</rb><rtc>d<rt>e</rt><rp>f</rp></rtc></ruby>"))

    (test-case "CDATA sections are read where the current element is foreign"
      (def (cdata-output open close)
        (template-output (string-append open "<![CDATA[a<b]]>" close) #f))
      (check (cdata-output "<svg><foreignObject>" "</foreignObject></svg>")
             => "<svg><foreignObject>a&lt;b</foreignObject></svg>")
      (check (cdata-output "<svg><desc>" "</desc></svg>") => "<svg><desc>a&lt;b</desc></svg>")
      (check (cdata-output "<svg><title>" "</title></svg>") => "<svg><title>a&lt;b</title></svg>")
      (for-each (lambda (local)
                  (check (cdata-output (string-append "<math><" local ">")
                                       (string-append "</" local "></math>"))
                         => (string-append "<math><" local ">a&lt;b</" local "></math>")))
                ["mi" "mo" "mn" "ms" "mtext"])
      (check (cdata-output "<math><annotation-xml>" "</annotation-xml></math>")
             => "<math><annotation-xml>a&lt;b</annotation-xml></math>")
      (check (cdata-output "<math><annotation-xml encoding=\"text/html\">" "</annotation-xml></math>")
             => "<math><annotation-xml encoding=\"text/html\">a&lt;b</annotation-xml></math>")
      ;; p is HTML: a bogus comment, as the parser reads it
      (check (cdata-output "<svg><foreignObject><p>" "</p></foreignObject></svg>")
             => "<svg><foreignObject><p><!--[CDATA[a<b]]--></p></foreignObject></svg>")
      (check (cdata-output "<p>" "</p>") => "<p><!--[CDATA[a<b]]--></p>"))

    (test-case "li, dd and dt start tags inside an open li, dd or dt that the parser ends"
      (def (item-error tag open column)
        (string-append "<template>:1:" (number->string column) ": <" tag "> inside an open <" open
                       ">, which the parser ends here with the elements inside it; close them first"))
      (check (template-error "<ul><li><div><p>x<li>y</div></ul>") => (item-error "li" "li" 18))
      (check (template-error "<ul><li><span><li>y</span></ul>") => (item-error "li" "li" 15))
      (check (template-error "<dl><dt><address>a<dd>b</address></dl>") => (item-error "dd" "dt" 19))
      (check (template-error "<dl><dd><div>a<dt>b</div></dl>") => (item-error "dt" "dd" 15))
      ;; a current item ends by implication; special elements stop the steps
      (for-each (lambda (template)
                  (check (template-output template #f) => template))
                ["<ul><li><ul><li>x</li></ul></li></ul>"
                 "<ul><li><button><li>x</li></button></li></ul>"
                 "<dl><dt><object><dd>x</dd></object></dt></dl>"])
      (check (template-output "<ul><li>a<li>b</ul>" #f) => "<ul><li>a</li><li>b</li></ul>")
      (check (template-output "<dl><dt>a<dd>b<dt>c</dl>" #f) => "<dl><dt>a</dt><dd>b</dd><dt>c</dt></dl>"))

    (test-case "deeply nested elements keep the open p and list item rules"
      (def (nested open close inner)
        (string-append (string-concatenate (make-list 500 open)) inner
                       (string-concatenate (make-list 500 close))))
      (for-each (lambda (template)
                  (check (template-output template #f) => template))
                [(nested "<span>" "</span>" "x")
                 (nested "<div>" "</div>" "x")
                 (string-append "<p>" (nested "<span>" "</span>" "x") "</p>")
                 (string-append "<ul><li>" (nested "<div>" "</div>" "x") "</li></ul>")
                 (string-append "<ul><li>" (nested "<section>" "</section>" "<li>x</li>")
                                "</li></ul>")])
      (check (template-error (string-append "<p>" (nested "<span>" "</span>" "<div>")))
             => (string-append "<template>:1:3004: <div> inside an open <p>, which the parser"
                               " ends here; close the <p> first"))
      (check (template-error (string-append "<ul><li>" (nested "<div>" "</div>" "<li>")))
             => (string-append "<template>:1:2509: <li> inside an open <li>, which the parser"
                               " ends here with the elements inside it; close them first")))

    (test-case "deeply nested elements around a dynamic one compile"
      (def (nested open close inner)
        (string-append (string-concatenate (make-list 500 open)) inner
                       (string-concatenate (make-list 500 close))))
      (check (template-output (nested "<span>" "</span>" "<b tal:content=\"x\">x</b>") "hi")
             => (nested "<span>" "</span>" "<b>hi</b>"))
      ;; the static elements beside the dynamic path are written as they are
      (check (template-output (nested "<div><i>s</i>" "<b>t</b></div>" "<b tal:replace=\"x\">x</b>")
                              "&")
             => (nested "<div><i>s</i>" "<b>t</b></div>" "&amp;"))
      (check (template-output (nested "<span>" "</span>"
                                      "<tal:block tal:content=\"x\">x</tal:block>")
                              "y")
             => (nested "<span>" "</span>" "y"))
      (check (template-output (nested "<div title=\"t\"><span>" "</span></div>"
                                      "<i tal:attributes=\"(title x)\">x</i>")
                              "z")
             => (nested "<div title=\"t\"><span>" "</span></div>" "<i title=\"z\">x</i>")))

    (test-case "start tags that end SVG and MathML content are errors"
      (check (template-error "<svg><p>x</p></svg>")
             => (string-append "<template>:1:6: <p> inside <svg>, where the parser ends SVG and"
                               " MathML content; close the SVG or MathML element first"))
      (check (template-error "<math><mrow><div>x</div></mrow></math>")
             => (string-append "<template>:1:13: <div> inside <mrow>, where the parser ends SVG and"
                               " MathML content; close the SVG or MathML element first"))
      (check (template-error "<svg><font color=\"red\"></font></svg>")
             => (string-append "<template>:1:6: <font> inside <svg>, where the parser ends SVG and"
                               " MathML content; close the SVG or MathML element first"))
      ;; font without color, face or size, and integration points, stay
      (for-each (lambda (template)
                  (check (template-output template #f) => template))
                ["<svg><font></font></svg>"
                 "<svg><foreignObject><p>x</p></foreignObject></svg>"
                 "<math><mi><div>x</div></mi></math>"]))

    (test-case "template errors are syntax errors at path:line:column"
      (check (template-error "<b><i>x</b></i>") => "<template>:1:8: open <i> does not match </b>")
      (check (template-error "<p>\n</div>") => "<template>:2:1: </div> has no open <div>")
      ;; CR LF and CR end lines too; columns count characters, not bytes
      (check (template-error "<p>\r\n</div>") => "<template>:2:1: </div> has no open <div>")
      (check (template-error "<p>\r\r</div>") => "<template>:3:1: </div> has no open <div>")
      (check (template-error "<p>\xe9;\x1f600;</div>") => "<template>:1:6: </div> has no open <div>")
      (check (template-error "<hr></hr>") => "<template>:1:5: </hr>: <hr> is a void element, without end tag")
      (check (template-error "<ul><li tal:content=\"x\">a<li>b</ul>")
             => "<template>:1:5: <li> with tal: attributes needs an explicit </li>")
      (check (template-error "<div>\n  <p>x") => "<template>:1:1: unclosed <div>")
      (check (template-error "<p tal:foo=\"1\">x</p>") => "<template>:1:1: <p>: unknown TAL attribute tal:foo")
      (check (template-error "<p tal:content=\"x\" tal:replace=\"x\">x</p>")
             => "<template>:1:1: <p>: tal:content and tal:replace together")
      (check (template-error "<br tal:content=\"x\">")
             => "<template>:1:1: <br> is a void element: tal:content cannot give it content")
      (check (template-error "<p>\n  <b tal:content=\"(x\">x</b></p>")
             => "<template>:2:3: tal:content: cannot read \"(x\": syntax error")
      (check (template-error "<p tal:content=\"bogus: x\">x</p>")
             => "<template>:1:1: tal:content: unknown type bogus:")
      (check (template-error "<p tal:repeat=\"x\">x</p>")
             => "<template>:1:1: tal:repeat: expected (name expression)")
      (check (template-error "<p tal:attributes=\"(tal:x 1)\">x</p>")
             => "<template>:1:1: tal:attributes: cannot set tal:x")
      (check (template-error "<p tal:attributes=\"(TAL:x 1)\">x</p>")
             => "<template>:1:1: tal:attributes: cannot set tal:x")
      (check (template-error "<math><annotation-xml tal:attributes=\"(encoding x)\"><mi>y</mi></annotation-xml></math>")
             => "<template>:1:7: tal:attributes: cannot set encoding of <annotation-xml>")
      (check (template-error "<math><annotation-xml tal:attributes=\"(Encoding x)\"><mi>y</mi></annotation-xml></math>")
             => "<template>:1:7: tal:attributes: cannot set encoding of <annotation-xml>")
      (check (template-error "<math><annotation-xml encoding=\"text/html\" tal:attributes=\"(title x)\"><p>y</p></annotation-xml></math>")
             => #f)
      (check (template-error "<plaintext>x")
             => "<template>:1:1: <plaintext> cannot be in a template: the parser reads all that follows as its text")
      (check (template-error "<div>\n<plaintext tal:content=\"x\"></plaintext></div>")
             => "<template>:2:1: <plaintext> cannot be in a template: the parser reads all that follows as its text")
      (check (template-error "<p tal:attributes=\"(a=b 1)\">x</p>")
             => "<template>:1:1: cannot be written as HTML: expected HTML attribute name, got a=b")
      (check (template-error "<p>x</p><!DOCTYPE html>") => "<template>:1:9: DOCTYPE after elements or text")
      (check (template-error "<p tal:content=\"x\">a</p><b") => "<template>:1:25: unterminated markup at the end of the template")
      (check (template-error "<p tal:content=\"x>a</p>") => "<template>:1:1: unterminated markup at the end of the template")
      (check (template-error "<b repeat/i.number=1 tal:content=\"x\">x</b>") => #f)
      ;; legacy bound i.repeat too; at top level it is an unbound global
      (check (let (output (capture-tal
                           (eval '(begin (import :std/text/markup/tal)
                                         (define-TAL (tal-test-hidden)
                                           "<b tal:repeat=\"(i '(1))\" tal:content=\"i.repeat\">x</b>")
                                         tal-test-hidden))))
               (string-prefix? "<b>ERROR: Unbound variable: i.repeat" output))
             => #t))

    (test-case "templates do not capture user names, nor user names TAL's (source)"
      (check (hygiene-results) => hygiene-expected))

    (test-case "templates do not capture user names, nor user names TAL's (compiled with gxc -O)"
      (let (results (compiled-hygiene-results))
        (if (string? results)
          (displayln "skipped: " results)
          (check results => hygiene-expected))))))
