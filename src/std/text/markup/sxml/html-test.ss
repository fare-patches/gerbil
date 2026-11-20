(export html-test)

(import :std/test :std/text/markup/sxml)

(def html-test
  (test-suite "test :std/text/markup/sxml HTML (legacy :std/text/markup/html)"
    (test-case "html->sxml parses simple HTML"
      ; plain text content
      (check (html->sxml "<p>Hello</p>") => '(*TOP* (p "Hello")))
      ; nested elements
      (check (html->sxml "<div><p>One</p><p>Two</p></div>")
             => '(*TOP* (div (p "One") (p "Two"))))
      ; void element produces empty element node
      (check (html->sxml "<br>") => '(*TOP* (br)))
      ; multiple top-level elements
      (check (html->sxml "<p>a</p><p>b</p>") => '(*TOP* (p "a") (p "b"))))

    (test-case "html->sxml preserves attributes"
      (let (doc (html->sxml "<div id=\"main\"><p class=\"hi\">text</p></div>"))
        (check (sxml-attribute-e (cadr doc) 'id) => "main")
        (check (sxml-attribute-e (car (sxml-children (cadr doc))) 'class) => "hi")))

    (test-case "sxml->html renders simple sxml"
      (check (sxml->html '(p "Hello")) => "<p>Hello</p>")
      (check (sxml->html '(div (p "One") (p "Two")))
             => "<div><p>One</p><p>Two</p></div>")
      ; void elements have no closing tag in HTML mode
      (check (sxml->html '(br)) => "<br>")
      (check (sxml->html '(img)) => "<img>"))

    (test-case "sxml->html renders attributes"
      (check (sxml->html '(a (@ (href "http://example.com")) "link"))
             => "<a href=\"http://example.com\">link</a>")
      (check (sxml->html '(input (@ (type "text") (value "x"))))
             => "<input type=\"text\" value=\"x\">"))

    (test-case "sxml->html escapes special characters in text"
      (check (sxml->html '(p "foo <bar> & baz")) => "<p>foo &lt;bar&gt; &amp; baz</p>"))

    (test-case "html-escape escapes special chars"
      (check (html-escape "<b>") => "&lt;b&gt;")
      (check (html-escape "a & b") => "a &amp; b")
      (check (html-escape "\"quoted\"") => "&quot;quoted&quot;")
      (check (html-escape "no special chars") => "no special chars")
      (check (html-escape "") => ""))

    (test-case "html-strip removes all tags"
      (check (html-strip "<p>Hello <b>world</b>!</p>") => "Hello world!")
      (check (html-strip "<div><p>a</p><p>b</p></div>") => "ab")
      (check (html-strip "no tags") => "no tags"))

    (test-case "html void tag predicate"
      (check (and (html-void-tag? 'br) #t) => #t)
      (check (and (html-void-tag? 'img) #t) => #t)
      (check (and (html-void-tag? 'input) #t) => #t)
      (check (and (html-void-tag? 'hr) #t) => #t)
      (check (and (html-void-tag? 'meta) #t) => #t)
      (check (html-void-tag? 'div) => #f)
      (check (html-void-tag? 'p) => #f)
      (check (html-void-tag? 'span) => #f)
      ; case-insensitive
      (check (and (html-void-tag? 'BR) #t) => #t)
      (check (and (html-void-tag? 'Img) #t) => #t))

    (test-case "html raw tag predicate"
      (check (and (html-raw-tag? 'script) #t) => #t)
      (check (and (html-raw-tag? 'style) #t) => #t)
      (check (html-raw-tag? 'div) => #f)
      (check (html-raw-tag? 'p) => #f))))
