(export sxml-test)

(import :std/test :std/text/markup/sxml)

(def sample-doc
  '(*TOP*
    (html
     (head (title "Test"))
     (body
      (div (@ (id "main") (class "container"))
           (p "First paragraph")
           (p (@ (class "special")) "Second paragraph"))
      (footer "Footer text")))))

(def sxml-test
  (test-suite "test :std/text/markup/sxml"
    (test-case "converting elements from sxml to html"
      ; normal elements with children include a closing tag
      (check-output (write-sxml
        '(*TOP*
          (div
            (p "I'm paragraph one")
            (p "I'm paragraph two"))) port: (current-output-port)
	    xml?: #f)
        "<div><p>I'm paragraph one</p><p>I'm paragraph two</p></div>")

      ; void elements must never include a closing tag
      (check-output (write-sxml
        '(*TOP*
          (area)
          (base)
          (br)
          (col)
          (embed)
          (hr)
          (img)
          (input)
          (link)
          (meta)
          (track)
          (wbr)) port: (current-output-port) xml?: #f)
        "<area><base><br><col><embed><hr><img><input><link><meta><track><wbr>"))

    (test-case "write-sxml xml mode"
      ; void elements in XML mode are self-closing
      (check-output (write-sxml '(*TOP* (br) (hr)) port: (current-output-port) xml?: #t)
                    "<br /><hr />")
      ; *COMMENT* special tag
      (check-output (write-sxml '(*COMMENT* " hello ") port: (current-output-port) xml?: #t)
                    "<!-- hello -->")
      ; *CDATA* special tag
      (check-output (write-sxml '(*CDATA* "raw & data") port: (current-output-port) xml?: #t)
                    "<![CDATA[raw & data]]>")
      ; *TOP* unwraps its children
      (check-output (write-sxml '(*TOP* (a) (b)) port: (current-output-port) xml?: #t)
                    "<a></a><b></b>"))

    (test-case "write-sxml attributes"
      (check-output (write-sxml '(a (@ (href "http://example.com") (class "link")) "click")
                                port: (current-output-port) xml?: #f)
                    "<a href=\"http://example.com\" class=\"link\">click</a>")
      ; atoms are escaped
      (check-output (write-sxml '(p "foo <bar> & baz") port: (current-output-port) xml?: #f)
                    "<p>foo &lt;bar&gt; &amp; baz</p>"))

    (test-case "attribute symbols preserve the same literal names as strings"
      (for-each
       (lambda ((name : :string)) => :void
         (for-each
          (lambda ((xml? : :boolean)) => :void
            (check-output
             (write-sxml-attribute [name "v"] port: (current-output-port) xml?: xml?)
             (string-append name "=\"v\""))
            (check-output
             (write-sxml-attribute [(string->symbol name) "v"] port: (current-output-port) xml?: xml?)
             (string-append name "=\"v\"")))
          [#f #t]))
       ["123" "a:" "data-Custom"]))

    (test-case "attribute values retain escaping and boolean policies"
      (check-output
       (write-sxml-attribute '(title "<&>\"'") port: (current-output-port))
       "title=\"&lt;&amp;&gt;&quot;'\"")
      (check-output
       (write-sxml-attribute '(title "<&>\"'") port: (current-output-port) quote-char: #\')
       "title='&lt;&amp;&gt;\"&apos;'")
      (check-output
       (write-sxml-attribute '(disabled) port: (current-output-port) xml?: #f)
       "disabled")
      (check-output
       (write-sxml-attribute 'disabled port: (current-output-port) xml?: #f)
       "disabled")
      (check-output
       (write-sxml-attribute '(disabled #t) port: (current-output-port) xml?: #f)
       "disabled=\"#t\"")
      (check-output
       (write-sxml-attribute '(disabled #f) port: (current-output-port) xml?: #f)
       "")
      (check-output
       (write-sxml-attribute #f port: (current-output-port) xml?: #f)
       "")
      (check-exception (write-sxml-attribute '(disabled) xml?: #t) error?))

    (test-case "sxml-inf node inspection"
      (check (sxml-e '(p "text")) => 'p)
      (check (sxml-e "string-node") => '*TEXT*)
      (check (sxml-e #f) => #f)

      (check (sxml-attributes '(div (@ (id "x") (class "y")) "body")) => '((id "x") (class "y")))
      (check (sxml-attributes '(div "no attrs")) => #f)

      (check (sxml-attribute-e '(div (@ (id "main")) "body") 'id) => "main")
      (check (sxml-attribute-e '(div (@ (id "main")) "body") 'class) => #f)
      (check (sxml-attribute-e '(div "no attrs") 'id) => #f)

      (check (sxml-children '(div (p "one") (p "two"))) => '((p "one") (p "two")))
      (check (sxml-children '(div (@ (id "x")) (p "text"))) => '((p "text")))
      (check (sxml-children '(leaf)) => []))

    (test-case "sxml-inf element predicates"
      (check ((sxml-e? 'p) '(p "text")) => #t)
      (check ((sxml-e? 'p) '(div "text")) => #f)
      (check ((sxml-e? 'p) "not-element") => #f)

      (check ((sxml-id? "main") '(div (@ (id "main")) "body")) => #t)
      (check ((sxml-id? "main") '(div (@ (id "other")) "body")) => #f)
      (check ((sxml-id? "main") '(div "no attrs")) => #f)

      (check ((sxml-class? "container") '(div (@ (class "container")) "body")) => #t)
      (check (and ((sxml-class? "special") '(div (@ (class "foo special bar")) "body")) #t) => #t)
      (check ((sxml-class? "missing") '(div (@ (class "foo bar")) "body")) => #f))

    (test-case "sxml-inf selectors"
      ; sxml-select collects matching nodes anywhere in the tree (DFS, not re-entering matched)
      (check (sxml-select sample-doc (sxml-e? 'p))
             => '((p "First paragraph") (p (@ (class "special")) "Second paragraph")))

      ; sxml-select* only looks at immediate children
      (check (sxml-select* '(body (div "a") (p "b") (div "c")) (sxml-e? 'div))
             => '((div "a") (div "c")))

      ; sxml-find returns the first match (DFS)
      (check (sxml-find sample-doc (sxml-e? 'p))
             => '(p "First paragraph"))
      (check (sxml-find sample-doc (sxml-e? 'missing)) => #f)

      ; sxml-find* looks only in immediate children
      (check (sxml-find* '(body (p "first") (div "d") (p "second")) (sxml-e? 'p))
             => '(p "first")))

    (test-case "sxpath selectors"
      ; select all p elements anywhere in the tree
      (check ((sxpath '(// p)) sample-doc)
             => '((p "First paragraph") (p (@ (class "special")) "Second paragraph")))

      ; select div's direct children p elements
      (check ((sxpath '(// div p)) sample-doc)
             => '((p "First paragraph") (p (@ (class "special")) "Second paragraph")))

      ; select title text
      (check ((sxpath '(// title *text*)) sample-doc)
             => '("Test")))))
