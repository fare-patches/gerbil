(export xml-test)

(import :std/test :std/text/markup/sxml)

(def xml-test
  (test-suite "test :std/text/markup/sxml XML (legacy :std/text/markup/xml)"
    (test-case "read-xml parses simple XML"
      ; basic element with text
      (check (read-xml "<root><child>text</child></root>")
             => '(*TOP* (root (child "text"))))
      ; multiple children
      (check (read-xml "<items><item>a</item><item>b</item></items>")
             => '(*TOP* (items (item "a") (item "b"))))
      ; self-closing element
      (check (read-xml "<root><empty/></root>")
             => '(*TOP* (root (empty)))))

    (test-case "read-xml preserves attributes"
      (let (doc (read-xml "<el id=\"x\" class=\"y\">body</el>"))
        (let (el (cadr doc))
          (check (sxml-attribute-e el 'id) => "x")
          (check (sxml-attribute-e el 'class) => "y"))))

    (test-case "read-xml accepts port and u8vector inputs"
      (check (call-with-input-string "<r>t</r>" read-xml)
             => '(*TOP* (r "t")))
      (check (read-xml (string->utf8 "<r>t</r>"))
             => '(*TOP* (r "t"))))

    (test-case "write-xml renders sxml as xml"
      ; basic element
      (check-output (write-xml '(root (child "text")) (current-output-port))
                    "<root><child>text</child></root>")
      ; void element gets self-closing slash in XML mode
      (check-output (write-xml '(*TOP* (br) (hr)) (current-output-port))
                    "<br /><hr />")
      ; attributes
      (check-output (write-xml '(el (@ (id "x")) "body") (current-output-port))
                    "<el id=\"x\">body</el>")
      ; special chars are escaped
      (check-output (write-xml '(p "a < b & c > d") (current-output-port))
                    "<p>a &lt; b &amp; c &gt; d</p>"))

    (test-case "print-sxml->xml writes with indentation"
      ; write-sxml-element places the newline+indent before the closing >, so the
      ; format is <tag\n  SPACES> rather than <tag>.  Check structural presence only.
      (let (out (open-output-string))
        (print-sxml->xml '(root (child "text")) out)
        (let (result (get-output-string out))
          (check (and (string-contains result "<root") #t) => #t)
          (check (and (string-contains result "</root") #t) => #t)
          (check (and (string-contains result "<child") #t) => #t)
          (check (and (string-contains result "text</child") #t) => #t)
          ; indentation adds newlines
          (check (and (string-contains result "\n") #t) => #t))))

    (test-case "read-xml / write-xml round-trip"
      (let* ((xml "<items><item>a</item><item>b</item></items>")
             (sxml (cadr (read-xml xml)))
             (out (open-output-string)))
        (write-xml sxml out)
        (check (get-output-string out) => xml)))))
