;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/io
        :std/text/markup/xml/types
        :std/text/markup/xml/reader
        :std/text/markup/xml/writer)
(export reader-test)

;;; Compact view of a tree: (name ((attr value) ...) child ...), names as
;;; local or {uri}local, text as strings, PIs as (? target data), comments as
;;; (! data).
(def (name->string (n : XMLName))
  (if (string=? n.uri "")
    n.local
    (string-append "{" n.uri "}" n.local)))

(def (sexp node)
  (cond
   ((XMLElement? node)
    (using (node :- XMLElement)
      (cons* (name->string node.name)
             (map (lambda ((a : XMLAttribute)) [(name->string a.name) a.value])
                  node.attributes)
             (map sexp node.children))))
   ((XMLText? node)
    (using (node :- XMLText) node.data))
   ((XMLPI? node)
    (using (node :- XMLPI) ['? node.target node.data]))
   ((XMLComment? node)
    (using (node :- XMLComment) ['! node.data]))
   (else node)))

(def (root input)
  (using (doc (read-xml input) :- XMLDocument)
    (sexp doc.root)))

(def (rejects? input)
  (with-catch xml-parse-error? (lambda () (read-xml input) #f)))

;;; The offset and message of the error reading input raises.
(def (parse-error input)
  (with-catch (lambda (e) (and (xml-parse-error? e) [(XMLParseError-offset e) (error-message e)]))
              (lambda () (read-xml input) #f)))

;;; FNV-1a of an ASCII string, as the scanner hashes names.
(def (name-hash (str : :string)) => :fixnum
  (let loop ((k 0) (h 2166136261))
    (if (fx< k (string-length str))
      (loop (fx+ k 1)
            (fxand (fx* (fxxor h (char->integer (string-ref str k))) 16777619) #xffffffff))
      h)))

(def (repeat (str : :string)
             (n   : :fixnum)) => :string
  (string-concatenate (make-list n str)))

(def (round-trip? (input : :string)) => :boolean
  (using (doc (read-xml input) : XMLDocument)
    (equal? (root (xml->string doc)) (sexp doc.root))))

(def reader-test
  (test-suite "test :std/text/markup/xml/reader"
    (test-case "elements, attributes in document order, text"
      (check (root "<r b='2' a=\"1\">x<e/>y</r>") => '("r" (("b" "2") ("a" "1")) "x" ("e" ()) "y")))

    (test-case "whitespace-only text and comments are dropped; text merges across comments"
      (check (root "<r>\n  <a> x </a>  <!-- c -->\n</r>") => '("r" () ("a" () " x ")))
      (check (root "<r>a<!--c-->b</r>") => '("r" () "ab")))

    (test-case "keep-space? and keep-comments?"
      (def (kept input . options)
        (using (doc (apply read-xml input options) : XMLDocument)
          (map sexp (append doc.prolog [doc.root] doc.epilog))))
      (check (kept "<r>\n  <a> x </a> <b/></r>" keep-space?: #t)
             => '(("r" () "\n  " ("a" () " x ") " " ("b" ()))))
      (check (kept "<r>a<!--c-->b</r>" keep-comments?: #t) => '(("r" () "a" (! "c") "b")))
      (check (kept "<r> <!--c--> </r>" keep-comments?: #t) => '(("r" () (! "c"))))
      (check (kept "<r> <!--c--> </r>" keep-comments?: #t keep-space?: #t)
             => '(("r" () " " (! "c") " ")))
      (check (kept "<!--p\r\nq--><r>&amp;<!--\r--><![CDATA[x]]></r><!--e-->" keep-comments?: #t)
             => '((! "p\nq") ("r" () "&" (! "\n") "x") (! "e")))
      (check (kept "<r>a<!--c-->b</r>") => '(("r" () "ab"))))

    (test-case "CDATA becomes text"
      (check (root "<r>x<![CDATA[<y> & ]]>z</r>") => '("r" () "x<y> & z"))
      (check (root "<r><![CDATA[  ]]></r>") => '("r" ())))

    (test-case "line ends and attribute values are normalized"
      (check (root "<r a=\"x\r\ny\tz\">a\r\nb\rc</r>") => '("r" (("a" "x y z")) "a\nb\nc"))
      (check (root "<r a=\"&#10;&#9;\"/>") => '("r" (("a" "\n\t")))))

    (test-case "predefined entities and character references"
      (check (root "<r>&lt;&gt;&amp;&quot;&apos;&#65;&#x42;&#x1F600;</r>")
             => (list "r" '() (string #\< #\> #\& #\" #\' #\A #\B (integer->char #x1F600)))))

    (test-case "namespaces"
      (using ((doc (read-xml "<r xmlns='urn:a' xmlns:b='urn:b'><b:c b:d='1' e='2'/><s xmlns=''/></r>")
                   : XMLDocument)
              (c (car doc.root.children) : XMLElement))
        (check (sexp doc.root) => '("{urn:a}r"
                                    (("{http://www.w3.org/2000/xmlns/}xmlns" "urn:a")
                                     ("{http://www.w3.org/2000/xmlns/}b" "urn:b"))
                                    ("{urn:b}c" (("{urn:b}d" "1") ("e" "2")))
                                    ("s" (("{http://www.w3.org/2000/xmlns/}xmlns" "")))))
        (check c.name.prefix => "b")
        (check c.name.local => "c")
        (check (xml-name=? c.name (make-xml-name "c" "urn:b")) => #t))
      (check (root "<r xml:lang='en'/>") => '("r" (("{http://www.w3.org/XML/1998/namespace}lang" "en")))))

    (test-case "prefix bindings: shadowing, the end of their element, many bindings"
      (def (names node)
        (if (XMLElement? node)
          (using (node :- XMLElement)
            (cons (name->string node.name)
                  (map names (filter XMLElement? node.children))))
          node))
      (def (root-names input)
        (using (doc (read-xml input) :- XMLDocument)
          (names doc.root)))
      ;; a declaration applies to its own element and ends with it
      (check (root-names "<r xmlns:p='urn:1'><p:a xmlns:p='urn:2'><p:b/></p:a><p:c/></r>")
             => '("r" ("{urn:2}a" ("{urn:2}b")) ("{urn:1}c")))
      (check (root-names "<r xmlns:p='urn:1'><p:a xmlns:p='urn:2'/><p:c/></r>")
             => '("r" ("{urn:2}a") ("{urn:1}c")))
      (check (parse-error "<r><a xmlns:p='urn:1'/><p:b/></r>") => [23 "undeclared namespace prefix"])
      (check (parse-error "<r><a xmlns:p='urn:1'></a><p:b/></r>") => [26 "undeclared namespace prefix"])
      (check (rejects? "<r><a xmlns:p='urn:1'><b/></a><c p:x='1'/></r>") => #t)
      ;; xmlns='' undeclares the default namespace
      (check (root-names "<r xmlns='urn:d'><a xmlns=''><b/></a><c/></r>")
             => '("{urn:d}r" ("a" ("b")) ("{urn:d}c")))
      ;; xml is bound by definition, and may be declared to its namespace
      (check (root-names "<xml:r/>") => '("{http://www.w3.org/XML/1998/namespace}r"))
      (check (root "<r xmlns:xml='http://www.w3.org/XML/1998/namespace' xml:lang='en'/>")
             => '("r" (("{http://www.w3.org/2000/xmlns/}xml" "http://www.w3.org/XML/1998/namespace")
                       ("{http://www.w3.org/XML/1998/namespace}lang" "en"))))
      ;; many bindings on the root, children using the oldest
      (let* ((n 2000)
             (input (string-concatenate
                     (append ["<r"]
                             (map (lambda (k) (string-append " xmlns:p" (number->string k) "='u"
                                                             (number->string k) "'"))
                                  (iota n))
                             [">"]
                             (map (lambda (k) "<p0:c/>") (iota n))
                             ["</r>"])))
             (kids (cdr (root-names input))))
        (check (length kids) => n)
        (check (andmap (lambda (kid) (equal? kid '("{u0}c"))) kids) => #t))
      ;; nested redeclarations, each element using the outermost prefix
      (let* ((n 2000)
             (input (string-concatenate
                     (append ["<p0:e xmlns:p0='u0'>"]
                             (map (lambda (k) (string-append "<p0:e xmlns:p" (number->string k) "='u"
                                                             (number->string k) "'>"))
                                  (iota n 1))
                             (map (lambda (k) "</p0:e>") (iota (fx+ n 1)))))))
        (check (let loop ((node (root-names input)) (depth 1))
                 (if (null? (cdr node))
                   (and (equal? (car node) "{u0}e") depth)
                   (loop (cadr node) (fx+ depth 1))))
               => (fx+ n 1))))

    (test-case "start tags with many prefixed attributes"
      ;; 20 prefixed attributes grow the scanner's pending-attribute vector;
      ;; a declaration after the first 10 still applies to them
      (def (attrs ks)
        (string-concatenate
         (map (lambda (k) (string-append " p:a" (number->string k) "='" (number->string k) "'"))
              ks)))
      (def (names ks)
        (map (lambda (k) [(string-append "{urn:p}a" (number->string k)) (number->string k)]) ks))
      (check (root (string-append "<r" (attrs (iota 10)) " xmlns:p='urn:p'" (attrs (iota 10 10)) "/>"))
             => (list "r" (append (names (iota 10))
                                 [["{http://www.w3.org/2000/xmlns/}p" "urn:p"]]
                                 (names (iota 10 10)))))
      (check (rejects? "<r xmlns:p='urn:p' xmlns:q='urn:p' p:a='1' q:a='2'/>") => #t))

    (test-case "duplicate attributes: past 16, expanded names, offsets, scaling"
      (def (attrs from to)
        (string-concatenate
         (map (lambda (k) (string-append " a" (number->string k) "='v'")) (iota (fx- to from) from))))
      (def many (attrs 0 20))                     ; 20 attributes, 150 bytes from offset 2
      ;; past 16 attributes: plain, expanded and xmlns duplicates, at the
      ;; duplicate's name
      (check (parse-error (string-append "<r" many " a5='w'/>")) => [153 "duplicate attribute"])
      (check (parse-error (string-append "<r" many " xmlns:p='urn:p' xmlns:q='urn:p' p:a='1' q:a='2'/>"))
             => [193 "duplicate attribute"])
      (check (parse-error (string-append "<r" many " xmlns:p='urn:p' xmlns:p='urn:p'/>"))
             => [169 "duplicate attribute"])
      ;; a and p:a are different names
      (check (length (cadr (root (string-append "<r xmlns:p='urn:p'" many " a='1' p:a='2'/>")))) => 23)
      (check (length (cadr (root "<r xmlns:p='urn:p' a='1' p:a='2'/>"))) => 3)
      ;; up to 16 attributes: errors at the attribute too
      (check (parse-error "<r xmlns:p='urn:p' xmlns:q='urn:p' p:a='1' q:a='2'/>") => [43 "duplicate attribute"])
      (check (parse-error "<r a='1' a='2'/>") => [9 "duplicate attribute"])
      (check (parse-error "<r a='1' p:b='2'/>") => [9 "undeclared namespace prefix"])
      (check (parse-error "<r a='1' xmlns:p=''/>") => [9 "expected non-empty namespace for a prefix"])
      (check (parse-error "<r a='>' xmlns='http://www.w3.org/2000/xmlns/'/>")
             => [9 "expected namespace other than the reserved ones"])
      ;; 16 and 17 attributes, the last a duplicate: plain only, after one
      ;; prefixed attribute, and of that prefixed attribute
      (for-each
       (lambda (n)
         (for-each
          (lambda (first last)
            (let* ((head (string-append "<r" first (attrs 1 (fx- n 1))))
                   (input (string-append head last "/>")))
              (check (cons input (parse-error input))
                     => [input (fx+ (string-length head) 1) "duplicate attribute"])))
          [" a0='v'" " xml:lang='en'" " xml:lang='en'"]
          [" a0='w'" " a1='w'" " xml:lang='fr'"]))
       [16 17])
      ;; 32,000 attributes, plain or prefixed
      (for-each
       (lambda (prefix)
         (let* ((n 32000)
                (input (string-concatenate
                        (append ["<r xmlns:p='urn:p'"]
                                (map (lambda (k) (string-append " " prefix "a" (number->string k) "='v'"))
                                     (iota n))
                                ["/>"])))
                (count (using (doc (read-xml input) :- XMLDocument)
                         (length doc.root.attributes))))
           (check (cons prefix count) => (cons prefix (fx+ n 1)))))
       ["" "p:"]))

    (test-case "prolog and epilog keep processing instructions; no XML declaration node"
      (using (doc (read-xml "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e 'v'>]><?a x?><r/><!-- c --><?b  y ?>")
                  : XMLDocument)
        (check (map sexp doc.prolog) => '((? "a" "x")))
        (check (map sexp doc.epilog) => '((? "b" "y ")))))

    (test-case "inputs: string, UTF-8 bytes, ports, Reader, ISO-8859-1 bytes"
      (let (expected (list "r" '() (string #\x #\xe9)))
        (check (root "<r>x\xe9;</r>") => expected)
        (check (root (string->utf8 "\xfeff;<r>x\xe9;</r>")) => expected)
        (check (call-with-input-string "<r>x\xe9;</r>" root) => expected)
        (check (call-with-input-u8vector (string->utf8 "<r>x\xe9;</r>") root) => expected)
        (check (root (open-buffered-reader (string->utf8 "<r>x\xe9;</r>"))) => expected)
        (check (root (u8vector-append (string->utf8 "<?xml version='1.0' encoding='ISO-8859-1'?><r>x")
                                      (u8vector #xe9)
                                      (string->utf8 "</r>")))
               => expected))
      (check-exception (read-xml 42) contract-violation-error?))

    (test-case "rejects malformed documents"
      (for-each
       (lambda (input)
         (check (cons input (rejects? input)) => (cons input #t)))
       ["" "<r>" "<r></s>" "<r a='1' a='2'/>" "<r>&foo;</r>" "<x:r/>" "<r a=1/>" "text<r/>"
        "<r/><s/>" "<r/>trailing" "<1r/>" "<r a='<'/>" "<r>&#0;</r>" "<r>&#xD800;</r>"
        "<r>]]></r>" "<r>\x1;</r>" "<r a='1'b='2'/>" "<r><!-- a -- b --></r>" "<r><?xml x?></r>"
        "<a:b:c xmlns:a='u'/>" "<r xmlns:p=''/>" "<r \xd7;='1'/>" "<r><" "<r a='1" "<r><![CDATA[x"
        (u8vector 60 114 62 #xff 60 47 114 62)
        (string->utf8 "<?xml version='1.0' encoding='UTF-16'?><r/>")]))

    (test-case "document type declarations"
      (for-each
       (lambda (input)
         (check (cons input (root input)) => (cons input '("r" ()))))
       ["<!DOCTYPE r><r/>"
        "<!DOCTYPE r SYSTEM 'r.dtd'><r/>"
        "<!DOCTYPE r PUBLIC '-//X//DTD r//EN' \"r.dtd\" ><r/>"
        "<!DOCTYPE r [<!ENTITY e \"]>\">]><r/>"
        "<!DOCTYPE r [ ] ><r/>"
        "<!DOCTYPE r [ <!-- ] --> <?p ]?> ]><r/>"])
      (def (doctype input)
        (using ((doc (read-xml input) : XMLDocument)
                (dt doc.doctype :? XMLDoctype))
          (and dt [dt.name dt.public-id dt.system-id])))
      (check (doctype "<r/>") => #f)
      ;; internal subset declarations are not processed
      (check (parse-error "<!DOCTYPE r [<!ENTITY e 'x'>]><r>&e;</r>") => [33 "invalid reference"])
      (check (doctype "<!DOCTYPE p:r [<!ELEMENT r ANY>]><r/>") => '("p:r" #f #f))
      (check (doctype "<!DOCTYPE r SYSTEM 'a\r\nb\xe9;'><r/>") => '("r" #f "a\nb\xe9;"))
      (check (doctype "<!DOCTYPE r PUBLIC \"-//X//EN\" 'r.dtd'><r/>") => '("r" "-//X//EN" "r.dtd"))
      (for-each
       (lambda (input)
         (check (cons input (rejects? input)) => (cons input #t)))
       ["<!DOCTYPE r\x1;><r/>" "<!DOCTYPE 1r><r/>" "<!DOCTYPE ><r/>" "<!DOCTYPE r junk><r/>"
        "<!DOCTYPE r [ ] junk><r/>" "<!DOCTYPE r PUBLIC 'x'><r/>" "<!DOCTYPE r SYSTEM><r/>"
        "<!DOCTYPE r \xe9;><r/>" "<!DOCTYPE r [\x0;]><r/>" "<!DOCTYPE r\xfffe;><r/>"
        "<!DOCTYPE r PUBLIC 'a{' 'b'><r/>" "<!DOCTYPE r [ <!ENTITY e 'x>]><r/>"
        (u8vector-append (string->utf8 "<!DOCTYPE r [") (u8vector #xff #xfe) (string->utf8 "]><r/>"))]))

    (test-case "errors carry the offset in the original input"
      (check (parse-error "<r>&foo;</r>") => [3 "invalid reference"])
      (check (parse-error (string->utf8 "<r>\xe9;&x;</r>")) => [5 "invalid reference"])
      ;; string input: character index
      (check (parse-error "<r>\xe9;&x;</r>") => [4 "invalid reference"])
      (check (parse-error "\xfeff;<r>&x;</r>") => [4 "invalid reference"])
      ;; ISO-8859-1 input: byte offset before transcoding
      (check (parse-error (u8vector-append
                           (string->utf8 "<?xml version='1.0' encoding='ISO-8859-1'?><r>")
                           (u8vector #xe9 #xe9)
                           (string->utf8 "&x;</r>")))
             => [48 "invalid reference"])
      ;; a UTF-8 byte order mark admits only a UTF-8 declaration
      (check (parse-error (u8vector-append
                           (u8vector #xef #xbb #xbf)
                           (string->utf8 "<?xml version='1.0' encoding='ISO-8859-1'?><r/>")))
             => [33 "byte order mark contradicts the declared encoding"])
      (check (parse-error (string->utf8 "<r>\xfffe;</r>")) => [3 "character not allowed in XML"])
      (check (parse-error (u8vector 60 114 62 #xed #xa0 #x80 60 47 114 62)) => [3 "invalid UTF-8"])
      ;; a lone surrogate in a string (Gambit's UTF-8 port decoder returns
      ;; U+D800 for the bytes ED A0 80), at its character index
      (let (str (read-line (open-input-u8vector [char-encoding: 'UTF-8
                                                 init: (u8vector-append (string->utf8 "<r>\xe9;")
                                                                        (u8vector #xed #xa0 #x80)
                                                                        (string->utf8 "</r>"))])
                           #f))
        (check (char->integer (string-ref str 4)) => #xd800)
        (check (parse-error str) => [4 "character not allowed in XML"])
        (check (parse-error (open-input-string str)) => [4 "character not allowed in XML"])))

    (test-case "invalid UTF-8 is reported at its first byte in every construct"
      (for-each
       (lambda (construct)
         (let ((prefix (car construct))
               (suffix (cadr construct)))
           (for-each
            (lambda (bad)
              (let ((bytes (car bad))
                    (message (cadr bad))
                    (offset (u8vector-length (string->utf8 prefix))))
                (check (list prefix bytes
                             (parse-error (u8vector-append (string->utf8 prefix) bytes
                                                           (string->utf8 suffix))))
                       => (list prefix bytes [offset message]))))
            [[(u8vector #xc0 #x80) "invalid UTF-8"]
             [(u8vector #x80) "invalid UTF-8"]
             [(u8vector #xed #xa0 #x80) "invalid UTF-8"]
             [(u8vector #xe2 #x82) "invalid UTF-8"]
             [(u8vector #xf4 #x90 #x80 #x80) "invalid UTF-8"]
             [(u8vector #xef #xbf #xbe) "character not allowed in XML"]
             [(u8vector #xef #xbf #xbf) "character not allowed in XML"]])))
       [["<a>x\xe9;" "</a>"]
        ["<a>&amp;x\xe9;" "</a>"]
        ["<a>x\r\n\xe9;" "</a>"]
        ["<a><!--x\xe9;" "--></a>"]
        ["<a><?p x\xe9;" "?></a>"]
        ["<a b='x\xe9;" "'/>"]
        ["<a b='&amp;x\xe9;" "'/>"]
        ["<a><![CDATA[x\xe9;" "]]></a>"]
        ["<!DOCTYPE a SYSTEM 'x\xe9;" "'><a/>"]
        ["<!DOCTYPE a [<!-- x\xe9;" " -->]><a/>"]
        ["<!DOCTYPE a [ \xe9;" "]><a/>"]
        ["<!DOCTYPE a [<!ENTITY e 'x\xe9;" "'>]><a/>"]])
      ;; names: ill-formed UTF-8 at its byte, a noncharacter is not a name character
      (check (parse-error (u8vector-append (string->utf8 "<a\xe9;") (u8vector #xc0 #x80) (string->utf8 "/>")))
             => [4 "invalid UTF-8"])
      (check (parse-error (u8vector-append (string->utf8 "<a") (u8vector #xe2 #x82) (string->utf8 "/>")))
             => [2 "invalid UTF-8"])
      (check (parse-error (u8vector-append (string->utf8 "<a") (u8vector #xef #xbf #xbe) (string->utf8 "/>")))
             => [1 "invalid name"])
      ;; with keep-comments? the comment is scanned once, as it is kept
      (check (with-catch (lambda (e) (and (xml-parse-error? e) (XMLParseError-offset e)))
                         (lambda ()
                           (read-xml (u8vector-append (string->utf8 "<a><!--x") (u8vector #x80)
                                                      (string->utf8 "--></a>"))
                                     keep-comments?: #t)))
             => 8))

    (test-case "XML declaration: version, encoding name, standalone"
      ;; VersionNum is 1. and digits; a 1.0 processor reads 1.x as 1.0
      (for-each (lambda (version)
                  (let (input (string-append "<?xml version='" version "'?><r/>"))
                    (check (cons version (root input)) => (cons version '("r" ())))
                    (check (cons version (root (string->utf8 input))) => (cons version '("r" ())))))
                ["1.0" "1.1" "1.10"])
      (for-each (lambda (version)
                  (let (input (string-append "<?xml version='" version "'?><r/>"))
                    (check (cons version (parse-error input))
                           => (cons version [15 "unsupported XML version"]))
                    (check (cons version (parse-error (string->utf8 input)))
                           => (cons version [15 "unsupported XML version"]))))
                ["1.foo" "1.0a" "1." "2.0" ""])
      ;; EncName, for string and byte input
      (for-each (lambda (name)
                  (let (input (string-append "<?xml version='1.0' encoding='" name "'?><r/>"))
                    (check (cons name (parse-error input)) => (cons name [30 "invalid encoding name"]))
                    (check (cons name (parse-error (string->utf8 input)))
                           => (cons name [30 "invalid encoding name"]))))
                ["" "-x" "1x" ".x"])
      (check (parse-error (string->utf8 "<?xml version='1.0' encoding='UTF-16'?><r/>"))
             => [30 "unsupported encoding"])
      ;; a string has no encoding: a valid name is ignored
      (check (root "<?xml version='1.0' encoding='UTF-16'?><r/>") => '("r" ()))
      (check (root "<?xml version='1.0' encoding='x.y_z-1'?><r/>") => '("r" ()))
      (check (parse-error "<?xml version='1.0' standalone='maybe'?><r/>")
             => [32 "invalid standalone value"])
      (check (root "<?xml version='1.0' encoding='utf-8' standalone='yes'?><r/>") => '("r" ())))

    (test-case "XML declaration: US-ASCII is enforced on bytes; UTF-16 is not read"
      (check (parse-error (string->utf8 "<?xml version='1.0' encoding='US-ASCII'?><r>\xe9;</r>"))
             => [44 "non-ASCII byte in a US-ASCII document"])
      (check (parse-error (string->utf8 "<?xml version='1.0' encoding='ascii'?><r a='\xe9;'/>"))
             => [44 "non-ASCII byte in a US-ASCII document"])
      (check (root (string->utf8 "<?xml version='1.0' encoding='US-ASCII'?><r>x</r>")) => '("r" () "x"))
      (check (root "<?xml version='1.0' encoding='US-ASCII'?><r>\xe9;</r>") => '("r" () "\xe9;"))
      (check (parse-error (u8vector #xff #xfe #x3c #x00 #x72 #x00 #x2f #x00 #x3e #x00))
             => [0 "unsupported encoding (UTF-16)"])
      (check (parse-error (u8vector #xfe #xff #x00 #x3c #x00 #x72 #x00 #x2f #x00 #x3e))
             => [0 "unsupported encoding (UTF-16)"]))

    (test-case "comment and end of input errors"
      (check (parse-error "<r><!--a--b--></r>") => [8 "-- in comment"])
      (check (parse-error (string->utf8 "<r><!--\xe9;--b--></r>")) => [9 "-- in comment"])
      (check (parse-error "<r><!--x--") => [10 "unexpected end of input"])
      (check (parse-error "<r><a>") => [6 "unexpected end of input"])
      (check (parse-error "<r a='x") => [7 "unexpected end of input"])
      (check (parse-error "") => [0 "unexpected end of input"]))

    (test-case "premature end of input"
      (check-exception (read-xml "<r><a>") premature-end-of-input-error?)
      (check-exception (read-xml "<r><a>") xml-parse-error?)
      (check (with-catch XMLParseError-offset (lambda () (read-xml "<r><a>"))) => 6)
      (check-exception (read-xml "<r>x</s>") io-error?))

    (test-case "many names: intern table growth, its cap and its probe limit"
      (let* ((names (map (lambda (k) (string-append "n" (number->string k))) (iota 5000)))
             (input (string-append
                     "<r>"
                     (string-concatenate
                      (map (lambda (n) (string-append "<" n " " n "='1' a" n "='2'/>")) names))
                     "</r>"))
             (kids (using (doc (read-xml input) :- XMLDocument) doc.root.children)))
        (check (length kids) => 5000)
        (check (map (lambda ((el : XMLElement)) el.name.local) kids) => names)
        (check (round-trip? input) => #t))
      ;; names whose hashes share their low 13 bits probe one chain of the
      ;; table at every size up to the cap
      (let* ((bucket (fxand (name-hash "c0") #x1fff))
             (names (let loop ((k 0) (found '()))
                      (if (fx= (length found) 40)
                        (reverse found)
                        (let (n (string-append "c" (number->string k)))
                          (loop (fx+ k 1)
                                (if (fx= (fxand (name-hash n) #x1fff) bucket) (cons n found) found))))))
             (input (string-append
                     "<r>"
                     (repeat
                      (string-concatenate (map (lambda (n) (string-append "<" n "/>")) names))
                      3)
                     "</r>")))
        (check (using (doc (read-xml input) :- XMLDocument)
                 (map (lambda ((el : XMLElement)) el.name.local) doc.root.children))
               => (append names names names))))

    (test-case "deep nesting, long text and large inputs"
      (let (deep (string-append (repeat "<d>" 100) "x" (repeat "</d>" 100)))
        (check (round-trip? deep) => #t))
      (let* ((text (repeat "a &amp; \xe9;\x1F600;\r\n" 200))
             (expected (repeat "a & \xe9;\x1F600;\n" 200)))
        (check (root (string-append "<r>" text "</r>")) => (list "r" '() expected))
        (check (root (string-append "<r a='" text "'/>"))
               => (list "r" (list (list "a" (repeat "a & \xe9;\x1F600; " 200))))))
      (let* ((input (string-append "<r>" (repeat "<e a='\xe9;'>t\xe9;</e>" 20000) "</r>"))
             (expected (root input)))
        (check (> (u8vector-length (string->utf8 input)) 65536) => #t)
        (check (call-with-input-string input root) => expected)
        (check (call-with-input-u8vector (string->utf8 input) root) => expected)
        (check (root (open-buffered-reader (string->utf8 input))) => expected))
      ;; a byte port that characters were read from is rejected by Gambit
      (let (port (open-input-u8vector (string->utf8 "x<r/>")))
        (read-char port)
        (check-exception (read-xml port) (lambda (e) (not (xml-parse-error? e)))))
      ;; an empty port has no root element
      (check (parse-error (open-input-string "")) => [0 "unexpected end of input"])
      (check (parse-error (open-input-u8vector (u8vector))) => [0 "unexpected end of input"]))))
