;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/text/markup/html/tokenizer
        :std/text/markup/html/entities
        (only-in :std/text/markup/html/scanner html-atom-name))
(export tokenizer-test)

;;; The tokens of input as html5lib writes them, adjacent characters merged:
;;; ("Character" data) ("StartTag" name ((name . value) ...) [#t])
;;; ("EndTag" name) ("Comment" data) ("ProcessingInstruction" target data)
;;; ("DOCTYPE" name public-id system-id correct?), #f for a missing name or
;;; identifier.
(def (tokens input
             state: (state html-state-data)
             last-start-tag: (last-start-tag #f)
             cdata: (cdata? #f))
  (let (tz (make-html-tokenizer input))
    (html-tokenizer-state-set! tz state)
    (html-tokenizer-last-start-tag-set! tz last-start-tag)
    (html-tokenizer-cdata-set! tz cdata?)
    (let loop ((out '()))
      (def (characters data)
        (if (and (pair? out) (equal? (caar out) "Character"))
          (loop (cons ["Character" (string-append (cadar out) data)] (cdr out)))
          (loop (cons ["Character" data] out))))
      (let (kind (html-tokenizer-next! tz))
        (cond
         ((fx= kind html-token-eof) (reverse out))
         ((fx= kind html-token-characters) (characters (html-token-text tz)))
         ((fx= kind html-token-null-character) (characters (string #\nul)))
         ((fx= kind html-token-start-tag)
          (loop (cons (append ["StartTag" (html-token-tag-name tz) (html-token-attributes tz)]
                              (if (html-token-self-closing? tz) [#t] []))
                      out)))
         ((fx= kind html-token-end-tag) (loop (cons ["EndTag" (html-token-tag-name tz)] out)))
         ((fx= kind html-token-comment) (loop (cons ["Comment" (html-token-data tz)] out)))
         ((fx= kind html-token-pi)
          (loop (cons ["ProcessingInstruction" (html-token-target tz) (html-token-data tz)] out)))
         (else
          (loop (cons ["DOCTYPE" (html-token-doctype-name tz)
                       (html-token-doctype-public-id tz) (html-token-doctype-system-id tz)
                       (not (html-token-force-quirks? tz))]
                      out))))))))

(def (text input . options)
  (let (out (apply tokens input options))
    (if (and (= (length out) 1) (equal? (caar out) "Character"))
      (cadar out)
      out)))

(def (attributes input)
  (caddr (car (tokens input))))

(def (utf8-error-offset input)
  (with-catch (lambda (e) (and (html-parse-error? e) (HTMLParseError-offset e)))
              (lambda () (tokens input) #f)))

;;; The named character references of the generated trie in ./entities, as
;;; (name . value) pairs: every path from the root to a node with a value.
(def (entity-table)
  (def (value k)
    (utf8->string (subu8vector entity-value-bytes
                               (u16vector-ref entity-value-start (fx- k 1))
                               (u16vector-ref entity-value-start k))))
  (let walk ((node 0) (name '()) (out '()))
    (let ((out (let (k (u16vector-ref entity-node-value node))
                 (if (fx> k 0)
                   (cons (cons (list->string (reverse name)) (value k)) out)
                   out)))
          (end (u16vector-ref entity-edge-start (fx+ node 1))))
      (let loop ((edge (u16vector-ref entity-edge-start node)) (out out))
        (if (fx< edge end)
          (loop (fx+ edge 1)
                (walk (u16vector-ref entity-edge-target edge)
                      (cons (integer->char (u8vector-ref entity-edge-byte edge)) name)
                      out))
          out)))))

(def tokenizer-test
  (test-suite "test :std/text/markup/html/tokenizer"
    (test-case "tags, attributes and case folding"
      (check (tokens "<DIV Class=A id='b' title=\"c\" hidden>x</DiV >")
             => '(("StartTag" "div" (("class" . "A") ("id" . "b") ("title" . "c") ("hidden" . "")))
                  ("Character" "x")
                  ("EndTag" "div")))
      (check (tokens "<br/><a =x b= c>") => '(("StartTag" "br" () #t)
                                             ("StartTag" "a" (("=x" . "") ("b" . "c")))))
      (check (attributes "<p a=1 A=2 a=3 b>") => '(("a" . "1") ("b" . "")))
      (check (tokens "</p a=1>") => '(("EndTag" "p")))
      (check (tokens "<p a='1") => '())
      (check (tokens "<x-y:z \x0;>") => (list ["StartTag" "x-y:z" [(cons (string #\xfffd) "")]]))
      ;; unquoted values run to whitespace or >, taking / " ' ` <
      (check (tokens "<a b=c/><a b='c'/><a/b>")
             => '(("StartTag" "a" (("b" . "c/"))) ("StartTag" "a" (("b" . "c")) #t)
                  ("StartTag" "a" (("b" . "")))))
      (check (attributes "<a b=c\"d'e`f<g>") => '(("b" . "c\"d'e`f<g")))
      (check (attributes "<a b=\"x\"c d = 'e' f=>")
             => '(("b" . "x") ("c" . "") ("d" . "e") ("f" . "")))
      (check (attributes "<a\tb\nc\x0c;d=e>") => '(("b" . "") ("c" . "") ("d" . "e")))
      (check (attributes "<a \"b'=c <d>") => '(("\"b'" . "c") ("<d" . "")))
      (check (tokens "<a\x0;B>") => (list ["StartTag" (string #\a #\xfffd #\b) []]))
      (check (attributes "<a b='\x0;'>") => (list (cons "b" (string #\xfffd))))
      (check (tokens "</a/>") => '(("EndTag" "a")))
      (check (tokens "< a></ a><a") => '(("Character" "< a>") ("Comment" " a"))))

    (test-case "names outside the known table intern to one atom"
      (let* ((names (map (lambda (k) (string-append "n" (number->string k))) (iota 5000)))
             (input (apply string-append
                           (map (lambda (name) (string-append "<" name " " name "=v>")) names)))
             (out (tokens (string-append input input))))
        (check (map cadr out) => (append names names))
        (check (map caar (map caddr out)) => (append names names))))

    ;; enough names for the table to grow past clusters of max-probes entries
    (test-case "equal names are equal atoms in large name sets"
      (let* ((n 100000)
             (names (map (lambda (k) (string-append "x-" (number->string k))) (iota n)))
             (tag (string-concatenate (cons "<p" (map (lambda (name) (string-append " " name))
                                                      (append names names)))))
             (tz (make-html-tokenizer (string-append tag ">"))))
        (html-tokenizer-next! tz)
        (check (length (html-token-attributes tz)) => n))
      (let* ((n 100000)
             (names (map (lambda (k) (string-append "x-" (number->string k))) (iota n)))
             (input (string-concatenate
                     (map (lambda (name) (string-append "<" name " " name "=1>")) names)))
             (tz (make-html-tokenizer (string-append input input)))
             (atoms (make-hash-table))
             (mismatches 0))
        (def (intern! atom)
          (let* ((name (html-atom-name tz atom))
                 (old (hash-ref atoms name atom)))
            (hash-put! atoms name atom)
            (unless (fx= old atom)
              (set! mismatches (fx+ mismatches 1)))))
        (let loop ()
          (unless (fx= (html-tokenizer-next! tz) html-token-eof)
            (using (tz :- HTMLTokenizer)
              (intern! tz.tag)
              (intern! (vector-ref tz.attributes 0)))
            (loop)))
        (check (hash-length atoms) => n)
        (check mismatches => 0)))

    (test-case "text: line ends, NUL and less-than signs"
      (check (text "a\r\nb\rc\nd") => "a\nb\nc\nd")
      (check (text "\r\r\n\na\r") => "\n\n\na\n")
      (check (attributes "<a b='x\r\ny\rz'>") => '(("b" . "x\ny\nz")))
      (check (tokens "a\x0;b") => (list ["Character" (string #\a #\nul #\b)]))
      (check (text "a < b <3 <> <=") => "a < b <3 <> <=")
      (check (text "</>x") => "x")
      (check (tokens "a</") => '(("Character" "a</")))
      (check (text "a\x0;b" state: html-state-rcdata) => (string #\a #\xfffd #\b))
      (check (text "a\r\n\x0;" state: html-state-rawtext) => (string #\a #\newline #\xfffd))
      (check (text "a\x0;" state: html-state-script-data) => (string #\a #\xfffd))
      (check (text "a\x0;" state: html-state-plaintext) => (string #\a #\xfffd)))

    (test-case "named character references"
      (check (text "&amp;&lt;&AMP;&amp&ampx") => "&<&&&x")
      (check (text "&notit; &notin; &not") => "\xac;it; \x2209; \xac;")
      (check (text "&notin &ampamp; &amp;amp;") => "\xac;in &amp; &amp;")
      (check (text "&NotEqualTilde;&acE;") => (string #\x2242 #\x0338 #\x223e #\x0333))
      (check (text "&foo; &; & &#") => "&foo; &; & &#")
      (check (text "&ouml;&Ouml&AElig&nbsp&apos;") => "\xf6;\xd6;\xc6;\xa0;'")
      ;; in attribute values a reference without ; followed by = or an
      ;; alphanumeric is literal text
      (check (attributes "<a b='&amp=&notit;&copy;&ampx&amp;x'>")
             => '(("b" . "&amp=&notit;\xa9;&ampx&x")))
      (check (attributes "<a b=&lt c=&lt;d>") => '(("b" . "<") ("c" . "<d")))
      (check (attributes "<a b='&not x' c=\"&not;it\" d=&amp;e e='&notit'>")
             => '(("b" . "\xac; x") ("c" . "\xac;it") ("d" . "&e") ("e" . "&notit")))
      (check (text "&amp;" state: html-state-rawtext) => "&amp;")
      (check (text "&amp;" state: html-state-script-data) => "&amp;")
      (check (text "&amp;" state: html-state-plaintext) => "&amp;")
      (check (text "&amp;" state: html-state-rcdata) => "&"))

    (test-case "every name of the entity table decodes to its value"
      (let (table (entity-table))
        (check (length table) => 2231)
        (check (filter (lambda (entry)
                         (let ((name (string-append "&" (car entry))))
                           (not (and (equal? (text name) (cdr entry))
                                     (equal? (attributes (string-append "<a b='" name "'>"))
                                             [(cons "b" (cdr entry))])))))
                       table)
               => '())))

    (test-case "numeric character references"
      (check (text "&#65;&#x42;&#X43;&#x1F600;") => (string #\A #\B #\C (integer->char #x1F600)))
      (check (text "&#0;&#xD800;&#x110000;&#99999999999999999999;")
             => (string #\xfffd #\xfffd #\xfffd #\xfffd))
      (check (text "&#128;&#x9f;&#x81;&#13;") => (string #\x20ac #\x178 #\x81 #\return))
      (check (text "&#150;&#x8D;&#x8e;&#x10FFFF;")
             => (string #\x2013 #\x8d #\x17d (integer->char #x10ffff)))
      (check (text "&#65&#x42x&#;&#x;") => "ABx&#;&#x;")
      (check (text "&#x00000041;&#00000000000000066;&#x43") => "ABC")
      (check (attributes "<a b='&#38;&#x41x'>") => '(("b" . "&Ax"))))

    (test-case "comments, bogus comments, processing instructions, CDATA"
      (check (tokens "<!--a-- b--!>c<!---->d<!-->e<!--->")
             => '(("Comment" "a-- b") ("Character" "c") ("Comment" "") ("Character" "d")
                  ("Comment" "") ("Character" "e") ("Comment" "")))
      (check (tokens "<!--x--!-->") => '(("Comment" "x--!")))
      (check (tokens "<!--a--!b--><!---x--><!--a---->")
             => '(("Comment" "a--!b") ("Comment" "-x") ("Comment" "a--")))
      ;; nested comment openers
      (check (tokens "<!--<!--x--><!--a<!-->") => '(("Comment" "<!--x") ("Comment" "a<!")))
      (check (tokens "<!--\x0;\r\n") => (list ["Comment" (string #\xfffd #\newline)]))
      (check (tokens "<!--a-") => '(("Comment" "a")))
      (check (tokens "<!--") => '(("Comment" "")))
      (check (tokens "<!x><?><![CDATA[y]]></3>")
             => '(("Comment" "x") ("Comment" "?") ("Comment" "[CDATA[y]]") ("Comment" "3")))
      (check (tokens "<!-x><!>") => '(("Comment" "-x") ("Comment" "")))
      (check (tokens "<!") => '(("Comment" "")))
      (check (tokens "<!a\x0;>") => (list ["Comment" (string #\a #\xfffd)]))
      (check (tokens "<?php echo 1 ?><?x?><?xml version='1.0'?><?a.b>")
             => '(("ProcessingInstruction" "php" "echo 1 ") ("ProcessingInstruction" "x" "")
                  ("Comment" "?xml version='1.0'?") ("Comment" "?a.b")))
      (check (tokens "<?a?b><?a\tb c?><?_a-1 x><?xmlx y><?a>")
             => '(("ProcessingInstruction" "a" "?b") ("ProcessingInstruction" "a" "b c")
                  ("ProcessingInstruction" "_a-1" "x") ("ProcessingInstruction" "xmlx" "y")
                  ("ProcessingInstruction" "a" "")))
      (check (tokens "<?1><?XML x?><?xml-stylesheet x?>")
             => '(("Comment" "?1") ("Comment" "?XML x?") ("Comment" "?xml-stylesheet x?")))
      (check (tokens "<?a\x0;>") => (list ["Comment" (string #\? #\a #\xfffd)]))
      ;; NUL in processing instruction data is kept, as the state machine says
      (check (tokens "<?a \x0;>") => (list ["ProcessingInstruction" "a" (string #\nul)]))
      (check (tokens "<?pi data") => '())
      (check (tokens "<?a b?") => '())
      (check (tokens "a]]b]]>c" state: html-state-cdata) => '(("Character" "a]]bc"))))

    (test-case "CDATA sections in foreign content"
      (check (tokens "<![CDATA[a<b>]]b]]]>c<![CDATA[d" cdata: #t)
             => '(("Character" "a<b>]]b]cd")))
      (check (tokens "<![CDATA[\x0;\r\n]]>" cdata: #t)
             => (list ["Character" (string #\nul #\newline)]))
      (check (tokens "<![cdata[x]]>" cdata: #t) => '(("Comment" "[cdata[x]]")))
      (check (tokens "<![CDATA[x]]>") => '(("Comment" "[CDATA[x]]"))))

    (test-case "DOCTYPE"
      (check (tokens "<!DOCTYPE html>") => '(("DOCTYPE" "html" #f #f #t)))
      (check (tokens "<!doctype HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">")
             => '(("DOCTYPE" "html" "-//W3C//DTD HTML 4.01//EN" #f #t)))
      (check (tokens "<!DOCTYPE html SYSTEM 'about:legacy-compat'>")
             => '(("DOCTYPE" "html" #f "about:legacy-compat" #t)))
      (check (tokens "<!DOCTYPE>") => '(("DOCTYPE" #f #f #f #f)))
      (check (tokens "<!DOCTYPE") => '(("DOCTYPE" #f #f #f #f)))
      (check (tokens "<!DOCTYPE html PUBLIC \"a>") => '(("DOCTYPE" "html" "a" #f #f)))
      (check (tokens "<!DOCTYPE html bogus>x") => '(("DOCTYPE" "html" #f #f #f) ("Character" "x")))
      (check (tokens "<!DOCTYPE html PUBLIC 'a' 'b'><!doctype html public \"a\" >")
             => '(("DOCTYPE" "html" "a" "b" #t) ("DOCTYPE" "html" "a" #f #t)))
      ;; missing whitespace is an error that keeps the DOCTYPE correct
      (check (tokens "<!DOCTYPEhtml><!DOCTYPE html PUBLIC\"a\"\"b\">")
             => '(("DOCTYPE" "html" #f #f #t) ("DOCTYPE" "html" "a" "b" #t)))
      (check (tokens "<!DOCTYPE html PUBLIC><!DOCTYPE html SYSTEM>")
             => '(("DOCTYPE" "html" #f #f #f) ("DOCTYPE" "html" #f #f #f)))
      ;; text after the system identifier is ignored; after the public one it
      ;; forces quirks
      (check (tokens "<!DOCTYPE html SYSTEM \"a\" x><!DOCTYPE html PUBLIC \"a\" x>")
             => '(("DOCTYPE" "html" #f "a" #t) ("DOCTYPE" "html" "a" #f #f)))
      (check (tokens "<!DOCTYPE html SYSTEM \"a") => '(("DOCTYPE" "html" #f "a" #f)))
      (check (tokens "<!DOCTYPE A\x0;b>") => (list ["DOCTYPE" (string #\a #\xfffd #\b) #f #f #t])))

    (test-case "RCDATA, RAWTEXT and script data end at the appropriate end tag"
      (check (tokens "a</b></title x>c" state: html-state-rcdata last-start-tag: "title")
             => '(("Character" "a</b>") ("EndTag" "title") ("Character" "c")))
      (check (tokens "a</title" state: html-state-rcdata last-start-tag: "title")
             => '(("Character" "a</title")))
      (check (tokens "a</title " state: html-state-rcdata last-start-tag: "title")
             => '(("Character" "a")))
      ;; the tokenizer alone returns to the data state after the end tag
      (check (tokens "</titles></tit><b>&amp;</TiTlE/><b>" state: html-state-rcdata
                     last-start-tag: "title")
             => '(("Character" "</titles></tit><b>&") ("EndTag" "title") ("StartTag" "b" ())))
      (check (tokens "<b>&amp;</style\t>x" state: html-state-rawtext last-start-tag: "style")
             => '(("Character" "<b>&amp;") ("EndTag" "style") ("Character" "x")))
      (check (tokens "</style>" state: html-state-rawtext last-start-tag: "xmp")
             => '(("Character" "</style>")))
      (check (tokens "<!--<script></script>--></script>" state: html-state-script-data
                     last-start-tag: "script")
             => '(("Character" "<!--<script></script>-->") ("EndTag" "script")))
      (check (tokens "x</style>" state: html-state-plaintext) => '(("Character" "x</style>"))))

    (test-case "script data: escaped and double escaped"
      (def (script input)
        (tokens input state: html-state-script-data last-start-tag: "script"))
      ;; </script> ends the escaped state's script
      (check (script "a<!--b</script>c")
             => '(("Character" "a<!--b") ("EndTag" "script") ("Character" "c")))
      ;; <script> in an escape starts the double escape, which </script> ends
      (check (script "<!--<script>x</script>y</SCRIPT >")
             => '(("Character" "<!--<script>x</script>y") ("EndTag" "script")))
      (check (script "<!--<script>-->x</script>")
             => '(("Character" "<!--<script>-->x") ("EndTag" "script")))
      (check (script "<!--<SCRIPT>--</script>-->") => '(("Character" "<!--<SCRIPT>--</script>-->")))
      (check (script "<!-->x</script>") => '(("Character" "<!-->x") ("EndTag" "script")))
      (check (script "<!--<scripts></script>")
             => '(("Character" "<!--<scripts>") ("EndTag" "script")))
      (check (script "<!--\x0;<script>\x0;")
             => (list ["Character" (string-append "<!--" (string #\xfffd)
                                                  "<script>" (string #\xfffd))]))
      ;; the separator after an escaped <script or </script is preprocessed
      (check (script "<!--<script\r></script>--></script>")
             => '(("Character" "<!--<script\n></script>-->") ("EndTag" "script")))
      (check (script "<!--<script></script\r>--></script>")
             => '(("Character" "<!--<script></script\n>-->") ("EndTag" "script")))
      (check (script "<!--<script\r\n></script\r\n>--></script>")
             => '(("Character" "<!--<script\n></script\n>-->") ("EndTag" "script")))
      (check (script "<!--<script\r\nx</script>")
             => '(("Character" "<!--<script\nx</script>")))
      (check (script "<!--<script>x</script\ry</script>")
             => '(("Character" "<!--<script>x</script\ny") ("EndTag" "script"))))

    (test-case "UTF-8 input"
      (check (text (u8vector #xef #xbb #xbf #x61 #xc3 #xa9)) => "a\xe9;")
      (check (text (string #\xfeff #\a)) => (string #\xfeff #\a))
      (check (utf8-error-offset (u8vector #x61 #x62 #xff)) => 2)
      (check (utf8-error-offset (u8vector #x3c #x61 #x20 #x62 #x3d #xc3)) => 5)
      (check (utf8-error-offset (u8vector #x3c #x21 #x2d #x2d #xed #xa0 #x80)) => 4)
      (check (utf8-error-offset (u8vector #x3c #x21 #x44 #x4f #x43 #x54 #x59 #x50 #x45 #x20
                                          #x78 #x20 #x79 #xe0 #x80 #x80 #x3e))
             => 13)
      (check (text (open-input-u8vector (u8vector #x61 #x62))) => "ab")
      (check (text (open-input-string "ab")) => "ab"))

    (test-case "token accessors check the token kind"
      (let (tz (make-html-tokenizer "x"))
        (check-exception (html-token-text tz) true)
        (html-tokenizer-next! tz)
        (check (html-token-text tz) => "x")
        (check-exception (html-token-tag-name tz) true)
        (check (html-tokenizer-next! tz) => html-token-eof)
        (check (html-tokenizer-next! tz) => html-token-eof))
      (check-exception (make-html-tokenizer 'x) true)
      (check-exception (html-tokenizer-state-set! (make-html-tokenizer "") 9) true)
      (for-each (lambda (name)
                  (check-exception (html-tokenizer-last-start-tag-set! (make-html-tokenizer "") name)
                                   true))
                ["" "Title" "a b"]))

    (test-case "field accessors check the token kind and raise as themselves"
      (let (tz (make-html-tokenizer "x<!--c-->"))
        (html-tokenizer-next! tz)
        (for-each (lambda (accessor+name)
                    (check (with-catch (lambda (e)
                                         (and (contract-violation-error? e)
                                              (car (error-irritants e))))
                                       (lambda () ((car accessor+name) tz) #f))
                           => (cdr accessor+name)))
                  [[html-token-self-closing? :: 'html-token-self-closing?]
                   [html-token-data :: 'html-token-data]
                   [html-token-target :: 'html-token-target]
                   [html-token-doctype-name :: 'html-token-doctype-name]
                   [html-token-doctype-public-id :: 'html-token-doctype-public-id]
                   [html-token-doctype-system-id :: 'html-token-doctype-system-id]
                   [html-token-force-quirks? :: 'html-token-force-quirks?]])
        (check (html-tokenizer-next! tz) => html-token-comment)
        (check (html-token-data tz) => "c")))

    (test-case "no token after an invalid UTF-8 error"
      (let (tz (make-html-tokenizer (u8vector #x61 #x3c #x62 #x20 #x63 #x3d #xff #x3e)))
        (check (html-tokenizer-next! tz) => html-token-characters)
        (check-exception (html-tokenizer-next! tz) html-parse-error?)
        (check-exception (html-token-text tz) true)
        (check-exception (html-token-tag-name tz) true)))))
