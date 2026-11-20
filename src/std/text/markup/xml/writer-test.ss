;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/interface
        :std/io
        (only-in :std/io/bio/cache buffer-cache.get buffer-cache.put!)
        :std/text/markup/xml/types
        :std/text/markup/xml/reader
        :std/text/markup/xml/writer
        (only-in :std/text/markup/html/types make-html-element make-html-raw)
        (only-in :std/text/markup/html/reader read-html-fragment))
(export writer-test)

(def (name local (uri "") (prefix ""))
  (make-xml-name local uri prefix))

(def (element local attrs . children)
  (make-xml-element (name local)
                    (map (lambda (a) (make-xml-attribute (name (car a)) (cdr a))) attrs)
                    children))

;;; A Writer to target that counts its writes and records a close; every
;;; write raises #f while fail? is set.
(defstruct recording-writer
  ((target  :- BufferedWriter)
   (fail?   :- :boolean)
   (writes  :- :fixnum)
   (closed? :- :boolean)))

(defmethod {write recording-writer}
  (lambda (self input start end)
    (using (self :- recording-writer)
      (set! self.writes (fx+ self.writes 1))
      (if self.fail?
        (raise #f)
        (self.target.write input start end))))
  interface: Writer)

(defmethod {close recording-writer}
  (lambda (self)
    (using (self :- recording-writer)
      (set! self.closed? #t)))
  interface: Closer)

(@implement Writer recording-writer)

;;; Whether the buffer of stdio's default size that the buffer cache hands
;;; out next is back in the cache after (thunk): the cache hands out the
;;; buffer released last first.
(def (released-after? thunk)
  (let (buf (buffer-cache.get default-buffer-size))
    (buffer-cache.put! buf)
    (thunk)
    (let (next (buffer-cache.get default-buffer-size))
      (buffer-cache.put! next)
      (eq? next buf))))

(def writer-test
  (test-suite "test :std/text/markup/xml/writer"
    (test-case "escapes text and attribute values; empty elements self-close"
      (check (xml->string (element "r" '(("a" . "<&\"\t\n\r>"))
                                   (make-xml-text "a<b & c>d\r")
                                   (element "e" '())))
             => "<r a=\"&lt;&amp;&quot;&#9;&#10;&#13;>\">a&lt;b &amp; c&gt;d&#13;<e/></r>"))

    (test-case "comments, processing instructions, CDATA and documents"
      (check (xml->string (make-xml-document
                           [(make-xml-pi "p" "d")]
                           (element "r" '() (make-xml-comment " c ") (make-xml-cdata "<x>")
                                    (make-xml-pi "q" ""))
                           [(make-xml-comment "e")]))
             => "<?p d?><r><!-- c --><![CDATA[<x>]]><?q?></r><!--e-->"))

    (test-case "non-ASCII text is written as UTF-8"
      (check (xml->u8vector (element "r" '() (make-xml-text "\xe9;\x1F600;")))
             => (string->utf8 "<r>\xe9;\x1F600;</r>")))

    (test-case "read then write then read is the identity"
      (let* ((input "<r xmlns='urn:a' xmlns:b='urn:b' a='x &amp; y'><b:c b:d='1'>t &lt; u<![CDATA[]]]]>\r\n</b:c><s xmlns=''/></r>")
             (doc (read-xml input))
             (again (read-xml (xml->string doc))))
        (check (xml->string again) => (xml->string doc))
        (check (xml->string doc)
               => "<r xmlns=\"urn:a\" xmlns:b=\"urn:b\" a=\"x &amp; y\"><b:c b:d=\"1\">t &lt; u]]\n</b:c><s xmlns=\"\"/></r>")))

    (test-case "keep-space? and keep-comments? trees write and read back unchanged"
      (let (input "<!--p\r\nq--><?a x?><r>\n <a> x </a>a<!--c-->b<![CDATA[ ]]> <!-- d --> </r>\n<!--e-->")
        (for-each
         (lambda (options)
           (let (out (xml->string (apply read-xml input options)))
             (check (cons options (xml->string (apply read-xml out options))) => (cons options out))))
         '(() (keep-space?: #t) (keep-comments?: #t) (keep-space?: #t keep-comments?: #t)))
        (check (xml->string (read-xml input keep-space?: #t keep-comments?: #t))
               => "<!--p\nq--><?a x?><r>\n <a> x </a>a<!--c-->b  <!-- d --> </r><!--e-->")))

    (test-case "prolog comments and PIs after the DOCTYPE are written before it"
      (let (out (xml->string (read-xml "<?a x?><!DOCTYPE r><!--c--><?b y?><r/>" keep-comments?: #t)))
        (check out => "<?a x?><!--c--><?b y?><!DOCTYPE r><r/>")
        (check (xml->string (read-xml out keep-comments?: #t)) => out))
      (check (xml->string (read-xml "<!DOCTYPE r><!--c--><?b y?><r/>")) => "<?b y?><!DOCTYPE r><r/>"))

    (test-case "declares namespaces that hand-built names need"
      (check (xml->string (make-xml-element (name "r" "urn:a") []
                                            [(make-xml-element (name "c" "urn:b" "b") [] [])
                                             (make-xml-element (name "d") [] [])]))
             => "<r xmlns=\"urn:a\"><b:c xmlns:b=\"urn:b\"/><d xmlns=\"\"/></r>")
      (check (xml->string (make-xml-element (name "r") [(make-xml-attribute (name "k" "urn:k") "v")] []))
             => "<r xmlns:ns1=\"urn:k\" ns1:k=\"v\"/>")
      (check (xml->string (make-xml-element (name "r") [(make-xml-attribute (name "lang" xml-namespace-uri "xml") "en")] []))
             => "<r xml:lang=\"en\"/>"))

    (test-case "many declarations in scope: each binding ends with its element"
      (def (numbered n make)
        (string-concatenate (map (lambda (k) (make (number->string k))) (iota n))))
      ;; 2000 nested elements each declaring a prefix, around one using the
      ;; root's; then one element with 2000 declarations and attributes
      (for-each
       (lambda (input)
         (check (xml->string (read-xml input)) => input))
       [(string-append "<a:r xmlns:a=\"urn:a\">"
                       (numbered 2000 (lambda (k) (string-append "<a:e xmlns:b" k "=\"urn:b" k "\">")))
                       "<a:e a:x=\"1\" b0:y=\"2\" b1999:z=\"3\"/>"
                       (string-concatenate (make-list 2000 "</a:e>"))
                       "</a:r>")
        (string-append "<r"
                       (numbered 2000 (lambda (k) (string-append " xmlns:p" k "=\"urn:p" k "\" p" k ":a=\"1\"")))
                       "/>")])
      (let* ((declare (lambda (prefix uri) (make-xml-attribute (name prefix xmlns-namespace-uri) uri)))
             (in-u (lambda (local prefix) (make-xml-element (name local "urn:u" prefix) [] []))))
        ;; a binding made by an element is gone at its end: its sibling
        ;; declares the prefix again
        (check (xml->string (make-xml-element (name "r") []
                                              [(make-xml-element (name "c") [(declare "p" "urn:u")]
                                                                 [(in-u "d" "p")])
                                               (in-u "e" "p")]))
               => "<r><c xmlns:p=\"urn:u\"><p:d/></c><p:e xmlns:p=\"urn:u\"/></r>")
        ;; a prefix bound again to another namespace no longer names the
        ;; first; the outer prefix q still does
        (check (xml->string (make-xml-element (name "r") [(declare "q" "urn:u") (declare "p" "urn:u")]
                                              [(make-xml-element (name "c")
                                                                 [(declare "p" "urn:v")
                                                                  (make-xml-attribute (name "a" "urn:u") "1")]
                                                                 [])]))
               => "<r xmlns:q=\"urn:u\" xmlns:p=\"urn:u\"><c xmlns:p=\"urn:v\" q:a=\"1\"/></r>")
        (check (xml->string (make-xml-element (name "r") [(declare "p" "urn:u")]
                                              [(make-xml-element (name "c")
                                                                 [(declare "p" "urn:v")
                                                                  (make-xml-attribute (name "a" "urn:u" "p") "1")]
                                                                 [])]))
               => "<r xmlns:p=\"urn:u\"><c xmlns:p=\"urn:v\" xmlns:ns1=\"urn:u\" ns1:a=\"1\"/></r>")
        ;; the outer prefix q is found past 8 prefixes bound again, not past
        ;; 9 (max-stale-prefixes): a new one is declared instead
        (let (rebound (lambda (n)
                        (let (prefixes (map (lambda (k) (string-append "p" (number->string k))) (iota n)))
                          (xml->string
                           (make-xml-element (name "r")
                                             (cons (declare "q" "urn:u")
                                                   (map (cut declare <> "urn:u") prefixes))
                                             [(make-xml-element
                                               (name "c")
                                               (append (map (cut declare <> "urn:v") prefixes)
                                                       [(make-xml-attribute (name "a" "urn:u") "1")])
                                               [])])))))
          (check (string-suffix? "\" q:a=\"1\"/></r>" (rebound 8)) => #t)
          (check (string-suffix? "\" xmlns:ns1=\"urn:u\" ns1:a=\"1\"/></r>" (rebound 9)) => #t))))

    (test-case "names in reserved namespaces round trip"
      (for-each
       (lambda (el)
         (let (out (xml->string el))
           (check (xml->string (read-xml out)) => out)))
       [(make-xml-element (name "lang" xml-namespace-uri "xml") [] [])
        (make-xml-element (name "r" "urn:a")
                          [(make-xml-attribute (name "xmlns" xmlns-namespace-uri) "urn:a")
                           (make-xml-attribute (name "lang" xml-namespace-uri "xml") "en")]
                          [(make-xml-element (name "c" "urn:a") [] [])])]))

    (test-case "sinks: Writer, BufferedWriter, byte and character ports"
      (let ((node (element "r" '() (make-xml-text "\xe9;")))
            (expected (string->utf8 "<r>\xe9;</r>")))
        (let (w (open-buffered-writer #f))
          (write-xml node w)
          (check (get-memory-output-u8vector w) => expected))
        (check (call-with-output-u8vector #u8() (lambda (port) (write-xml node port))) => expected)
        (check (call-with-output-string "" (lambda (port) (write-xml node port))) => "<r>\xe9;</r>")
        (check-exception (write-xml node 42) contract-violation-error?)
        (check-exception (write-xml node (open-input-string "x")) contract-violation-error?)
        ;; a closed BufferedWriter
        (let (w (open-buffered-writer #f))
          (BufferedWriter-close w)
          (check-exception (write-xml node w) io-closed-error?))
        ;; a port receives nothing when the writer raises
        (let (bad (element "r" '() (make-xml-text (make-string 100000 #\a)) (make-xml-text "\x1;")))
          (check (call-with-output-u8vector
                  #u8() (lambda (port) (with-catch void (lambda () (write-xml bad port)))))
                 => #u8())
          (check (call-with-output-string
                  "" (lambda (port) (with-catch void (lambda () (write-xml bad port)))))
                 => ""))))

    (test-case "sinks: a failure releases the temporary buffer and leaves the sink open"
      (let ((node (element "r" '() (make-xml-text "x")))
            (bad (element "r" '() (make-xml-text "\x1;")))
            (big (element "r" '() (make-xml-text (make-string 100000 #\a)))))
        (def (raised thunk)
          (with-catch (lambda (e) [e]) (lambda () (thunk) 'returned)))
        ;; an emitter exception: raised as is; the Writer gets no write
        (let (w (make-recording-writer (open-buffered-writer #f) #f 0 #f))
          (check (released-after?
                  (lambda ()
                    (check-exception (write-xml bad w) contract-violation-error?)))
                 => #t)
          (check (recording-writer-writes w) => 0)
          (check (recording-writer-closed? w) => #f)
          (write-xml node w)
          (check (get-memory-output-u8vector (recording-writer-target w))
                 => (string->utf8 "<r>x</r>")))
        ;; a write failure, at the end and while the buffer drains: the raised
        ;; #f as is, after one write, which is not retried
        (for-each
         (lambda (doc)
           (let (w (make-recording-writer (open-buffered-writer #f) #t 0 #f))
             (check (released-after?
                     (lambda ()
                       (check (raised (lambda () (write-xml doc w))) => [#f])))
                    => #t)
             (check (recording-writer-writes w) => 1)
             (check (recording-writer-closed? w) => #f)))
         [node big])
        ;; a caller's BufferedWriter stays the caller's, open
        (let (w (open-buffered-writer #f))
          (check-exception (write-xml bad w) contract-violation-error?)
          (check (BufferedWriter-write-u8 w 0) => 1))))

    (test-case "long strings and large outputs: slices and buffer drains"
      (def (repeat str n)
        (string-concatenate (make-list n str)))
      ;; one string slice holds 5461 characters (32768, stdio's default
      ;; buffer size, / 6); cross that boundary with plain, escaped and 4-byte
      ;; characters
      (for-each
       (lambda (n)
         (for-each
          (lambda (unit)
            (let* ((data (repeat unit n))
                   (node (element "r" [(cons "a" data)] (make-xml-text data)))
                   (bytes (xml->u8vector node))
                   (w (open-buffered-writer #f)))
              (write-xml node w)
              (check (get-memory-output-u8vector w) => bytes)
              (check (xml->string node) => (utf8->string bytes))
              (using ((doc (read-xml bytes) : XMLDocument)
                      (text (car doc.root.children) : XMLText)
                      (attr (car doc.root.attributes) : XMLAttribute))
                (check text.data => data)
                (check attr.value => data))))
          ["x" "\"&<" "\x1F600;"]))
       [5457 5461 5465 10923 10926])
      ;; more than one stdio buffer through a BufferedWriter, a Writer, a
      ;; BufferedWriter whose small buffer drains to a Writer and grows, and
      ;; a byte port
      (let* ((node (make-xml-element
                    (name "r") []
                    (map (lambda (k)
                           (element "e" [(cons "k" (number->string k))] (make-xml-text "t\xe9;")))
                         (iota 20000))))
             (bytes (xml->u8vector node))
             (w (open-buffered-writer #f)))
        (check (> (u8vector-length bytes) (* 3 65536)) => #t)
        (write-xml node w)
        (check (get-memory-output-u8vector w) => bytes)
        (let (target (open-buffered-writer #f))
          (write-xml node (open-detachable-writer target))
          (check (get-memory-output-u8vector target) => bytes))
        (let* ((target (open-buffered-writer #f))
               (small (open-buffered-writer (open-detachable-writer target) 64)))
          (write-xml node small)
          (BufferedWriter-flush small)
          (check (get-memory-output-u8vector target) => bytes))
        (check (call-with-output-u8vector #u8() (lambda (port) (write-xml node port))) => bytes)))

    (test-case "rejects characters XML cannot represent and non-nodes"
      (check-exception (xml->string (element "r" '() (make-xml-text "\x1;"))) contract-violation-error?)
      (check-exception (xml->string (element "r" '(("a" . "\xFFFE;")))) contract-violation-error?)
      (check-exception (xml->string "text") contract-violation-error?)
      ;; an HTML node XML has no syntax for
      (check-exception (xml->string (make-html-element "p" [] [(make-html-raw "<b>")]))
                       contract-violation-error?))

    (test-case "rejects trees XML cannot represent, such as HTML-parsed ones"
      (def (rejects? node)
        (with-catch contract-violation-error? (lambda () (xml->string node) #f)))
      (for-each
       (lambda (input)
         (check (cons input (rejects? (car (read-html-fragment input)))) => (cons input #t)))
       [;; comments with -- or a final -
        "<p><!-- a -- b -></p>" "<p><!--x---></p>"
        ;; invalid namespace declarations
        "<svg xmlns:xlink=''></svg>" "<svg xmlns:xlink='http://www.w3.org/2000/xmlns/'></svg>"
        "<svg xmlns:xlink='http://www.w3.org/XML/1998/namespace'></svg>"
        ;; an HTML attribute xmlns, in no namespace, would read back as one
        "<div xmlns='urn:x'><p></p></div>"
        ;; an xmlns declaration the element's own namespace contradicts
        "<svg xmlns='urn:x'></svg>"])
      (check (with-catch (lambda (e)
                           (and (member "attribute named xmlns in xmlns-namespace-uri, not in no namespace"
                                        (error-irritants e))
                                #t))
                         (lambda () (xml->string (car (read-html-fragment "<div xmlns='urn:x'></div>")))))
             => #t)
      ;; what XML can represent is still written
      (check (xml->string (car (read-html-fragment "<p><!-- a - b --></p>"))) => "<p><!-- a - b --></p>")
      (check (xml->string (car (read-html-fragment "<svg xmlns:xlink='urn:x'></svg>")))
             => "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"urn:x\"/>"))

    (test-case "every node kind, namespaces and a DOCTYPE in one document"
      (let* ((root (make-xml-element (name "r" "urn:r" "p")
                                     [(make-xml-attribute (name "a" "urn:a" "q") "1")]
                                     [(make-xml-text "t") (make-xml-comment "c") (make-xml-cdata "d")
                                      (make-xml-pi "p" "x")]))
             (doc (make-xml-document [(make-xml-comment "b")] root [(make-xml-pi "e" "")]
                                     (make-xml-doctype "r" "-//X//EN" "r.dtd"))))
        (check (xml->string doc)
               => (string-append "<!--b--><!DOCTYPE r PUBLIC \"-//X//EN\" \"r.dtd\">"
                                 "<p:r xmlns:p=\"urn:r\" xmlns:q=\"urn:a\" q:a=\"1\">"
                                 "t<!--c--><![CDATA[d]]><?p x?></p:r><?e?>"))))

    (test-case "names longer than one output slice"
      (for-each
       (lambda (n)
         (let* ((local (make-string n #\n))
                (input (string-append "<" local " " local "=\"v\"><?" local " d?></" local ">"))
                (doc (read-xml input)))
           (check (xml->string doc) => input)
           (check (xml->string (read-xml (xml->u8vector doc))) => input)))
       [20000 1000000]))

    (test-case "document type declarations"
      (def (doc doctype)
        (make-xml-document [] (element "r" '()) [] doctype))
      (check (xml->string (doc (make-xml-doctype "r"))) => "<!DOCTYPE r><r/>")
      (check (xml->string (doc (make-xml-doctype "r" #f "a\"b"))) => "<!DOCTYPE r SYSTEM 'a\"b'><r/>")
      (check (xml->string (doc (make-xml-doctype "p:r" "-//X//EN" "r.dtd")))
             => "<!DOCTYPE p:r PUBLIC \"-//X//EN\" \"r.dtd\"><r/>")
      (let (out (xml->string (doc (make-xml-doctype "r" "-//X//EN" "\xe9;.dtd"))))
        (check (xml->string (read-xml out)) => out)))))
