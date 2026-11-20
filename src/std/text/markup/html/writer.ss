;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML writer: serializes typed HTML trees as UTF-8, as the WHATWG HTML
;;; fragment serialization algorithm does, so that read-html and
;;; read-html-fragment read them back.
(import :std/error
        :std/io/bio/types
        (only-in ../output make-memory-output memory-output-string)
        ../sink
        ./node
        ./emitter)
(export write-html
        html->u8vector
        html->string
        html-escape)

;;; What the writers take: a document, an HTML node, or a fragment, a
;;; proper list of HTML nodes.
(def (html-writable? (x : :t)) => :boolean
  (or (HTMLDocument? x) (html-node? x) ((list-of? html-node?) x)))

;;; Writes node, an HTMLDocument, an HTML node, or a list of HTML nodes (a
;;; fragment, written in order), as UTF-8 to sink: a Writer (including a
;;; BufferedWriter), a byte port, or a character port (as characters).
;;; Raises ContractViolation for any tree the HTML parser would not read
;;; back as written; html.md gives the output and every rejected case.
(def (write-html (node                   :~ html-writable? :- :t)
                 (sink                   :  :t := (current-output-port))
                 scripting?: (scripting? :  :boolean := #t)) => :void
  (unless (write-to-sink sink (lambda ((out :- basic-output-buffer))
                                (emit-html-into! out node scripting?)))
    (raise-bad-argument write-html "Writer or output port" sink)))

(def (emit-html-into! (out        :- basic-output-buffer)
                      (node       :- :t)
                      (scripting? :- :boolean)) => :void
  (emit-html! (make-html-emitter out scripting?) node))

(def (html->u8vector (node                   :~ html-writable? :- :t)
                     scripting?: (scripting? :  :boolean := #t)) => :u8vector
  (let (out (make-memory-output))
    (emit-html-into! out node scripting?)
    (memory-output-u8vector out)))

(def (html->string (node                   :~ html-writable? :- :t)
                   scripting?: (scripting? :  :boolean := #t)) => :string
  (let (out (make-memory-output))
    (emit-html-into! out node scripting?)
    (memory-output-string out)))

;;; str with & < > " ' escaped as &amp; &lt; &gt; &quot; &#39;, for text and
;;; attribute values; str itself when it has none of them.
(def (html-escape (str : :string)) => :string
  (html-escape-string str))
