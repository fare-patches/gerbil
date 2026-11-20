;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Generates the HTML tokenizer's static tables in this directory:
;;;   atoms.ss     known element and attribute names (atom IDs)
;;;   entities.ss  the named character reference trie
;;; Run from the checkout root:
;;;   ./run.sh gxi src/std/text/markup/html/gen.ss <entities.json> src/std/text/markup/html
;;; entities.json is https://html.spec.whatwg.org/entities.json.
(import :std/encoding/json
        :std/encoding/hex
        :std/crypto/digest
        (only-in :std/misc/ports read-all-as-u8vector)
        :std/format
        (only-in :std/text/markup/scan-input fnv-basis fnv))
(export main)

;;; Lowercase ASCII names the tokenizer can produce: the HTML element,
;;; attribute and event handler attribute indices (as in Go's
;;; golang.org/x/net/html/atom), plus names the tree builder dispatches on.
(def known-names
  '("a" "abbr" "accept" "accept-charset" "accesskey" "acronym" "action" "address"
    "align" "allowfullscreen" "allowpaymentrequest" "allowusermedia" "alt"
    "annotation" "annotation-xml" "applet" "area" "article" "as" "aside" "async"
    "audio" "autocomplete" "autofocus" "autoplay" "b" "base" "basefont" "bdi" "bdo"
    "bgsound" "big" "blink" "blockquote" "body" "br" "button" "canvas" "caption"
    "center" "challenge" "charset" "checked" "cite" "class" "code" "col" "colgroup"
    "color" "cols" "colspan" "command" "content" "contenteditable" "contextmenu"
    "controls" "coords" "crossorigin" "data" "datalist" "datetime" "dd" "decoding"
    "default" "defer" "definitionurl" "del" "desc" "details" "dfn" "dialog" "dir"
    "dirname" "disabled" "div" "dl" "download" "draggable" "dropzone" "dt" "em"
    "embed" "encoding" "enctype" "face" "fieldset" "figcaption" "figure" "font"
    "footer" "for" "foreignobject" "form" "formaction" "formenctype" "formmethod"
    "formnovalidate" "formtarget" "frame" "frameset" "h1" "h2" "h3" "h4" "h5" "h6"
    "head" "header" "headers" "height" "hgroup" "hidden" "high" "hr" "href"
    "hreflang" "html" "http-equiv" "i" "icon" "id" "iframe" "image" "img" "inert"
    "input" "inputmode" "ins" "integrity" "is" "isindex" "ismap" "itemid" "itemprop"
    "itemref" "itemscope" "itemtype" "kbd" "keygen" "keytype" "kind" "label" "lang"
    "legend" "li" "link" "list" "listing" "loading" "loop" "low" "main" "malignmark"
    "manifest" "map" "mark" "marquee" "math" "max" "maxlength" "media" "mediagroup"
    "menu" "menuitem" "meta" "meter" "method" "mglyph" "mi" "min" "minlength" "mn"
    "mo" "ms" "mtext" "multiple" "muted" "name" "nav" "nobr" "noembed" "noframes"
    "nomodule" "nonce" "noscript" "novalidate" "object" "ol" "onabort"
    "onafterprint" "onautocomplete" "onautocompleteerror" "onauxclick"
    "onbeforeprint" "onbeforeunload" "onblur" "oncancel" "oncanplay"
    "oncanplaythrough" "onchange" "onclick" "onclose" "oncontextmenu" "oncopy"
    "oncuechange" "oncut" "ondblclick" "ondrag" "ondragend" "ondragenter"
    "ondragexit" "ondragleave" "ondragover" "ondragstart" "ondrop"
    "ondurationchange" "onemptied" "onended" "onerror" "onfocus" "onhashchange"
    "oninput" "oninvalid" "onkeydown" "onkeypress" "onkeyup" "onlanguagechange"
    "onload" "onloadeddata" "onloadedmetadata" "onloadend" "onloadstart"
    "onmessage" "onmessageerror" "onmousedown" "onmouseenter" "onmouseleave"
    "onmousemove" "onmouseout" "onmouseover" "onmouseup" "onmousewheel" "onoffline"
    "ononline" "onpagehide" "onpageshow" "onpaste" "onpause" "onplay" "onplaying"
    "onpopstate" "onprogress" "onratechange" "onrejectionhandled" "onreset"
    "onresize" "onscroll" "onsecuritypolicyviolation" "onseeked" "onseeking"
    "onselect" "onshow" "onsort" "onstalled" "onstorage" "onsubmit" "onsuspend"
    "ontimeupdate" "ontoggle" "onunhandledrejection" "onunload" "onvolumechange"
    "onwaiting" "onwheel" "open" "optgroup" "optimum" "option" "output" "p" "param"
    "pattern" "picture" "ping" "placeholder" "plaintext" "playsinline" "popover"
    "poster" "pre" "preload" "progress" "prompt" "public" "q" "radiogroup" "rb"
    "readonly" "referrerpolicy" "rel" "required" "reversed" "role" "rows" "rowspan"
    "rp" "rt" "rtc" "ruby" "s" "samp" "sandbox" "scope" "scoped" "script" "seamless"
    "search" "section" "select" "selected" "selectedcontent" "shape" "size" "sizes"
    "slot" "small" "sortable" "sorted" "source" "spacer" "span" "spellcheck" "src"
    "srcdoc" "srclang" "srcset" "start" "step" "strike" "strong" "style" "sub"
    "summary" "sup" "svg" "system" "tabindex" "table" "target" "tbody" "td"
    "template" "textarea" "tfoot" "th" "thead" "time" "title" "tr" "track"
    "translate" "tt" "type" "typemustmatch" "u" "ul" "updateviacache" "usemap"
    "value" "var" "video" "wbr" "width" "workertype" "wrap" "xmlns" "xmp"))

;;; The tokenizer's name hash of an ASCII name.
(def (name-hash (name : :string)) => :fixnum
  (let loop ((k 0) (h fnv-basis))
    (if (fx< k (string-length name))
      (loop (fx+ k 1) (fnv h (char->integer (string-ref name k))))
      h)))

(def atom-slot-count 1024)

(def (write-numbers (port    : :port)
                    (prefix  : :string)
                    (numbers : :list)
                    (suffix  : :string)) => :void
  (display prefix port)
  (let loop ((rest numbers) (column (string-length prefix)) (first? #t))
    (when (pair? rest)
      (let* ((str (number->string (car rest)))
             (wrap? (and (not first?) (fx> (fx+ column 1 (string-length str)) 100))))
        (cond
         (wrap? (display "\n   " port))
         ((not first?) (display " " port)))
        (display str port)
        (loop (cdr rest)
              (fx+ (if wrap? 3 column) (if first? 0 1) (string-length str))
              #f))))
  (display suffix port)
  (newline port))

(def (generate-atoms (path : :string)) => :void
  (let* ((names (list-sort string<? known-names))
         (slots (make-vector atom-slot-count 0)))
    (for-each
     (lambda (name id)
       (let probe ((slot (fxand (name-hash name) (fx- atom-slot-count 1))))
         (if (fx= (vector-ref slots slot) 0)
           (vector-set! slots slot id)
           (probe (fxand (fx+ slot 1) (fx- atom-slot-count 1))))))
     names (iota (length names) 1))
    (call-with-output-file path
      (lambda (port)
        (display ";;; -*- Gerbil -*-\n;;; © Gerbil contributors\n" port)
        (display ";;; Generated by gen.ss from its known-names list; do not edit.\n" port)
        (display ";;; Known HTML names as atom IDs 1 .. known-atom-count; 0 is no name.\n" port)
        (display "(export #t)\n\n" port)
        (for-each (lambda (name id)
                    (fprintf port "(defconst atom-%a %a)\n" name id))
                  names (iota (length names) 1))
        (fprintf port "\n(def known-atom-count %a)\n\n" (length names))
        (display ";;; Name of each known atom, by ID.\n" port)
        (display "(def known-atom-names\n  '#(\"\"" port)
        (for-each (lambda (name) (fprintf port "\n     %s" name)) names)
        (display "))\n\n" port)
        (fprintf port ";;; Open-addressing table of %a slots: atom ID or 0, at the name hash\n"
                 atom-slot-count)
        (display ";;; (FNV-1a, 32 bits) modulo the size, probing linearly.\n" port)
        (write-numbers port "(def known-atom-slots\n  '#u16(" (vector->list slots) "))")))))

;;; trie nodes

(defstruct EntityTrie
  ((edges :- :list)       ; alist byte -> EntityTrie
   (value :- :fixnum))    ; 1 + value index, or 0
  transparent: #t)

(def (trie-insert! (root  : EntityTrie)
                   (bytes : :u8vector)
                   (value : :fixnum)) => :void
  (let loop ((node root : EntityTrie) (k 0))
    (if (fx= k (u8vector-length bytes))
      (set! node.value value)
      (let* ((b (u8vector-ref bytes k))
             (edge (assv b node.edges)))
        (if edge
          (loop (cdr edge) (fx+ k 1))
          (let (child (make-EntityTrie '() 0))
            (set! node.edges (cons (cons b child) node.edges))
            (loop child (fx+ k 1))))))))

;;; The trie's nodes in depth-first preorder (root first), so a name's chain
;;; of nodes is mostly contiguous.
(def (trie-nodes (root : EntityTrie)) => :list
  (let loop ((stack [root]) (out '()))
    (if (null? stack)
      (reverse out)
      (using (node (car stack) : EntityTrie)
        (set! node.edges (list-sort (lambda (a b) (fx< (car a) (car b))) node.edges))
        (loop (append (map cdr node.edges) (cdr stack)) (cons node out))))))

;;; Index of byte b in the pair table: letters, then digits.
(def (byte-index (b : :fixnum)) => :fixnum
  (cond
   ((and (fx>= b 65) (fx<= b 90)) (fx- b 65))
   ((and (fx>= b 97) (fx<= b 122)) (fx+ 26 (fx- b 97)))
   ((and (fx>= b 48) (fx<= b 57)) (fx+ 52 (fx- b 48)))
   (else 255)))

(def (generate-entities (json-path : :string)
                        (path      : :string)) => :void
  (let* ((input-sha256 (hex-encode (sha256 (call-with-input-file [path: json-path]
                                               (lambda (port) (read-all-as-u8vector port))))))
         (table (parameterize ((current-json-read-options
                                (JSONReadOptions object-as-hash: #t)))
                  (call-with-input-file json-path read-json)))
         (entries (list-sort (lambda (a b) (string<? (car a) (car b)))
                             (map (lambda (pair)
                               (let ((name (car pair))
                                     (codepoints (hash-ref (cdr pair) "codepoints")))
                                 (cons (substring name 1 (string-length name)) codepoints)))
                             (hash->list table))))
         (values-table (make-hash-table))
         (value-list '())
         (root (make-EntityTrie '() 0)))
    ;; value index + 1 per distinct UTF-8 encoding
    (for-each
     (lambda (entry)
       (let* ((utf8 (string->utf8 (list->string (map integer->char (cdr entry)))))
              (key (u8vector->list utf8))
              (index (or (hash-get values-table key)
                         (let (index (fx+ (hash-length values-table) 1))
                           (hash-put! values-table key index)
                           (set! value-list (cons utf8 value-list))
                           index))))
         (trie-insert! root (string->utf8 (car entry)) index)))
     entries)
    (let* ((nodes (trie-nodes root))
           (ids (let (h (make-hash-table-eq))
                  (for-each (lambda (node id) (hash-put! h node id)) nodes (iota (length nodes)))
                  h))
           (edge-start (let loop ((rest nodes) (k 0) (out '()))
                         (if (null? rest)
                           (reverse (cons k out))
                           (using (node (car rest) : EntityTrie)
                             (loop (cdr rest) (fx+ k (length node.edges)) (cons k out))))))
           (edges (foldr append '() (map EntityTrie-edges nodes)))
           (pair-child (let (table (make-vector (fx* 52 62) 0))
                         (for-each
                          (lambda (edge1)
                            (for-each
                             (lambda (edge2)
                               (vector-set! table
                                            (fx+ (fx* (byte-index (car edge1)) 62)
                                                 (byte-index (car edge2)))
                                            (hash-ref ids (cdr edge2))))
                             (using (node (cdr edge1) : EntityTrie)
                               node.edges)))
                          (using (root : EntityTrie)
                            root.edges))
                         (vector->list table)))
           (value-bytes (reverse value-list))
           (value-start (let loop ((rest value-bytes) (k 0) (out '()))
                          (if (null? rest)
                            (reverse (cons k out))
                            (loop (cdr rest) (fx+ k (u8vector-length (car rest))) (cons k out))))))
      (call-with-output-file path
        (lambda (port)
          (display ";;; -*- Gerbil -*-\n;;; © Gerbil contributors\n" port)
          (display ";;; Generated by gen.ss from WHATWG entities.json; do not edit.\n" port)
          (fprintf port ";;; entities.json sha256 %a.\n" input-sha256)
          (fprintf port ";;; %a names, %a trie nodes, %a distinct values.\n"
                   (length entries) (length nodes) (length value-bytes))
          (display ";;; The named character reference trie: node 0 is the root; the edges\n" port)
          (display ";;; of node n are [entity-edge-start[n], entity-edge-start[n + 1]),\n" port)
          (display ";;; sorted by byte; entity-node-value[n] is 1 + the index of the UTF-8\n" port)
          (display ";;; value of the name ending at n, or 0. Names exclude the &.\n" port)
          (display "(export #t)\n\n" port)
          (display ";;; Index of each byte: A-Z 0..25, a-z 26..51, 0-9 52..61, others 255.\n" port)
          (write-numbers port "(def entity-byte-index\n  '#u8(" (map byte-index (iota 256)) "))")
          (newline port)
          (display ";;; The node after the first two bytes of a name (every name has at\n" port)
          (display ";;; least two, both alphanumeric) at index[b1] * 62 + index[b2], or 0.\n" port)
          (write-numbers port "(def entity-pair-child\n  '#u16(" pair-child "))")
          (newline port)
          (write-numbers port "(def entity-edge-start\n  '#u16(" edge-start "))")
          (newline port)
          (write-numbers port "(def entity-edge-byte\n  '#u8(" (map car edges) "))")
          (newline port)
          (write-numbers port "(def entity-edge-target\n  '#u16("
                         (map (lambda (edge) (hash-ref ids (cdr edge))) edges) "))")
          (newline port)
          (write-numbers port "(def entity-node-value\n  '#u16(" (map EntityTrie-value nodes) "))")
          (newline port)
          (display ";;; Value k (from 1) is entity-value-bytes[start[k - 1], start[k]).\n" port)
          (write-numbers port "(def entity-value-start\n  '#u16(" value-start "))")
          (newline port)
          (write-numbers port "(def entity-value-bytes\n  '#u8("
                         (foldr append '() (map u8vector->list value-bytes)) "))"))))))

(def (main (json-path : :string)
           (dir       : :string)) => :void
  (generate-atoms (path-expand "atoms.ss" dir))
  (generate-entities json-path (path-expand "entities.ss" dir)))
