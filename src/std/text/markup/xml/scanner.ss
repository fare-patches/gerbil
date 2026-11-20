;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; XML scanner: builds a typed tree from UTF-8 bytes in one pass.
;;; Unchecked internals; :std/text/markup/xml/reader checks arguments and
;;; supplies the input buffer.
(import :std/error
        (only-in :std/struct/rbtree RBTree make-RBTree rbtree-ref rbtree-put! string-cmp)
        (only-in :std/encoding/utf8
                 &put-utf8!
                 &utf8-encode
                 &utf8-sequence-length
                 &utf8-code-at
                 &utf8-count-continuations
                 &utf8-decode
                 utf8-error?
                 UTF8Error-offset)
        :std/io/bio/types
        (only-in ../output make-memory-output output-reserve! output-append!)
        ./node
        ../scan-input)
(export scan-xml-document
        string->xml-scan-input
        XMLParseError
        XMLParseError?
        xml-parse-error?
        XMLParseError-offset)
(declare (not safe))

;;; Input contract: buf holds the document in [0, end) and buf[end] is 0.
;;; Byte 0 is never valid XML, so every scanning loop stops at the sentinel
;;; without a bounds check; multi-byte lookahead matches one byte at a time,
;;; so it never reads past the sentinel either.

;;; byte classes

;;; Character data and attribute values share the class codes; text-class
;;; marks ] (for ]]>) and attribute-class marks TAB and LF (normalized to
;;; spaces) with the same code 4.
(defconst class-plain 0)
(defconst class-lt 1)
(defconst class-amp 2)
(defconst class-cr 3)
(defconst class-bracket 4)        ; text: ]
(defconst class-tab-lf 4)         ; attribute values: TAB or LF
(defconst class-continuation 5)   ; UTF-8 continuation byte
(defconst class-high 6)           ; other byte >= #x80
(defconst class-invalid 7)        ; C0 control other than TAB/LF/CR; the sentinel
(defconst class-quote 8)          ; attribute values: " or '

(def (control-byte? (b :- :fixnum)) => :boolean
  (and (fx< b (ascii #\space))
       (not (fx= b (ascii #\tab)))
       (not (fx= b (ascii #\newline)))
       (not (fx= b (ascii #\return)))))

(def (high-byte-class (b :- :fixnum)) => :fixnum
  (if (fx< b #xc0) class-continuation class-high))

(def text-class
  (make-byte-table
   (lambda (b)
     (cond
      ((control-byte? b) class-invalid)
      ((fx= b (ascii #\<)) class-lt)
      ((fx= b (ascii #\&)) class-amp)
      ((fx= b (ascii #\return)) class-cr)
      ((fx= b (ascii #\])) class-bracket)
      ((fx< b #x80) class-plain)
      (else (high-byte-class b))))))

(def attribute-class
  (make-byte-table
   (lambda (b)
     (cond
      ((control-byte? b) class-invalid)
      ((fx= b (ascii #\<)) class-lt)
      ((fx= b (ascii #\&)) class-amp)
      ((fx= b (ascii #\return)) class-cr)
      ((or (fx= b (ascii #\tab)) (fx= b (ascii #\newline))) class-tab-lf)
      ((or (fx= b (ascii #\")) (fx= b (ascii #\'))) class-quote)
      ((fx< b #x80) class-plain)
      (else (high-byte-class b))))))

(defrule (skip-space buf i)
  (let skip ((k i))
    (if (xml-space? (##u8vector-ref buf k)) (skip (fx+ k 1)) k)))

;;; In-place list reversal, inline: ##reverse!, a call per closed element,
;;; instead took 13% more instructions and 10% more cycles reading nested
;;; elements (markup-benchmark.ss mode xml-read-nested, SIZE 1600,
;;; ITERATIONS 2000).
(defrule (reverse-in-place! lst)
  (let loop ((rest lst) (result '()))
    (if (pair? rest)
      (let (next (##cdr rest))
        (##set-cdr! rest result)
        (loop next rest))
      result)))

(definline (name-start-byte? (b :- :fixnum)) => :boolean
  (let (c (##u8vector-ref name-class b))
    (or (fx= c name-start) (fx= c name-high))))

(definline (name-byte? (b :- :fixnum)) => :boolean
  (not (fx= (##u8vector-ref name-class b) name-other)))

;;; state

;;; value is the result register: scanning procedures return the next index
;;; and leave the token they produced here, so no multiple values are
;;; allocated on the hot path.
(defstruct XMLScanner
  ((buf        :- :u8vector)
   (end        :- :fixnum)
   (mapped?    :- :boolean)  ; buf was encoded from the input: map error offsets
   (scratch    :- memory-output-buffer) ; character data rewritten for references and CR
   (names      :- :vector)   ; qname intern table (open addressing)
   (name-count :- :fixnum)
   (stack      :- :vector)   ; open element frames
   (prefixes   :- :list)     ; (prefix . XMLPrefixBinding) of the first few prefixes
   (prefix-count :- :fixnum) ; entries in prefixes
   (prefix-tree :? RBTree)   ; XMLPrefixBinding by prefix for the others, or #f
   (declared   :- :list)     ; XMLPrefixBinding values the current start tag pushed
   (default-ns :- :string)
   (pending    :- :vector)   ; start tag's prefixed and xmlns attributes
   (keep-space? :- :boolean) ; keep whitespace-only text
   (keep-comments? :- :boolean) ; keep comments as nodes; text does not merge across them
   (value      :- :t))
  final: #t)

;;; XMLQNameEntry kinds
(defconst kind-plain 0)          ; unprefixed
(defconst kind-prefixed 1)
(defconst kind-xmlns 2)          ; the attribute name xmlns
(defconst kind-xmlns-prefix 3)   ; xmlns:prefix

;;; The namespaces a prefix is bound to by the open elements, innermost
;;; first; empty while it is unbound. Declarations push onto it and their
;;; element's end pops them, so a lookup is a field read (expat's design).
(defstruct XMLPrefixBinding
  ((uris :- :list))
  final: #t)

;;; Interned qualified name, keyed by its bytes.
(defstruct XMLQNameEntry
  ((key        :- :u8vector)
   (hash       :- :fixnum)
   (prefix     :- :string)
   (local      :- :string)
   (kind       :- :fixnum)
   (plain-name :? XMLName)  ; name outside any namespace, or the xmlns name
   (cache-uri  :- :string)   ; last namespace this qname resolved in
   (cache-name :? XMLName)
   (binding    :? XMLPrefixBinding)) ; of the prefix it uses or (xmlns:) declares, once needed
  final: #t)

(def max-interned-names 4096)
;;; Longest probe sequence; a name whose slot lies farther is not interned,
;;; so colliding names cost a bounded lookup each.
(def max-probes 16)

;;; Open elements are frames of 7 slots in one growable vector: qname start
;;; and end (for the end tag), name, attributes, the parent's children, the
;;; prefix bindings the element declared and the default namespace to restore.
(def frame-size 7)

;;; Prefixed and xmlns attributes carry this name until resolution.
(def unresolved-name (unchecked-node XMLName "" "" ""))

;;; errors

;;; A well-formedness error at offset in the input: bytes for byte input,
;;; characters for string input.
(deferror-class (XMLParseError IOError) (offset) xml-parse-error?)

;;; XMLParseError at the end of input.
(deferror-class (XMLPrematureEndOfInput XMLParseError PrematureEndOfInput) ())

;;; UTF-8 encodes str into a scan input buffer (../scan-input); a lone surrogate,
;;; which Gambit's port decoders return for an encoded surrogate, raises
;;; XMLParseError at its character index, as a character XML does not allow.
(def (string->xml-scan-input (str :- :string)) => :u8vector
  (with-catch (lambda (e)
                (if (utf8-error? e)
                  (let (offset (UTF8Error-offset e))
                    (raise (XMLParseError "character not allowed in XML"
                                          offset: offset
                                          where: 'read-xml
                                          irritants: ['offset offset])))
                  (raise e)))
              (lambda () (&utf8-encode str 0 (##string-length str) 1))))

(def (raise-scan-error (st      :- XMLScanner)
                       (i       :- :fixnum)
                       (message :- :string)) => :void
  (let (offset (scan-input-offset st.buf st.end st.mapped? i))
    (raise
     (if (fx>= i st.end)
       (XMLPrematureEndOfInput "unexpected end of input"
                               offset: offset
                               where: 'read-xml
                               irritants: ['offset offset])
       (XMLParseError message
                      offset: offset
                      where: 'read-xml
                      irritants: ['offset offset])))))

(defrule (scan-error st i message)
  (abort! (raise-scan-error st i message)))

(defrule (expect-byte! st buf i byte message)
  (unless (fx= (##u8vector-ref buf i) byte)
    (scan-error st i message)))

;;; UTF-8

;;; Length of the UTF-8 sequence at buf[k], whose first byte is >= #x80, of
;;; a character XML allows; raises at k for ill-formed UTF-8 (surrogates
;;; included) and for the noncharacters U+FFFE and U+FFFF (EF BF BE, EF BF
;;; BF), which are well-formed.
(defrule (xml-char-length st buf k)
  (let* ((i k)
         (len (&utf8-sequence-length buf i)))
    (cond
     ((fx= len 0)
      (scan-error st i "invalid UTF-8"))
     ((and (fx= len 3)
           (fx= (##u8vector-ref buf i) #xef)
           (fx= (##u8vector-ref buf (fx+ i 1)) #xbf)
           (fx>= (##u8vector-ref buf (fx+ i 2)) #xbe))
      (scan-error st i "character not allowed in XML"))
     (else len))))

;;; Checks the UTF-8 sequences from j, the index of a byte >= #x80, then
;;; continues with (loop k continuations) at the next ASCII byte, counting
;;; their continuation bytes. &utf8-check-run, but with xml-char-length:
;;; XML also rejects U+FFFE and U+FFFF.
(defrule (high-run st buf j continuations loop)
  (let run ((k j) (n continuations))
    (if (fx< (##u8vector-ref buf k) #x80)
      (loop k n)
      (let (len (xml-char-length st buf k))
        (run (fx+ k len) (fx+ n (fx- len 1)))))))

;;; String of the checked buf[s, e) given its count of continuation bytes,
;;; which the scanning loops keep.
(defrule (span-string buf s e continuations)
  (let ((start s) (end e))
    (&utf8-decode buf start end (fx- (fx- end start) continuations))))

;;; String of the checked buf[s, e), counting its continuation bytes first.
(def (utf8-span-string (buf :- :u8vector)
                       (s   :- :fixnum)
                       (e   :- :fixnum)) => :string
  (span-string buf s e (&utf8-count-continuations buf s e)))

(def (whitespace-span? (buf :- :u8vector)
                       (s   :- :fixnum)
                       (e   :- :fixnum)) => :boolean
  (let loop ((i s))
    (cond
     ((fx>= i e) #t)
     ((xml-space? (##u8vector-ref buf i)) (loop (fx+ i 1)))
     (else #f))))

;;; scratch buffer

;;; Appends code point c (an ASCII byte, or a referenced character) as UTF-8.
(def (scratch-append-char! (st :- XMLScanner)
                           (c  :- :fixnum)) => :void
  (using (out st.scratch :- memory-output-buffer)
    (let (scratch (output-reserve! out 4))
      (set! out.whi (&put-utf8! scratch out.whi c)))))

;;; Appends buf[seg, j) and an LF for the line end at j; returns the index
;;; after the line end.
(def (scratch-append-line! (st  :- XMLScanner)
                           (buf :- :u8vector)
                           (seg :- :fixnum)
                           (j   :- :fixnum)) => :fixnum
  (output-append! st.scratch buf seg j)
  (scratch-append-char! st (ascii #\newline))
  (after-cr buf j))

;;; Takes the scratch contents as a string, or #f when drop-space? is set and
;;; they are only XML whitespace, and empties the scratch.
(def (scratch-text (st          :- XMLScanner)
                   (drop-space? :- :boolean)) => (Maybe :string)
  (using (out st.scratch :- memory-output-buffer)
    (let ((scratch out.buf)
          (fill out.whi))
      (set! out.whi 0)
      (if (and drop-space? (whitespace-span? scratch 0 fill))
        #f
        (utf8-span-string scratch 0 fill)))))

;;; String of buf[s, e) with its line ends normalized; uses the scratch, which
;;; must be empty.
(def (span-text (st :- XMLScanner)
                (s  :- :fixnum)
                (e  :- :fixnum)) => :string
  (let (buf st.buf)
    (let loop ((seg s) (j s))
      (cond
       ((fx>= j e)
        (if (fx= seg s)
          (utf8-span-string buf s e)
          (begin
            (output-append! st.scratch buf seg e)
            (:- (scratch-text st #f) :string))))
       ((fx= (##u8vector-ref buf j) (ascii #\return))
        (let (next (scratch-append-line! st buf seg j))
          (loop next next)))
       (else (loop seg (fx+ j 1)))))))

;;; True when the text run buf[s, e) is not kept: empty, or only XML
;;; whitespace unless keep-space? is set.
(definline (drop-text? (keep-space? :- :boolean)
                       (buf         :- :u8vector)
                       (s           :- :fixnum)
                       (e           :- :fixnum)) => :boolean
  (if keep-space? (fx= s e) (whitespace-span? buf s e)))

;;; names

;;; Validates the name bytes buf[s, e) as a QName (or an NCName when
;;; colon-ok? is #f). Returns the colon index, or -1.
(def (check-qname (st        :- XMLScanner)
                  (s         :- :fixnum)
                  (e         :- :fixnum)
                  (colon-ok? :- :boolean)) => :fixnum
  (let (buf st.buf)
    (defrule (bad) (scan-error st s "invalid name"))
    (let loop ((i s) (start? #t) (colon -1))
      (if (fx< i e)
        (let (b (##u8vector-ref buf i))
          (cond
           ((fx= b (ascii #\:))
            (if (or start? (not colon-ok?) (fx>= colon 0))
              (bad)
              (loop (fx+ i 1) #t i)))
           ((fx< b #x80)
            ;; the class table: xml-name-code? is a call per byte
            (let (k (##u8vector-ref name-class b))
              (unless (or (fx= k name-start) (and (fx= k name-char) (not start?)))
                (bad)))
            (loop (fx+ i 1) #f colon))
           (else
            ;; the bytes from i to e are name bytes: a sequence ends by e
            (let (len (&utf8-sequence-length buf i))
              (when (fx= len 0)
                (scan-error st i "invalid UTF-8"))
              (let (c (&utf8-code-at buf i))
                (unless (if start? (xml-name-start-code? c) (xml-name-code? c))
                  (bad))
                (loop (fx+ i len) #f colon))))))
        (if start?
          (bad)
          colon)))))

(def (new-qname-entry (st :- XMLScanner)
                      (s  :- :fixnum)
                      (e  :- :fixnum)
                      (h  :- :fixnum)) => XMLQNameEntry
  (let* ((buf st.buf)
         (colon (check-qname st s e #t))
         (prefix (if (fx< colon 0)
                   ""
                   (utf8-span-string buf s colon)))
         (local (if (fx< colon 0)
                  (utf8-span-string buf s e)
                  (utf8-span-string buf (fx+ colon 1) e)))
         (kind (cond
                ((fx>= colon 0) (if (string=? prefix "xmlns") kind-xmlns-prefix kind-prefixed))
                ((string=? local "xmlns") kind-xmlns)
                (else kind-plain)))
         (plain-name (cond
                      ((fx= kind kind-plain) (unchecked-node XMLName local "" ""))
                      ((fx= kind kind-xmlns) (unchecked-node XMLName local xmlns-namespace-uri ""))
                      ((fx= kind kind-xmlns-prefix)
                       (unchecked-node XMLName local xmlns-namespace-uri prefix))
                      (else #f))))
    (make-XMLQNameEntry (subu8vector buf s e) h prefix local kind plain-name "" #f #f)))

(def (grow-names! (st :- XMLScanner)) => :void
  (let* ((old st.names)
         (size (fx* 2 (##vector-length old)))
         (mask (fx- size 1))
         (new (make-vector size #f)))
    (let loop ((k 0))
      (when (fx< k (##vector-length old))
        (let (entry (##vector-ref old k))
          (when entry
            (using (entry :- XMLQNameEntry)
              (let probe ((slot (fxand entry.hash mask)))
                (if (##vector-ref new slot)
                  (probe (fxand (fx+ slot 1) mask))
                  (##vector-set! new slot entry))))))
        (loop (fx+ k 1))))
    (set! st.names new)))

;;; The entry for name bytes buf[s, e) with hash h. A new name is interned
;;; while the table holds fewer than max-interned-names and its slot is
;;; within max-probes of the hash; otherwise it gets a fresh, unshared entry.
(def (intern-qname (st :- XMLScanner)
                   (s  :- :fixnum)
                   (e  :- :fixnum)
                   (h  :- :fixnum)) => XMLQNameEntry
  (let* ((buf st.buf)
         (table st.names)
         (mask (fx- (##vector-length table) 1))
         (len (fx- e s)))
    (let probe ((k (fxand h mask)) (probes 0))
      (let (entry (##vector-ref table k))
        (cond
         ((fx>= probes max-probes)
          (new-qname-entry st s e h))
         ((not entry)
          (let ((entry (new-qname-entry st s e h))
                (count st.name-count))
            (when (fx< count max-interned-names)
              (##vector-set! table k entry)
              (set! st.name-count (fx+ count 1))
              (when (fx> (fx* 2 (fx+ count 1)) (##vector-length table))
                (grow-names! st)))
            entry))
         (else
          (using (entry :- XMLQNameEntry)
            (if (and (fx= entry.hash h)
                     (let (key entry.key)
                       (and (fx= (##u8vector-length key) len)
                            (bytes=? key 0 buf s len))))
              entry
              (probe (fxand (fx+ k 1) mask) (fx+ probes 1))))))))))

;;; Scans the name starting at i, whose first byte the caller has checked with
;;; name-start-byte?. Returns the end index; the XMLQNameEntry is left in value.
(def (scan-qname (st :- XMLScanner)
                 (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (let loop ((j i) (h fnv-basis))
      (let (b (##u8vector-ref buf j))
        (if (name-byte? b)
          (loop (fx+ j 1) (fnv h b))
          (begin
            (set! st.value (intern-qname st i j h))
            j))))))

;;; Prefixes kept in a list before the red-black tree: the tree alone took
;;; 17% more instructions and 26% more cycles reading small namespace-heavy
;;; documents (markup-benchmark.ss mode xml-read-namespaces, SIZE 100,
;;; ITERATIONS 600); the tree keeps a flood of prefixes O(log n) each.
(def max-listed-prefixes 8)

;;; The binding of prefix, created unbound (xml bound by definition).
(def (prefix-binding-of (st     :- XMLScanner)
                        (prefix :- :string)) => XMLPrefixBinding
  (let loop ((rest st.prefixes))
    (cond
     ((pair? rest)
      (if (string-same? prefix (##car (##car rest)))
        (##cdr (##car rest))
        (loop (##cdr rest))))
     ((and st.prefix-tree (rbtree-ref st.prefix-tree prefix #f)))
     (else
      (let (binding (make-XMLPrefixBinding (if (string=? prefix "xml") [xml-namespace-uri] [])))
        (if (fx< st.prefix-count max-listed-prefixes)
          (begin
            (set! st.prefixes (cons (cons prefix binding) st.prefixes))
            (set! st.prefix-count (fx+ st.prefix-count 1)))
          (rbtree-put! (or st.prefix-tree
                           (let (tree (make-RBTree string-cmp))
                             (set! st.prefix-tree tree)
                             tree))
                       prefix binding))
        binding)))))

;;; The binding of prefix, which entry uses or declares, cached in entry.
(def (entry-binding (st     :- XMLScanner)
                    (entry  :- XMLQNameEntry)
                    (prefix :- :string)) => XMLPrefixBinding
  (or entry.binding
      (let (binding (prefix-binding-of st prefix))
        (set! entry.binding binding)
        binding)))

;;; The namespace of the prefix of entry, a prefixed name, or #f when unbound.
(def (bound-uri (st    :- XMLScanner)
                (entry :- XMLQNameEntry)) => (Maybe :string)
  (let (uris (using (binding (entry-binding st entry entry.prefix) :- XMLPrefixBinding)
               binding.uris))
    (and (pair? uris) (##car uris))))

;;; The namespace of the prefix of entry, a prefixed element name at at.
(def (prefix-uri (st    :- XMLScanner)
                 (entry :- XMLQNameEntry)
                 (at    :- :fixnum)) => :string
  (or (bound-uri st entry)
      (scan-error st at "undeclared namespace prefix")))

;;; Pops the prefix bindings an element declared; inline for the common
;;; element that declares none.
(defrule (pop-bindings! declared-expr)
  (let (declared declared-expr)
    (when (pair? declared)
      (pop-declared! declared))))

(def (pop-declared! (declared :- :pair)) => :void
  (let loop ((rest declared))
    (when (pair? rest)
      (using (binding (##car rest) :- XMLPrefixBinding)
        (set! binding.uris (##cdr binding.uris)))
      (loop (##cdr rest)))))

(def (entry-name (entry :- XMLQNameEntry)
                 (uri   :- :string)) => XMLName
  (cond
   ((fx= (##string-length uri) 0)
    (if (fx= entry.kind kind-plain)
      (:- entry.plain-name XMLName)
      (unchecked-node XMLName entry.local "" "")))
   ((eq? uri entry.cache-uri)
    (:- entry.cache-name XMLName))
   (else
    (let (name (if (string-same? uri entry.cache-uri)
                 (:- entry.cache-name XMLName)
                 (unchecked-node XMLName entry.local uri entry.prefix)))
      (set! entry.cache-uri uri)
      (set! entry.cache-name name)
      name))))

(def (element-name (st    :- XMLScanner)
                   (entry :- XMLQNameEntry)
                   (at    :- :fixnum)) => XMLName
  (let (kind entry.kind)
    (cond
     ((fx= kind kind-prefixed) (entry-name entry (prefix-uri st entry at)))
     ((fx= kind kind-xmlns-prefix)
      (scan-error st at "the xmlns prefix cannot name an element"))
     (else (entry-name entry st.default-ns)))))

;;; references

;;; Decodes the reference after the & at i - 1 and appends its character to
;;; scratch. Returns the index after the ;.
(def (scan-reference (st :- XMLScanner)
                     (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (defrule (bad) (scan-error st (fx- i 1) "invalid reference"))
    (defrule (named entity code)
      (and (match-ascii? buf i entity)
           (begin
             (scratch-append-char! st (ascii code))
             (fx+ i (string-length entity)))))
    (if (fx= (##u8vector-ref buf i) (ascii #\#))
      (let* ((hex? (fx= (##u8vector-ref buf (fx+ i 1)) (ascii #\x)))
             (start (if hex? (fx+ i 2) (fx+ i 1))))
        (let loop ((j start) (c 0))
          (let* ((b (##u8vector-ref buf j))
                 (digit (cond
                         ((and (fx>= b (ascii #\0)) (fx<= b (ascii #\9)))
                          (fx- b (ascii #\0)))
                         ((not hex?) -1)
                         ((and (fx>= b (ascii #\a)) (fx<= b (ascii #\f)))
                          (fx+ 10 (fx- b (ascii #\a))))
                         ((and (fx>= b (ascii #\A)) (fx<= b (ascii #\F)))
                          (fx+ 10 (fx- b (ascii #\A))))
                         (else -1))))
            (cond
             ((fx>= digit 0)
              (let (c (fx+ (fx* c (if hex? 16 10)) digit))
                (if (fx> c #x10ffff)
                  (bad)
                  (loop (fx+ j 1) c))))
             ((and (fx= b (ascii #\;)) (fx> j start)
                   (or (fx= c #x9) (fx= c #xa) (fx= c #xd)
                       (and (fx>= c #x20) (fx<= c #xd7ff))
                       (and (fx>= c #xe000) (fx<= c #xfffd))
                       (fx>= c #x10000)))
              (scratch-append-char! st c)
              (fx+ j 1))
             (else (bad))))))
      (or (named "lt;" #\<)
          (named "gt;" #\>)
          (named "amp;" #\&)
          (named "quot;" #\")
          (named "apos;" #\')
          (bad)))))

;;; attribute values

;;; Scans an attribute value from i (after the opening quote q) through the
;;; closing quote; returns the index after it, the value string in value.
(def (scan-attribute-value (st :- XMLScanner)
                           (i  :- :fixnum)
                           (q  :- :fixnum)) => :fixnum
  (let ((buf st.buf)
        (table attribute-class))
    (let loop ((j i) (continuations 0))
      (let* ((j (skip-plain buf table j))
             (b (##u8vector-ref buf j))
             (c (##u8vector-ref table b)))
        (cond
         ((or (fx= c class-continuation) (fx= c class-high))
          (high-run st buf j continuations loop))
         ((fx= b q)
          (set! st.value (span-string buf i j continuations))
          (fx+ j 1))
         ((fx= c class-quote) (loop (fx+ j 1) continuations))
         (else
          (output-append! st.scratch buf i j)
          (scan-attribute-value/rewrite st j q)))))))

(def (scan-attribute-value/rewrite (st :- XMLScanner)
                                   (i  :- :fixnum)
                                   (q  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (let loop ((seg i) (j i))
      (let* ((b (##u8vector-ref buf j))
             (c (##u8vector-ref attribute-class b)))
        (cond
         ((fx= c class-plain)
          (loop seg (fx+ j 1)))
         ((or (fx= c class-continuation) (fx= c class-high))
          (loop seg (fx+ j (xml-char-length st buf j))))
         ((fx= b q)
          (output-append! st.scratch buf seg j)
          (set! st.value (scratch-text st #f))
          (fx+ j 1))
         ((fx= c class-quote) (loop seg (fx+ j 1)))
         ((fx= c class-amp)
          (output-append! st.scratch buf seg j)
          (let (next (scan-reference st (fx+ j 1)))
            (loop next next)))
         ((fx= c class-cr)
          (output-append! st.scratch buf seg j)
          (scratch-append-char! st (ascii #\space))
          (let (next (after-cr buf j))
            (loop next next)))
         ((fx= c class-tab-lf)
          (output-append! st.scratch buf seg j)
          (scratch-append-char! st (ascii #\space))
          (loop (fx+ j 1) (fx+ j 1)))
         ((fx= c class-lt)
          (scan-error st j "< in attribute value"))
         (else (scan-error st j "invalid character in attribute value")))))))

;;; namespace declarations and attribute names

;;; The start tag's prefixed and xmlns attributes wait in st.pending, as
;;; attribute and XMLQNameEntry in slots 2k and 2k + 1, until the tag's
;;; declarations are known; reusing one vector keeps start tags allocation-free.
(def (push-pending! (st    :- XMLScanner)
                    (count :- :fixnum)
                    (attr  :- XMLAttribute)
                    (entry :- XMLQNameEntry)) => :fixnum
  (let* ((pending st.pending)
         (k (fx* 2 count))
         (pending (if (fx< (fx+ k 1) (##vector-length pending))
                    pending
                    (let (new (vector-grow pending k 16))
                      (set! st.pending new)
                      new))))
    (##vector-set! pending k attr)
    (##vector-set! pending (fx+ k 1) entry)
    (fx+ count 1)))

;;; The index of the name of attr, one of the attributes attrs of a start tag
;;; whose attributes start at i. Scans the well-formed start tag again, so
;;; that only errors pay for attribute positions.
(def (attribute-offset (st    :- XMLScanner)
                       (i     :- :fixnum)
                       (attrs :- :list)
                       (attr  :- XMLAttribute)) => :fixnum
  (let (buf st.buf)
    (let loop ((j (skip-space buf i)) (rest attrs))
      (if (or (not (pair? rest)) (eq? (##car rest) attr))
        j
        (let* ((e (let name ((k j))
                    (if (name-byte? (##u8vector-ref buf k)) (name (fx+ k 1)) k)))
               (v (skip-space buf (fx+ (skip-space buf e) 1)))
               (q (##u8vector-ref buf v))
               (close (let value ((k (fx+ v 1)))
                        (if (fx= (##u8vector-ref buf k) q) k (value (fx+ k 1))))))
          (loop (skip-space buf (fx+ close 1)) (##cdr rest)))))))

;;; Applies the xmlns attributes among the count pending attributes of attrs,
;;; whose start tag has its attributes from start.
(def (declare-namespaces! (st    :- XMLScanner)
                          (count :- :fixnum)
                          (start :- :fixnum)
                          (attrs :- :list)) => :void
  (let loop ((k 0))
    (when (fx< k count)
      (using ((attr (##vector-ref st.pending (fx* 2 k)) :- XMLAttribute)
              (entry (##vector-ref st.pending (fx+ (fx* 2 k) 1)) :- XMLQNameEntry))
        (defrule (fail message)
          (scan-error st (attribute-offset st start attrs attr) message))
        (let ((uri attr.value)
              (kind entry.kind))
          (when (or (fx= kind kind-xmlns) (fx= kind kind-xmlns-prefix))
            (let (expected (namespace-binding-error (and (fx= kind kind-xmlns-prefix) entry.local)
                                                    uri))
              (when expected
                (fail (string-append "expected " expected)))))
          (cond
           ((fx= kind kind-xmlns)
            (set! st.default-ns uri))
           ((fx= kind kind-xmlns-prefix)
            (let (prefix entry.local)
              (using (binding (entry-binding st entry prefix) :- XMLPrefixBinding)
                (set! binding.uris (cons uri binding.uris))
                (set! st.declared (cons binding st.declared))))))))
      (loop (fx+ k 1)))))

;;; Names the count pending attributes of attrs, the attributes of a start
;;; tag with its attributes from start.
(def (resolve-attribute-names! (st    :- XMLScanner)
                               (attrs :- :list)
                               (count :- :fixnum)
                               (start :- :fixnum)) => :void
  (let loop ((k 0))
    (when (fx< k count)
      (using ((attr (##vector-ref st.pending (fx* 2 k)) :- XMLAttribute)
              (entry (##vector-ref st.pending (fx+ (fx* 2 k) 1)) :- XMLQNameEntry))
        (set! attr.name
              (if (fx= entry.kind kind-prefixed)
                (entry-name entry
                            (or (bound-uri st entry)
                                (scan-error st (attribute-offset st start attrs attr)
                                            "undeclared namespace prefix")))
                (:- entry.plain-name XMLName))))
      (loop (fx+ k 1)))))

(def (attribute-name<? (a :- XMLAttribute)
                       (b :- XMLAttribute)) => :boolean
  (xml-name<? a.name b.name))

(definline (attribute-name=? (a :- XMLAttribute)
                             (b :- XMLAttribute)) => :boolean
  (and (string-same? a.name.local b.name.local)
       (string-same? a.name.uri b.name.uri)))

;;; Rejects duplicate expanded names among attrs, the total attributes of a
;;; start tag with its attributes from start: up to pairwise-attribute-limit
;;; pairwise, inline; more through find-duplicate. find-duplicate for all of
;;; them took 35% more instructions and 22% more cycles reading
;;; attribute-heavy XML (markup-benchmark.ss mode xml-read-attributes, SIZE
;;; 1000, ITERATIONS 300).
(def (check-distinct-attributes! (st    :- XMLScanner)
                                 (attrs :- :list)
                                 (total :- :fixnum)
                                 (start :- :fixnum)) => :void
  (let (attr (if (fx<= total pairwise-attribute-limit)
               (pairwise-duplicate (p attrs (pair? p) (##cdr p) (##car p))
                                   (a b (attribute-name=? a b)))
               (find-duplicate attrs attribute-name<? attribute-name=?)))
    (when attr
      (scan-error st (attribute-offset st start attrs attr) "duplicate attribute"))))

;;; Scans attributes from i (after the element name) through the end of the
;;; start tag. Returns the index after the closing >; the attribute list is
;;; left in value. Namespace declarations push prefix bindings onto
;;; st.declared and set st.default-ns. Duplicates are checked once the
;;; names are resolved (check-distinct-attributes!).
(def (scan-attributes (st :- XMLScanner)
                      (i  :- :fixnum)) => :fixnum
  (let ((buf st.buf)
        (start i))
    (let loop ((i i) (head '()) (tail '()) (pending 0) (total 0))
      (defrule (finish next)
        (begin
          (when (fx> pending 0)
            (declare-namespaces! st pending start head)
            (resolve-attribute-names! st head pending start))
          (when (fx> total 1)
            (check-distinct-attributes! st head total start))
          (set! st.value head)
          next))
      (let* ((j (skip-space buf i))
             (b (##u8vector-ref buf j)))
        (cond
         ((fx= b (ascii #\>)) (finish (fx+ j 1)))
         ((fx= b (ascii #\/))
          (expect-byte! st buf (fx+ j 1) (ascii #\>) "expected />")
          (finish (fx+ j 2)))
         ((and (fx> j i) (name-start-byte? b))
          (let* ((e (scan-qname st j))
                 (entry st.value)
                 (e (skip-space buf e)))
            (using (entry :- XMLQNameEntry)
              (expect-byte! st buf e (ascii #\=) "expected = after attribute name")
              (let* ((v (skip-space buf (fx+ e 1)))
                     (q (##u8vector-ref buf v)))
                (unless (or (fx= q (ascii #\")) (fx= q (ascii #\')))
                  (scan-error st v "expected quoted attribute value"))
                (let* ((next (scan-attribute-value st (fx+ v 1) q))
                       (plain? (fx= entry.kind kind-plain))
                       (attr (unchecked-node XMLAttribute
                                             (if plain? (:- entry.plain-name XMLName) unresolved-name)
                                             st.value))
                       (cell (cons attr '()))
                       (pending (if plain? pending (push-pending! st pending attr entry))))
                  (if (null? head)
                    (loop next cell cell pending (fx+ total 1))
                    (begin
                      (##set-cdr! tail cell)
                      (loop next head cell pending (fx+ total 1)))))))))
         (else
          (scan-error st j "expected attribute, > or />")))))))

;;; character data

;;; Scans character data from i up to the < of the next tag or processing
;;; instruction. Returns that index; the text string is left in value, or #f
;;; when the run is empty or only XML whitespace.
(def (scan-text (st :- XMLScanner)
                (i  :- :fixnum)) => :fixnum
  (let ((buf st.buf)
        (table text-class))
    (let loop ((j i) (continuations 0))
      (let* ((j (skip-plain buf table j))
             (c (##u8vector-ref table (##u8vector-ref buf j))))
        (cond
         ((fx= c class-lt)
          (if (and (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\!))
                   (not (and st.keep-comments? (match-ascii? buf j "<!--"))))
            (begin
              (output-append! st.scratch buf i j)
              (scan-text/rewrite st j))
            (begin
              (set! st.value
                    (if (drop-text? st.keep-space? buf i j)
                      #f
                      (span-string buf i j continuations)))
              j)))
         ((fx= c class-invalid)
          (scan-error st j "invalid character"))
         ((fx>= c class-continuation) (high-run st buf j continuations loop))
         ((fx= c class-bracket)
          (check-cdata-end! st buf j)
          (loop (fx+ j 1) continuations))
         (else
          (output-append! st.scratch buf i j)
          (scan-text/rewrite st j)))))))

(def (check-cdata-end! (st  :- XMLScanner)
                       (buf :- :u8vector)
                       (j   :- :fixnum)) => :void
  (when (match-ascii? buf j "]]>")
    (scan-error st j "]]> in character data")))

(def (scan-text/rewrite (st :- XMLScanner)
                        (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (let loop ((seg i) (j i))
      (let (c (##u8vector-ref text-class (##u8vector-ref buf j)))
        (cond
         ((fx= c class-plain)
          (loop seg (fx+ j 1)))
         ((or (fx= c class-continuation) (fx= c class-high))
          (loop seg (fx+ j (xml-char-length st buf j))))
         ((fx= c class-lt)
          (output-append! st.scratch buf seg j)
          (cond
           ((and (match-ascii? buf j "<!--") (not st.keep-comments?))
            (let (next (skip-comment st (fx+ j 4)))
              (loop next next)))
           ((match-ascii? buf j "<![CDATA[")
            (let (next (scan-cdata st (fx+ j 9)))
              (loop next next)))
           ((and (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\!))
                 (not (match-ascii? buf j "<!--")))
            (scan-error st j "markup declaration in content"))
           (else
            (set! st.value
                  (if (fx= st.scratch.whi 0)
                    #f
                    (scratch-text st (not st.keep-space?))))
            j)))
         ((fx= c class-amp)
          (output-append! st.scratch buf seg j)
          (let (next (scan-reference st (fx+ j 1)))
            (loop next next)))
         ((fx= c class-cr)
          (let (next (scratch-append-line! st buf seg j))
            (loop next next)))
         ((fx= c class-bracket)
          (check-cdata-end! st buf j)
          (loop seg (fx+ j 1)))
         (else (scan-error st j "invalid character")))))))

;;; Appends the CDATA section content from i (after <![CDATA[) to scratch,
;;; normalizing line ends. Returns the index after ]]>.
(def (scan-cdata (st :- XMLScanner)
                 (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (let loop ((seg i) (j i))
      (let (c (##u8vector-ref text-class (##u8vector-ref buf j)))
        (cond
         ((fx= c class-bracket)
          (if (match-ascii? buf j "]]>")
            (begin
              (output-append! st.scratch buf seg j)
              (fx+ j 3))
            (loop seg (fx+ j 1))))
         ((fx= c class-cr)
          (let (next (scratch-append-line! st buf seg j))
            (loop next next)))
         ((fx= c class-invalid)
          (scan-error st j "invalid character in CDATA section"))
         ((fx>= c class-continuation)
          (loop seg (fx+ j (xml-char-length st buf j))))
         (else (loop seg (fx+ j 1))))))))

;;; Skips a comment body from i (after <!--), validating its characters.
;;; Returns the index after -->.
(def (skip-comment (st :- XMLScanner)
                   (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (let loop ((j i))
      (let* ((b (##u8vector-ref buf j))
             (c (##u8vector-ref text-class b)))
        (cond
         ((fx= b (ascii #\-))
          (if (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\-))
            (begin
              (unless (fx= (##u8vector-ref buf (fx+ j 2)) (ascii #\>))
                (scan-error st (if (fx>= (fx+ j 2) st.end) (fx+ j 2) j) "-- in comment"))
              (fx+ j 3))
            (loop (fx+ j 1))))
         ((fx= c class-invalid)
          (scan-error st j "invalid character in comment"))
         ((fx>= c class-continuation) (loop (fx+ j (xml-char-length st buf j))))
         (else (loop (fx+ j 1))))))))

;;; Scans a comment from i (after <!--); returns the index after -->, the
;;; XMLComment in value.
(def (scan-comment (st :- XMLScanner)
                   (i  :- :fixnum)) => :fixnum
  (let (next (skip-comment st i))
    (set! st.value (unchecked-node XMLComment (span-text st i (fx- next 3))))
    next))

;;; processing instructions

;;; Scans a processing instruction from i (after <?). Returns the index after
;;; ?>; the XMLPI is left in value.
(def (scan-pi (st :- XMLScanner)
              (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (unless (name-start-byte? (##u8vector-ref buf i))
      (scan-error st i "expected processing instruction target"))
    (let (e (let loop ((e i))
              (if (name-byte? (##u8vector-ref buf e))
                (loop (fx+ e 1))
                e)))
      (check-qname st i e #f)
      (when (and (fx= (fx- e i) 3)
                 (fx= (ascii-fold-code (##u8vector-ref buf i)) (ascii #\x))
                 (fx= (ascii-fold-code (##u8vector-ref buf (fx+ i 1))) (ascii #\m))
                 (fx= (ascii-fold-code (##u8vector-ref buf (fx+ i 2))) (ascii #\l)))
        (scan-error st i "reserved processing instruction target"))
      (let ((target (utf8-span-string buf i e))
            (b (##u8vector-ref buf e)))
        (cond
         ((match-ascii? buf e "?>")
          (set! st.value (unchecked-node XMLPI target ""))
          (fx+ e 2))
         ((xml-space? b)
          (let* ((s (skip-space buf e))
                 (next (scan-pi-data st s)))
            (set! st.value (unchecked-node XMLPI target (scratch-text st #f)))
            next))
         (else
          (scan-error st e "expected space or ?> after processing instruction target")))))))

;;; Appends processing instruction data from i to scratch, normalizing line
;;; ends. Returns the index after ?>.
(def (scan-pi-data (st :- XMLScanner)
                   (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (let loop ((seg i) (j i))
      (let (c (##u8vector-ref text-class (##u8vector-ref buf j)))
        (cond
         ((match-ascii? buf j "?>")
          (output-append! st.scratch buf seg j)
          (fx+ j 2))
         ((fx= c class-cr)
          (let (next (scratch-append-line! st buf seg j))
            (loop next next)))
         ((fx= c class-invalid)
          (scan-error st j "invalid character in processing instruction"))
         ((fx>= c class-continuation)
          (loop seg (fx+ j (xml-char-length st buf j))))
         (else (loop seg (fx+ j 1))))))))

;;; elements

(def (push-frame! (st       :- XMLScanner)
                  (depth    :- :fixnum)
                  (qs       :- :fixnum)
                  (qe       :- :fixnum)
                  (name     :- XMLName)
                  (attrs    :- :list)
                  (kids     :- :list)
                  (declared :- :list)
                  (ns       :- :string)) => :void
  (let* ((stack st.stack)
         (base (fx* depth frame-size))
         (stack (if (fx< (fx+ base frame-size) (##vector-length stack))
                  stack
                  (let (new (vector-grow stack base 0))
                    (set! st.stack new)
                    new))))
    (##vector-set! stack base qs)
    (##vector-set! stack (fx+ base 1) qe)
    (##vector-set! stack (fx+ base 2) name)
    (##vector-set! stack (fx+ base 3) attrs)
    (##vector-set! stack (fx+ base 4) kids)
    (##vector-set! stack (fx+ base 5) declared)
    (##vector-set! stack (fx+ base 6) ns)))

;;; Scans an element from i (after its <) and its whole subtree without
;;; recursion: open elements live in the frame stack. Returns the index after
;;; the element; the XMLElement is left in value.
(def (scan-element (st :- XMLScanner)
                   (i  :- :fixnum)) => :fixnum
  (let (buf st.buf)
    (def (open-tag i kids depth)
      (let* ((e (scan-qname st i))
             (entry st.value)
             (ns st.default-ns)
             (b (##u8vector-ref buf e))
             (next (cond
                    ((fx= b (ascii #\>))
                     (set! st.value '())
                     (fx+ e 1))
                    ((match-ascii? buf e "/>")
                     (set! st.value '())
                     (fx+ e 2))
                    ((xml-space? b) (scan-attributes st e))
                    (else (scan-error st e "expected attribute, > or />"))))
             (attrs st.value)
             (name (element-name st entry (fx- i 1))))
        ;; a start tag ends with > or />; the byte before > tells them apart
        (if (fx= (##u8vector-ref buf (fx- next 2)) (ascii #\/))
          (let (element (unchecked-node XMLElement name attrs '()))
            (pop-bindings! st.declared)
            (set! st.declared '())
            (set! st.default-ns ns)
            (if (fx= depth 0)
              (begin
                (set! st.value element)
                next)
              (content next (cons element kids) depth)))
          (begin
            (push-frame! st depth i e name attrs kids st.declared ns)
            (set! st.declared '())
            (content next '() (fx+ depth 1))))))

    (def (close-tag i kids depth)
      (let* ((stack st.stack)
             (base (fx* (fx- depth 1) frame-size))
             (qs (##vector-ref stack base))
             (qe (##vector-ref stack (fx+ base 1)))
             (len (fx- qe qs))
             (e (fx+ i len)))
        (unless (and (bytes=? buf qs buf i len)
                     (not (name-byte? (##u8vector-ref buf e))))
          (scan-error st (fx- i 2) "mismatched end tag"))
        (let (e (skip-space buf e))
          (expect-byte! st buf e (ascii #\>) "expected > after end tag name")
          (let ((element (unchecked-node XMLElement (##vector-ref stack (fx+ base 2))
                                                     (##vector-ref stack (fx+ base 3))
                                                     (reverse-in-place! kids)))
                (parent-kids (##vector-ref stack (fx+ base 4))))
            (pop-bindings! (##vector-ref stack (fx+ base 5)))
            (set! st.default-ns (##vector-ref stack (fx+ base 6)))
            (if (fx= depth 1)
              (begin
                (set! st.value element)
                (fx+ e 1))
              (content (fx+ e 1) (cons element parent-kids) (fx- depth 1)))))))

    (def (content i kids depth)
      (if (fx= (##u8vector-ref buf i) (ascii #\<))
        (let (b (##u8vector-ref buf (fx+ i 1)))
          (cond
           ((fx= b (ascii #\/)) (close-tag (fx+ i 2) kids depth))
           ((name-start-byte? b) (open-tag (fx+ i 1) kids depth))
           ((fx= b (ascii #\!))
            (if (and st.keep-comments? (match-ascii? buf i "<!--"))
              (let (next (scan-comment st (fx+ i 4)))
                (content next (cons st.value kids) depth))
              (text i kids depth)))
           ((fx= b (ascii #\?))
            (let (next (scan-pi st (fx+ i 2)))
              (content next (cons st.value kids) depth)))
           (else (scan-error st i "invalid markup"))))
        (text i kids depth)))

    (def (text i kids depth)
      (let* ((next (scan-text st i))
             (data st.value))
        (content next (if data (cons (unchecked-node XMLText data) kids) kids) depth)))

    (open-tag i '() 0)))

;;; document type declaration

;;; Skips a literal at i (the opening quote), checking its characters; with
;;; pubid? only PubidChar is allowed. Returns the index after the closing quote.
(def (skip-literal (st     :- XMLScanner)
                   (i      :- :fixnum)
                   (pubid? :- :boolean)) => :fixnum
  (let* ((buf st.buf)
         (q (##u8vector-ref buf i)))
    (unless (or (fx= q (ascii #\")) (fx= q (ascii #\')))
      (scan-error st i "expected quoted literal"))
    (let loop ((j (fx+ i 1)))
      (let (b (##u8vector-ref buf j))
        (cond
         ((fx= b q)
          (fx+ j 1))
         ((fx= (##u8vector-ref text-class b) class-invalid)
          (scan-error st j "invalid character in literal"))
         ((and pubid? (not (pubid-code? b)))
          (scan-error st j "invalid character in public identifier"))
         ((fx>= b #x80)
          (loop (fx+ j (xml-char-length st buf j))))
         (else (loop (fx+ j 1))))))))

;;; Skips the internal subset from i (after [) through ]; its declarations are
;;; not processed, but literals, comments, processing instructions and
;;; characters are checked. Returns the index after ].
(def (skip-internal-subset (st :- XMLScanner)
                           (i  :- :fixnum)) => :fixnum
  (let ((buf st.buf)
        (end st.end))
    (let loop ((j i))
      (let (b (##u8vector-ref buf j))
        (cond
         ((fx>= j end)
          (scan-error st j "unterminated document type declaration"))
         ((fx= b (ascii #\]))
          (fx+ j 1))
         ((or (fx= b (ascii #\")) (fx= b (ascii #\'))) (loop (skip-literal st j #f)))
         ((match-ascii? buf j "<!--") (loop (skip-comment st (fx+ j 4))))
         ((match-ascii? buf j "<?") (loop (scan-pi st (fx+ j 2))))
         ((fx= (##u8vector-ref text-class b) class-invalid)
          (scan-error st j "invalid character in document type declaration"))
         ((fx>= b #x80)
          (loop (fx+ j (xml-char-length st buf j))))
         (else (loop (fx+ j 1))))))))

;;; Scans a document type declaration from i (after <!DOCTYPE):
;;;   S Name (S ExternalID)? S? ('[' intSubset ']' S?)? '>'
;;; The internal subset is checked but not kept. Returns the index after >;
;;; the XMLDoctype is left in value.
(def (scan-doctype (st :- XMLScanner)
                   (i  :- :fixnum)) => :fixnum
  (let* ((buf st.buf)
         (s (skip-space buf i)))
    (unless (and (fx> s i) (name-start-byte? (##u8vector-ref buf s)))
      (scan-error st s "expected space and a name after <!DOCTYPE"))
    (let* ((e (let loop ((e s))
                (if (name-byte? (##u8vector-ref buf e)) (loop (fx+ e 1)) e)))
           (k (begin
                (check-qname st s e #t)
                (skip-space buf e)))
           (name (utf8-span-string buf s e))
           (public-id #f)
           (system-id #f))
      ;; the text of the literal from the quote at l to its end at next
      (defrule (literal l next)
        (span-text st (fx+ l 1) (fx- next 1)))
      (let* ((k (cond
                 ((and (fx> k e) (match-ascii? buf k "SYSTEM"))
                  (let (l (skip-space buf (fx+ k 6)))
                    (unless (fx> l (fx+ k 6))
                      (scan-error st l "expected space after SYSTEM"))
                    (let (next (skip-literal st l #f))
                      (set! system-id (literal l next))
                      (skip-space buf next))))
                 ((and (fx> k e) (match-ascii? buf k "PUBLIC"))
                  (let (l (skip-space buf (fx+ k 6)))
                    (unless (fx> l (fx+ k 6))
                      (scan-error st l "expected space after PUBLIC"))
                    (let* ((p (skip-literal st l #t))
                           (m (skip-space buf p)))
                      (unless (fx> m p)
                        (scan-error st m "expected space before the system literal"))
                      (let (next (skip-literal st m #f))
                        (set! public-id (literal l p))
                        (set! system-id (literal m next))
                        (skip-space buf next)))))
                 (else k)))
             (k (if (fx= (##u8vector-ref buf k) (ascii #\[))
                  (skip-space buf (skip-internal-subset st (fx+ k 1)))
                  k)))
        (expect-byte! st buf k (ascii #\>) "expected > to end the document type declaration")
        (set! st.value (unchecked-node XMLDoctype name public-id system-id))
        (fx+ k 1)))))

;;; XML declaration and encoding

;;; Parses an XML declaration from i (after <?xml and a space) and applies
;;; its encoding to byte input (see apply-declared-encoding!). Returns the
;;; index after ?>. Errors in a value are reported at the value.
(def (scan-xml-declaration (st       :- XMLScanner)
                           (i        :- :fixnum)
                           (decoded? :- :boolean)
                           (bom?     :- :boolean)) => :fixnum
  (let ((buf st.buf)
        (at 0))                         ; index of the last value scanned
    (def (pseudo-attribute i name required?)
      ;; returns the index after the value, value string in st, or i when absent
      (let (j (skip-space buf i))
        (cond
         ((and (fx> j i) (ascii-at? buf j name))
          (let* ((e (skip-space buf (fx+ j (string-length name))))
                 (v (begin
                      (expect-byte! st buf e (ascii #\=) "expected = in XML declaration")
                      (skip-space buf (fx+ e 1))))
                 (q (##u8vector-ref buf v)))
            (unless (or (fx= q (ascii #\")) (fx= q (ascii #\')))
              (scan-error st v "expected quoted value in XML declaration"))
            (set! at (fx+ v 1))
            (let loop ((k (fx+ v 1)))
              (let (b (##u8vector-ref buf k))
                (cond
                 ((fx= b q)
                  (set! st.value (&utf8-decode buf (fx+ v 1) k (fx- k (fx+ v 1))))
                  (fx+ k 1))
                 ((or (fx= (##u8vector-ref name-class b) name-start)
                      (fx= (##u8vector-ref name-class b) name-char))
                  (loop (fx+ k 1)))
                 (else (scan-error st k "invalid XML declaration value")))))))
         (required?
          (scan-error st j "expected version in XML declaration"))
         (else i))))
    (let (i (pseudo-attribute i "version" #t))
      (unless (version-num? st.value)
        (scan-error st at "unsupported XML version"))
      (let* ((j (pseudo-attribute i "encoding" #f))
             (encoding (and (fx> j i) (string-downcase st.value)))
             (encoding-at at)
             (k (pseudo-attribute j "standalone" #f)))
        (when (and encoding (not (enc-name? encoding)))
          (scan-error st encoding-at "invalid encoding name"))
        (when (and (fx> k j) (not (member st.value '("yes" "no"))))
          (scan-error st at "invalid standalone value"))
        (let (e (skip-space buf k))
          (unless (match-ascii? buf e "?>")
            (scan-error st e "expected ?> to end the XML declaration"))
          (when (and encoding (not decoded?))
            (apply-declared-encoding! st encoding bom? encoding-at (fx+ e 2)))
          (fx+ e 2))))))

;;; XML 1.0 [26] VersionNum: 1. and digits. A 1.0 processor reads other 1.x
;;; versions as 1.0 (XML 1.0 fifth edition, 2.8).
(def (version-num? (str :- :string)) => :boolean
  (let (n (string-length str))
    (and (fx> n 2)
         (string-prefix? "1." str)
         (let loop ((k 2))
           (or (fx>= k n)
               (and (char-numeric? (string-ref str k))
                    (loop (fx+ k 1))))))))

;;; XML 1.0 [81] EncName: an ASCII letter, then letters, digits, . _ and -.
;;; The scan of the value admits only those characters.
(def (enc-name? (str :- :string)) => :boolean
  (and (fx> (string-length str) 0)
       (char-alphabetic? (string-ref str 0))))

(def (ascii-at? (buf :- :u8vector)
                (i   :- :fixnum)
                (str :- :string)) => :boolean
  (let (n (##string-length str))
    (let loop ((k 0))
      (cond
       ((fx>= k n) #t)
       ((fx= (##u8vector-ref buf (fx+ i k)) (##char->integer (##string-ref str k)))
        (loop (fx+ k 1)))
       (else #f)))))

;;; Applies the declared encoding (lowercase) of byte input, whose
;;; declaration value is at at and which continues at i: UTF-8 is scanned as
;;; is, US-ASCII too once no byte from i on is #x80 or above, ISO-8859-1 is
;;; transcoded to UTF-8, anything else is rejected. A UTF-8 byte order mark
;;; admits only a UTF-8 (or ASCII) declaration.
(def (apply-declared-encoding! (st       :- XMLScanner)
                               (encoding :- :string)
                               (bom?     :- :boolean)
                               (at       :- :fixnum)
                               (i        :- :fixnum)) => :void
  (cond
   ((member encoding '("utf-8" "utf8")) (void))
   ((member encoding '("us-ascii" "ascii"))
    (let ((buf st.buf)
          (end st.end))
      (let loop ((k i))
        (when (fx< k end)
          (if (fx>= (##u8vector-ref buf k) #x80)
            (scan-error st k "non-ASCII byte in a US-ASCII document")
            (loop (fx+ k 1)))))))
   (bom?
    (scan-error st at "byte order mark contradicts the declared encoding"))
   ((member encoding '("iso-8859-1" "latin1" "iso_8859-1" "latin-1"))
    (let (out (latin1->utf8 st.buf st.end))
      (set! st.buf out)
      (set! st.end (fx- (##u8vector-length out) 1))
      (set! st.mapped? #t)))
   (else (scan-error st at "unsupported encoding"))))

;;; document

;;; Misc* after the root element: processing instructions are kept, comments
;;; and whitespace skipped.
(def (scan-epilog (st :- XMLScanner)
                  (i  :- :fixnum)) => :list
  (let ((buf st.buf)
        (end st.end))
    (let loop ((i i) (misc '()))
      (let (i (skip-space buf i))
        (cond
         ((fx>= i end) (reverse-in-place! misc))
         ((match-ascii? buf i "<?")
          (let (next (scan-pi st (fx+ i 2)))
            (loop next (cons st.value misc))))
         ((match-ascii? buf i "<!--")
          (if st.keep-comments?
            (let (next (scan-comment st (fx+ i 4)))
              (loop next (cons st.value misc)))
            (loop (skip-comment st (fx+ i 4)) misc)))
         (else (scan-error st i "content after the root element")))))))

;;; Scans a whole document. buf holds UTF-8 in [0, end) followed by a 0 byte.
;;; decoded? is true when the bytes were encoded from a string: a declared
;;; encoding no longer applies, and error offsets count characters.
(def (scan-xml-document (buf            :- :u8vector)
                        (end            :- :fixnum)
                        (decoded?       :- :boolean)
                        (keep-space?    :- :boolean)
                        (keep-comments? :- :boolean)) => XMLDocument
  (using (st (make-XMLScanner buf end decoded? (make-memory-output 256) (make-vector 64 #f) 0
                               (make-vector (fx* 16 frame-size) #f) '() 0 #f '() "" (vector)
                               keep-space? keep-comments? #f)
             :- XMLScanner)
    (let* ((bom? (and (fx= (##u8vector-ref buf 0) #xef)
                      (fx= (##u8vector-ref buf 1) #xbb)
                      (fx= (##u8vector-ref buf 2) #xbf)))
           (i (if bom? 3 0))
           (i (cond
               ((and (not decoded?)
                     (or (and (fx= (##u8vector-ref buf 0) #xff) (fx= (##u8vector-ref buf 1) #xfe))
                         (and (fx= (##u8vector-ref buf 0) #xfe) (fx= (##u8vector-ref buf 1) #xff))))
                (scan-error st 0 "unsupported encoding (UTF-16)"))
               ((and (match-ascii? buf i "<?xml")
                     (xml-space? (##u8vector-ref buf (fx+ i 5))))
                (scan-xml-declaration st (fx+ i 5) decoded? bom?))
               (else i))))
      (let loop ((i i) (prolog '()) (doctype #f))
        (let* ((buf st.buf)
               (i (skip-space buf i))
               (b (if (fx= (##u8vector-ref buf i) (ascii #\<))
                    (##u8vector-ref buf (fx+ i 1))
                    (scan-error st i "expected the root element"))))
          (cond
           ((name-start-byte? b)
            (let* ((next (scan-element st (fx+ i 1)))
                   (root st.value))
              (unchecked-node XMLDocument (reverse-in-place! prolog) root (scan-epilog st next) doctype)))
           ((fx= b (ascii #\?))
            (let (next (scan-pi st (fx+ i 2)))
              (loop next (cons st.value prolog) doctype)))
           ((match-ascii? buf i "<!--")
            (if st.keep-comments?
              (let (next (scan-comment st (fx+ i 4)))
                (loop next (cons st.value prolog) doctype))
              (loop (skip-comment st (fx+ i 4)) prolog doctype)))
           ((and (not doctype) (match-ascii? buf i "<!DOCTYPE"))
            (let (next (scan-doctype st (fx+ i 9)))
              (loop next prolog st.value)))
           (else (scan-error st i "expected the root element"))))))))
