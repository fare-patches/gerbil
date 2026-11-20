;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML tokenizer: the tokenization stage of the WHATWG HTML parser (HTML
;;; Living Standard §13.2.5) over UTF-8 bytes. Unchecked internals;
;;; :std/text/markup/html/tokenizer checks arguments and supplies the input.
;;;
;;; Conformance is checked against the html5lib tokenizer tests rather than
;;; by transcribing the state machine: text, attribute values and names are
;;; bulk scans, and the program counter implies most other states.
(import :std/error
        (only-in :std/struct/rbtree RBTree make-RBTree rbtree-ref rbtree-put! string-cmp)
        (only-in :std/encoding/utf8
                 &put-utf8!
                 &utf8-sequence-length
                 &utf8-check-run
                 &utf8-count-continuations
                 &utf8-decode)
        (only-in ../scan-input
                 scan-input-offset
                 ascii
                 match-ascii?
                 make-byte-table
                 skip-plain
                 bytes=?
                 after-cr
                 fnv-basis
                 fnv
                 vector-grow)
        :std/io/bio/types
        (only-in ../output make-memory-output output-reserve! output-append!)
        ./atoms
        ./entities
        ./rules)
(export (struct-out HTMLTokenizer)
        scan-input->html-tokenizer
        html-tokenizer-next!
        html-tokenizer-offset
        html-input-offset
        html-token-text
        html-atom-name
        html-token-attribute-list
        html-font-breakout-token?
        html-tokenizer-intern
        html-token-eof
        html-token-characters
        html-token-null-character
        html-token-start-tag
        html-token-end-tag
        html-token-comment
        html-token-doctype
        html-token-pi
        HTMLParseError
        HTMLParseError?
        html-parse-error?
        HTMLParseError-offset)
(declare (not safe))

;;; Input contract: buf holds the input in [0, end) and buf[end] is 0. NUL is
;;; valid input, so every scanning loop stops at any 0 byte and tells the
;;; sentinel apart by its index; multi-byte lookahead matches one byte at a
;;; time, so it never reads past the sentinel.
;;; Every byte >= #x80 is checked as UTF-8 by the scan that first passes it,
;;; whether or not a string is built from it, so the strings are decoded
;;; without checks.

;;; token kinds, as html-tokenizer-next! returns them
(defconst html-token-eof 0)
(defconst html-token-characters 1)      ; a run of characters: html-token-text
(defconst html-token-null-character 2)  ; one U+0000, in the data or CDATA state
(defconst html-token-start-tag 3)
(defconst html-token-end-tag 4)
(defconst html-token-comment 5)
(defconst html-token-doctype 6)
(defconst html-token-pi 7)

;;; The token html-tokenizer-next! returned is left in the registers below,
;;; valid until the next call:
;;; - characters: UTF-8 text-bytes[text-start, text-end) of text-chars
;;;   characters, in buf or the scratch;
;;; - start and end tags: tag (an atom), self-closing?, and attribute-count
;;;   attributes as atom, value pairs in attributes (start tags only; first
;;;   of duplicates kept);
;;; - comments: data; processing instructions: target and data;
;;; - DOCTYPE: doctype-name, public-id, system-id (#f when missing) and
;;;   force-quirks?.
;;; Names are atoms: 1 .. known-atom-count for the names of ./atoms, larger
;;; for other names of this input, interned per tokenizer, so equal names are
;;; equal atoms.
(defstruct HTMLTokenizer
  ((buf             :- :u8vector)
   (end             :- :fixnum)
   (mapped?         :- :boolean)  ; buf was encoded from a string: offsets count characters
   (i               :- :fixnum)   ; next input index
   (start           :- :fixnum)   ; input index where the current token starts
   (state           :- :fixnum)   ; state the next token starts in
   (last-start-tag  :- :fixnum)   ; atom of the last start tag emitted, or 0
   (cdata?          :- :boolean)  ; <![CDATA[ opens a CDATA section (foreign content)
   (kind            :- :fixnum)   ; kind of the current token
   (scratch         :- memory-output-buffer) ; text rewritten for references, CR and NUL
   (text-bytes      :- :u8vector)
   (text-start      :- :fixnum)
   (text-end        :- :fixnum)
   (text-chars      :- :fixnum)
   (tag             :- :fixnum)
   (self-closing?   :- :boolean)
   (attributes      :- :vector)
   (attribute-count :- :fixnum)
   (data            :- :string)
   (target          :- :string)
   (doctype-name    :? :string)
   (public-id       :? :string)
   (system-id       :? :string)
   (force-quirks?   :- :boolean)
   (atom            :- :fixnum)   ; result register of name scans
   (value           :- :string)   ; result register of attribute value scans
   (reference       :- :fixnum)   ; result register of match-reference
   (names           :- :vector)   ; HTMLNameEntry table (open addressing)
   (name-count      :- :fixnum)   ; names interned in this tokenizer
   (atom-names      :- :vector)   ; name of atom known-atom-count + 1 + k at k
   (overflow        :? RBTree)    ; names past max-probes, or #f
   (seen            :- :vector)   ; atom -> serial of the last tag with that attribute
   (serial          :- :fixnum))  ; serial of the current tag
  final: #t)

;;; A name interned in a tokenizer, keyed by its (folded) UTF-8 bytes.
(defstruct HTMLNameEntry
  ((key  :- :u8vector)
   (hash :- :fixnum)
   (atom :- :fixnum))
  final: #t)

(def max-probes 16)

(def known-atom-mask (fx- (u16vector-length known-atom-slots) 1))

;;; errors

;;; Invalid UTF-8 at byte offset in the input (only byte input can hold it:
;;; string input is encoded here), or nesting past the tree builder's limit.
;;; Markup errors are never raised.
(deferror-class (HTMLParseError IOError) (offset) html-parse-error?)

(def (raise-invalid-utf8 (i :- :fixnum)) => :void
  (raise (HTMLParseError "invalid UTF-8"
                         offset: i
                         where: 'html-tokenizer-next!
                         irritants: ['offset i])))

(defrule (invalid-utf8 i)
  (abort! (raise-invalid-utf8 i)))

;;; byte classes

(defconst class-plain 0)
(defconst class-lt 1)
(defconst class-amp 2)
(defconst class-cr 3)
(defconst class-nul 4)           ; NUL, including the sentinel
(defconst class-high 5)          ; byte >= #x80
(defconst class-quote 6)         ; quoted attribute values: the closing quote
(defconst class-space 7)         ; unquoted attribute values: TAB LF FF CR SPACE
(defconst class-gt 8)            ; unquoted attribute values: >
(defconst class-bracket 9)       ; CDATA sections: ]
(defconst class-dash 10)         ; comments: -

(definline (ascii-alpha? (b :- :fixnum)) => :boolean
  (let (x (fx- (fxior b #x20) (ascii #\a)))
    (and (fx>= x 0) (fx< x 26))))

(def (text-table (stops :- :list)) => :u8vector
  (make-byte-table
   (lambda (b)
     (cond
      ((fx= b 0) class-nul)
      ((fx>= b #x80) class-high)
      ((assv b stops) => cdr)
      (else class-plain)))))

(def data-class
  (text-table [[(ascii #\<) :: class-lt] [(ascii #\&) :: class-amp]
               [(ascii #\return) :: class-cr]]))

(def rawtext-class
  (text-table [[(ascii #\<) :: class-lt] [(ascii #\return) :: class-cr]]))

(def plaintext-class
  (text-table [[(ascii #\return) :: class-cr]]))

(def cdata-class
  (text-table [[(ascii #\]) :: class-bracket] [(ascii #\return) :: class-cr]]))

(def double-quoted-class
  (text-table [[(ascii #\") :: class-quote] [(ascii #\&) :: class-amp]
               [(ascii #\return) :: class-cr]]))

(def single-quoted-class
  (text-table [[(ascii #\') :: class-quote] [(ascii #\&) :: class-amp]
               [(ascii #\return) :: class-cr]]))

(def unquoted-class
  (text-table [[(ascii #\&) :: class-amp] [(ascii #\>) :: class-gt]
               [(ascii #\space) :: class-space] [(ascii #\newline) :: class-space]
               [(ascii #\tab) :: class-space] [#xc :: class-space]
               [(ascii #\return) :: class-space]]))

;;; comments: high bytes are plain, checked when the data string is built
(def comment-class
  (make-byte-table
   (lambda (b)
     (cond
      ((fx= b 0) class-nul)
      ((fx= b (ascii #\-)) class-dash)
      (else class-plain)))))

;;; name classes
(defconst name-plain 0)
(defconst name-upper 1)          ; ASCII upper case: folds to lower case
(defconst name-high 2)
(defconst name-nul 3)            ; NUL, including the sentinel
(defconst name-stop 4)

(def (name-table (stops :- :list)) => :u8vector
  (make-byte-table
   (lambda (b)
     (cond
      ((fx= b 0) name-nul)
      ((fx>= b #x80) name-high)
      ((and (fx>= b (ascii #\A)) (fx<= b (ascii #\Z))) name-upper)
      ((memv b stops) name-stop)
      (else name-plain)))))

(def tag-name-class
  (name-table [(ascii #\space) (ascii #\newline) (ascii #\tab) #xc (ascii #\return)
               (ascii #\/) (ascii #\>)]))

(def attribute-name-class
  (name-table [(ascii #\space) (ascii #\newline) (ascii #\tab) #xc (ascii #\return)
               (ascii #\/) (ascii #\>) (ascii #\=)]))

(defrule (skip-space buf i)
  (let skip ((k i))
    (if (html-space-code? (##u8vector-ref buf k)) (skip (fx+ k 1)) k)))

;;; True when buf holds str at i, its lower case letters matched ASCII
;;; case-insensitively and its other characters exactly.
(defsyntax (match-ascii-ci? stx)
  (syntax-case stx ()
    ((_ buf i str)
     (stx-string? #'str)
     (let (chars (string->list (stx-e #'str)))
       (with-syntax (((code ...) (map char->integer chars))
                     ((fold ...) (map (lambda (c) (if (char<=? #\a c #\z) #x20 0)) chars))
                     ((offset ...) (iota (length chars))))
         #'(and (fx= (fxior (##u8vector-ref buf (fx+ i offset)) fold) code) ...))))))

;;; UTF-8

;;; Checks buf[s, e) as UTF-8; returns its count of continuation bytes.
(def (check-utf8 (tz :- HTMLTokenizer)
                 (s  :- :fixnum)
                 (e  :- :fixnum)) => :fixnum
  (let ((buf tz.buf))
    (let loop ((k s) (n 0))
      (cond
       ((fx>= k e) n)
       ((fx< (##u8vector-ref buf k) #x80) (loop (fx+ k 1) n))
       (else (&utf8-check-run buf k e n invalid-utf8 loop))))))

;;; scratch buffer

(def (scratch-append-byte! (tz :- HTMLTokenizer)
                           (b  :- :fixnum)) => :void
  (using (out tz.scratch :- memory-output-buffer)
    (let (scratch (output-reserve! out 1))
      (##u8vector-set! scratch out.whi b)
      (set! out.whi (fx+ out.whi 1)))))

;;; Appends U+FFFD, which replaces NUL; it has 2 continuation bytes.
(def (scratch-append-replacement! (tz :- HTMLTokenizer)) => :void
  (using (out tz.scratch :- memory-output-buffer)
    (let* ((scratch (output-reserve! out 3))
           (fill out.whi))
      (##u8vector-set! scratch fill #xef)
      (##u8vector-set! scratch (fx+ fill 1) #xbf)
      (##u8vector-set! scratch (fx+ fill 2) #xbd)
      (set! out.whi (fx+ fill 3)))))

;;; Starts a rewrite of the current run into the scratch: the first time,
;;; empties the scratch; then appends buf[seg, j).
(defrule (rewrite-segment! tz rewritten? buf seg j)
  (using (t tz :- HTMLTokenizer)
    (unless rewritten?
      (set! t.scratch.whi 0))
    (output-append! t.scratch buf seg j)))

;;; Copies the checked buf[s, e) to the emptied scratch with CR and CR LF as
;;; LF and, when replace-nul? is set, NUL as U+FFFD. Returns the count of
;;; continuation bytes in the scratch.
(def (rewrite-span! (tz           :- HTMLTokenizer)
                    (s            :- :fixnum)
                    (e            :- :fixnum)
                    (replace-nul? :- :boolean)) => :fixnum
  (let (buf tz.buf)
    (set! tz.scratch.whi 0)
    (let loop ((seg s) (j s) (n 0))
      (if (fx< j e)
        (let (b (##u8vector-ref buf j))
          (cond
           ((fx= b (ascii #\return))
            (output-append! tz.scratch buf seg j)
            (scratch-append-byte! tz (ascii #\newline))
            (let (next (fxmin (after-cr buf j) e))
              (loop next next n)))
           ((and (fx= b 0) replace-nul?)
            (output-append! tz.scratch buf seg j)
            (scratch-append-replacement! tz)
            (loop (fx+ j 1) (fx+ j 1) (fx+ n 2)))
           ((fx= (fxand b #xc0) #x80) (loop seg (fx+ j 1) (fx+ n 1)))
           (else (loop seg (fx+ j 1) n))))
        (begin
          (output-append! tz.scratch buf seg e)
          n)))))

;;; The string of buf[s, e) after input preprocessing (CR and CR LF as LF),
;;; with NUL as U+FFFD when replace-nul? is set. Checks the UTF-8.
(def (span-text (tz           :- HTMLTokenizer)
                (s            :- :fixnum)
                (e            :- :fixnum)
                (replace-nul? :- :boolean)) => :string
  (let* ((buf tz.buf)
         (n (check-utf8 tz s e)))
    (let scan ((k s))
      (cond
       ((fx>= k e)
        (&utf8-decode buf s e (fx- (fx- e s) n)))
       ((let (b (##u8vector-ref buf k))
          (or (fx= b (ascii #\return)) (and (fx= b 0) replace-nul?)))
        (let (m (rewrite-span! tz s e replace-nul?))
          (&utf8-decode tz.scratch.buf 0 tz.scratch.whi (fx- tz.scratch.whi m))))
       (else (scan (fx+ k 1)))))))

;;; names

(def (known-name=? (id    :- :fixnum)
                   (bytes :- :u8vector)
                   (s     :- :fixnum)
                   (len   :- :fixnum)) => :boolean
  (let (name (##vector-ref known-atom-names id))
    (and (fx= (##string-length name) len)
         (let loop ((k 0))
           (cond
            ((fx>= k len) #t)
            ((fx= (##u8vector-ref bytes (fx+ s k)) (##char->integer (##string-ref name k)))
             (loop (fx+ k 1)))
            (else #f))))))

(def (name-string (bytes :- :u8vector)
                  (s     :- :fixnum)
                  (e     :- :fixnum)) => :string
  (&utf8-decode bytes s e (fx- (fx- e s) (&utf8-count-continuations bytes s e))))

;;; The atom of a new name of this tokenizer.
(def (new-atom! (tz   :- HTMLTokenizer)
                (name :- :string)) => :fixnum
  (let* ((count tz.name-count)
         (names tz.atom-names)
         (names (if (fx< count (##vector-length names))
                  names
                  (let (new (vector-grow names count 0))
                    (set! tz.atom-names new)
                    new)))
         (atom (fx+ known-atom-count 1 count))
         (seen tz.seen))
    (##vector-set! names count name)
    (set! tz.name-count (fx+ count 1))
    (when (fx>= atom (##vector-length seen))
      (set! tz.seen (vector-grow seen (##vector-length seen) 0)))
    atom))

(def (grow-names! (tz :- HTMLTokenizer)) => :void
  (let* ((old tz.names)
         (size (fx* 2 (##vector-length old)))
         (mask (fx- size 1))
         (new (make-vector size #f)))
    (let loop ((k 0))
      (when (fx< k (##vector-length old))
        (let (entry (##vector-ref old k))
          (when entry
            (using (entry :- HTMLNameEntry)
              (let probe ((slot (fxand entry.hash mask)) (probes 0))
                (cond
                 ((fx>= probes max-probes)
                  (rbtree-put! (overflow-tree tz) (html-atom-name tz entry.atom) entry.atom))
                 ((##vector-ref new slot)
                  (probe (fxand (fx+ slot 1) mask) (fx+ probes 1)))
                 (else (##vector-set! new slot entry)))))))
        (loop (fx+ k 1))))
    (set! tz.names new)))

(def (overflow-tree (tz :- HTMLTokenizer)) => RBTree
  (or tz.overflow
      (let (tree (make-RBTree string-cmp))
        (set! tz.overflow tree)
        tree)))

;;; Names whose slot lies more than max-probes from their hash go to a
;;; red-black tree ordered by string, so names colliding in the hash cost a
;;; bounded probe and a logarithmic search each, and still get one atom per
;;; name. (A second hash table would collide too: the runtime's string hash
;;; collides on the same names as FNV.) A name is either in the table within
;;; max-probes of its hash or in the tree, never both: growing the table
;;; moves entries that would land further into the tree, and a name that
;;; misses the table is looked up in the tree before it is added.
(def (intern-overflow-name (tz    :- HTMLTokenizer)
                           (bytes :- :u8vector)
                           (s     :- :fixnum)
                           (e     :- :fixnum)) => :fixnum
  (let* ((name (name-string bytes s e))
         (tree (overflow-tree tz))
         (atom (rbtree-ref tree name 0)))
    (if (fx> atom 0)
      atom
      (let (atom (new-atom! tz name))
        (rbtree-put! tree name atom)
        atom))))

(def (intern-document-name (tz    :- HTMLTokenizer)
                           (bytes :- :u8vector)
                           (s     :- :fixnum)
                           (e     :- :fixnum)
                           (h     :- :fixnum)) => :fixnum
  (let* ((table tz.names)
         (mask (fx- (##vector-length table) 1))
         (len (fx- e s)))
    (let probe ((k (fxand h mask)) (probes 0))
      (let (entry (##vector-ref table k))
        (cond
         ((fx>= probes max-probes)
          (intern-overflow-name tz bytes s e))
         ((not entry)
          (let* ((name (name-string bytes s e))
                 (tree tz.overflow)
                 (old (if tree (rbtree-ref tree name 0) 0)))
            (if (fx> old 0)
              old
              (let (atom (new-atom! tz name))
                (##vector-set! table k (make-HTMLNameEntry (subu8vector bytes s e) h atom))
                (when (fx> (fx* 2 tz.name-count) (##vector-length table))
                  (grow-names! tz))
                atom))))
         (else
          (using (entry :- HTMLNameEntry)
            (if (and (fx= entry.hash h)
                     (let (key entry.key)
                       (and (fx= (##u8vector-length key) len)
                            (bytes=? key 0 bytes s len))))
              entry.atom
              (probe (fxand (fx+ k 1) mask) (fx+ probes 1))))))))))

;;; The atom of the folded, checked name bytes[s, e) with hash h.
(def (intern-name (tz    :- HTMLTokenizer)
                  (bytes :- :u8vector)
                  (s     :- :fixnum)
                  (e     :- :fixnum)
                  (h     :- :fixnum)) => :fixnum
  (let (len (fx- e s))
    (let probe ((slot (fxand h known-atom-mask)))
      (let (id (##u16vector-ref known-atom-slots slot))
        (cond
         ((fx= id 0) (intern-document-name tz bytes s e h))
         ((known-name=? id bytes s len) id)
         (else (probe (fxand (fx+ slot 1) known-atom-mask))))))))

;;; The attributes of the current start tag as a list, in order, each the
;;; value of make, an expression with atom and value bound to the
;;; attribute's name atom and value. A macro, so that make is inline.
(defrule (html-token-attribute-list tz (atom value) make)
  (using (t tz :- HTMLTokenizer)
    (let ((attributes t.attributes))
      (let loop ((k (fx- t.attribute-count 1)) (result '()))
        (if (fx< k 0)
          result
          (loop (fx- k 1)
                (cons (let ((atom (##vector-ref attributes (fx* 2 k)))
                            (value (##vector-ref attributes (fx+ (fx* 2 k) 1))))
                        make)
                      result)))))))

;;; True when the current token of tz is a font start tag with an attribute
;;; that takes it out of foreign content (font-breakout-attribute-atom?).
(def (html-font-breakout-token? (tz :- HTMLTokenizer)) => :boolean
  (and (fx= tz.tag atom-font)
       (let ((attributes tz.attributes)
             (n tz.attribute-count))
         (let loop ((k 0))
           (and (fx< k n)
                (or (font-breakout-attribute-atom? (##vector-ref attributes (fx* 2 k)))
                    (loop (fx+ k 1))))))))

(def (html-atom-name (tz   :- HTMLTokenizer)
                     (atom :- :fixnum)) => :string
  (if (fx<= atom known-atom-count)
    (##vector-ref known-atom-names atom)
    (##vector-ref tz.atom-names (fx- atom (fx+ known-atom-count 1)))))

;;; The atom of name, a folded name string.
(def (html-tokenizer-intern (tz   :- HTMLTokenizer)
                            (name :- :string)) => :fixnum
  (let* ((bytes (string->utf8 name))
         (e (##u8vector-length bytes)))
    (let loop ((k 0) (h fnv-basis))
      (if (fx< k e)
        (loop (fx+ k 1) (fnv h (##u8vector-ref bytes k)))
        (intern-name tz bytes 0 e h)))))

;;; Interns buf[s, e) after folding ASCII upper case and replacing NUL.
(def (intern-folded-name (tz :- HTMLTokenizer)
                         (s  :- :fixnum)
                         (e  :- :fixnum)
                         (h  :- :fixnum)) => :fixnum
  (let (buf tz.buf)
    (set! tz.scratch.whi 0)
    (let loop ((k s))
      (when (fx< k e)
        (let (b (##u8vector-ref buf k))
          (cond
           ((fx= b 0) (scratch-append-replacement! tz))
           ((and (fx>= b (ascii #\A)) (fx<= b (ascii #\Z))) (scratch-append-byte! tz (fx+ b #x20)))
           (else (scratch-append-byte! tz b))))
        (loop (fx+ k 1))))
    (intern-name tz tz.scratch.buf 0 tz.scratch.whi h)))

;;; Scans a tag or attribute name from j to a byte table classes as a stop
;;; (or the end of input); buf[s, j) is already scanned with hash h. Returns
;;; the end index, the atom of the folded name in tz.atom.
(def (scan-name (tz    :- HTMLTokenizer)
                (s     :- :fixnum)
                (j     :- :fixnum)
                (h     :- :fixnum)
                (table :- :u8vector)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((k j) (h h) (plain? #t))
      (let* ((b (##u8vector-ref buf k))
             (c (##u8vector-ref table b)))
        (cond
         ((fx= c name-plain) (loop (fx+ k 1) (fnv h b) plain?))
         ((fx= c name-upper) (loop (fx+ k 1) (fnv h (fx+ b #x20)) #f))
         ((fx= c name-high)
          (let (len (&utf8-sequence-length buf k))
            (when (fx= len 0)
              (invalid-utf8 k))
            (let hash ((m 0) (h h))
              (if (fx< m len)
                (hash (fx+ m 1) (fnv h (##u8vector-ref buf (fx+ k m))))
                (loop (fx+ k len) h plain?)))))
         ((and (fx= c name-nul) (fx< k end))
          (loop (fx+ k 1) (fnv (fnv (fnv h #xef) #xbf) #xbd) #f))
         (else
          (set! tz.atom (if plain? (intern-name tz buf s k h) (intern-folded-name tz s k h)))
          k))))))

;;; character references

(def windows-1252-c1
  '#u16(#x20ac 0 #x201a #x0192 #x201e #x2026 #x2020 #x2021 #x02c6 #x2030 #x0160 #x2039
        #x0152 0 #x017d 0 0 #x2018 #x2019 #x201c #x201d #x2022 #x2013 #x2014 #x02dc
        #x2122 #x0161 #x203a #x0153 0 #x017e #x0178))

(definline (ascii-alphanumeric? (b :- :fixnum)) => :boolean
  (or (ascii-alpha? b) (and (fx>= b (ascii #\0)) (fx<= b (ascii #\9)))))

;;; Child of trie node for byte b, or 0.
(defrule (trie-child node b)
  (let ((e (##u16vector-ref entity-edge-start (fx+ node 1)))
        (byte b))
    (let scan ((k (##u16vector-ref entity-edge-start node)))
      (if (fx< k e)
        (let (edge (##u8vector-ref entity-edge-byte k))
          (cond
           ((fx= edge byte) (##u16vector-ref entity-edge-target k))
           ((fx> edge byte) 0)
           (else (scan (fx+ k 1)))))
        0))))

;;; Matches the longest name from buf[k] on, below trie node (reached by the
;;; name bytes before k). Returns the index after the name, the negated value
;;; number in tz.reference; or -1 when the & is text.
(def (match-named-reference (tz         :- HTMLTokenizer)
                            (node       :- :fixnum)
                            (k          :- :fixnum)
                            (attribute? :- :boolean)) => :fixnum
  (let (buf tz.buf)
    (let loop ((node node) (k k) (best-end -1) (best-value 0))
      (let* ((v (##u16vector-ref entity-node-value node))
             (best-end (if (fx> v 0) k best-end))
             (best-value (if (fx> v 0) v best-value))
             (child (trie-child node (##u8vector-ref buf k))))
        (cond
         ((fx> child 0) (loop child (fx+ k 1) best-end best-value))
         ((fx< best-end 0) -1)
         ;; for historical reasons, an attribute keeps &name= and &namex as
         ;; text when name has no ;
         ((and attribute?
               (not (fx= (##u8vector-ref buf (fx- best-end 1)) (ascii #\;)))
               (let (next (##u8vector-ref buf best-end))
                 (or (fx= next (ascii #\=)) (ascii-alphanumeric? next))))
          -1)
         (else
          (set! tz.reference (fx- 0 best-value))
          best-end))))))

(def (numeric-reference-code (code :- :fixnum)) => :fixnum
  (cond
   ((or (fx= code 0) (fx> code #x10ffff)) #xfffd)
   ((and (fx>= code #xd800) (fx<= code #xdfff)) #xfffd)
   ((and (fx>= code #x80) (fx<= code #x9f))
    (let (mapped (##u16vector-ref windows-1252-c1 (fx- code #x80)))
      (if (fx= mapped 0) code mapped)))
   (else code)))

;;; Matches the numeric reference from buf[k], after &#. Returns the index
;;; after it, its code point in tz.reference; or -1 when it has no digits.
(def (match-numeric-reference (tz :- HTMLTokenizer)
                              (k  :- :fixnum)) => :fixnum
  (let* ((buf tz.buf)
         (b (##u8vector-ref buf k))
         (hex? (or (fx= b (ascii #\x)) (fx= b (ascii #\X))))
         (start (if hex? (fx+ k 1) k)))
    (let loop ((j start) (code 0))
      (let* ((b (##u8vector-ref buf j))
             (digit (cond
                     ((and (fx>= b (ascii #\0)) (fx<= b (ascii #\9))) (fx- b (ascii #\0)))
                     ((not hex?) -1)
                     ((and (fx>= b (ascii #\a)) (fx<= b (ascii #\f))) (fx- b (fx- (ascii #\a) 10)))
                     ((and (fx>= b (ascii #\A)) (fx<= b (ascii #\F))) (fx- b (fx- (ascii #\A) 10)))
                     (else -1))))
        (cond
         ((fx>= digit 0)
          ;; past U+10FFFF the value only needs to stay past it
          (loop (fx+ j 1) (if (fx> code #x10ffff) code (fx+ (fx* code (if hex? 16 10)) digit))))
         ((fx= j start) -1)
         (else
          (set! tz.reference (numeric-reference-code code))
          (if (fx= b (ascii #\;)) (fx+ j 1) j)))))))

;;; Matches the character reference at buf[j], an &. Returns the index after
;;; it, its value in tz.reference (a code point, or a negated value number of
;;; the trie); or -1 when the & is text.
(def (match-reference (tz         :- HTMLTokenizer)
                      (j          :- :fixnum)
                      (attribute? :- :boolean)) => :fixnum
  (let* ((buf tz.buf)
         (b (##u8vector-ref buf (fx+ j 1))))
    (if (fx= b (ascii #\#))
      (match-numeric-reference tz (fx+ j 2))
      ;; a direct table for the first two bytes: the trie is widest there
      (let (i1 (##u8vector-ref entity-byte-index b))
        (if (fx>= i1 52)
          -1
          (let (i2 (##u8vector-ref entity-byte-index (##u8vector-ref buf (fx+ j 2))))
            (if (fx>= i2 62)
              -1
              (let (node (##u16vector-ref entity-pair-child (fx+ (fx* i1 62) i2)))
                (if (fx= node 0)
                  -1
                  (match-named-reference tz node (fx+ j 3) attribute?))))))))))

;;; Appends the value of the reference match-reference left in tz.reference
;;; to the scratch; returns its count of continuation bytes.
(def (append-reference! (tz :- HTMLTokenizer)) => :fixnum
  (let (r tz.reference)
    (if (fx>= r 0)
      (using (out tz.scratch :- memory-output-buffer)
        (let* ((scratch (output-reserve! out 4))
               (fill out.whi)
               (next (&put-utf8! scratch fill r)))
          (set! out.whi next)
          (fx- (fx- next fill) 1)))
      (let* ((k (fx- -1 r))
             (s (##u16vector-ref entity-value-start k))
             (e (##u16vector-ref entity-value-start (fx+ k 1))))
        (output-append! tz.scratch entity-value-bytes s e)
        (&utf8-count-continuations entity-value-bytes s e)))))

;;; text

;;; text modes of scan-text
(defconst text-data 0)
(defconst text-rcdata 1)
(defconst text-rawtext 2)
(defconst text-plaintext 3)
(defconst text-script 4)

;;; Sets the character token: buf[s, e) with n continuation bytes, or, when
;;; rewritten?, the scratch plus buf[seg, e). Continues at e.
(def (text-token! (tz         :- HTMLTokenizer)
                  (s          :- :fixnum)
                  (seg        :- :fixnum)
                  (e          :- :fixnum)
                  (n          :- :fixnum)
                  (rewritten? :- :boolean)) => :fixnum
  (if rewritten?
    (begin
      (output-append! tz.scratch tz.buf seg e)
      (set! tz.text-bytes tz.scratch.buf)
      (set! tz.text-start 0)
      (set! tz.text-end tz.scratch.whi)
      (set! tz.text-chars (fx- tz.scratch.whi n)))
    (begin
      (set! tz.text-bytes tz.buf)
      (set! tz.text-start s)
      (set! tz.text-end e)
      (set! tz.text-chars (fx- (fx- e s) n))))
  (set! tz.i e)
  html-token-characters)

;;; Sets the character token buf[s, e) after input preprocessing: CR and
;;; CR LF as LF, and NUL as U+FFFD when replace-nul? is set. n counts its
;;; continuation bytes; rewrite? is true when it holds CR or (replaced) NUL.
(def (raw-text-token! (tz           :- HTMLTokenizer)
                      (s            :- :fixnum)
                      (e            :- :fixnum)
                      (n            :- :fixnum)
                      (rewrite?     :- :boolean)
                      (replace-nul? :- :boolean)) => :fixnum
  (if rewrite?
    (let (m (rewrite-span! tz s e replace-nul?))
      (set! tz.text-bytes tz.scratch.buf)
      (set! tz.text-start 0)
      (set! tz.text-end tz.scratch.whi)
      (set! tz.text-chars (fx- tz.scratch.whi m))
      (set! tz.i e)
      html-token-characters)
    (text-token! tz s s e n #f)))

;;; Scans a character token from i, which starts no tag of the state:
;;; character references are decoded in data and RCDATA text, NUL ends data
;;; text (it is a token of its own) and becomes U+FFFD in the others.
(def (scan-text (tz    :- HTMLTokenizer)
                (i     :- :fixnum)
                (mode  :- :fixnum)
                (table :- :u8vector)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((j i) (seg i) (n 0) (rewritten? #f))
      (defrule (resume k m) (loop k seg m rewritten?))
      (let* ((j (skip-plain buf table j))
             (c (##u8vector-ref table (##u8vector-ref buf j))))
        (cond
         ((fx= c class-high)
          (&utf8-check-run buf j end n invalid-utf8 resume))
         ((fx= c class-lt)
          (if (if (fx= mode text-data)
                (let (b (##u8vector-ref buf (fx+ j 1)))
                  (or (ascii-alpha? b) (fx= b (ascii #\/)) (fx= b (ascii #\!)) (fx= b (ascii #\?))))
                (fx>= (appropriate-end-tag tz j) 0))
            (text-token! tz i seg j n rewritten?)
            (loop (fx+ j 1) seg n rewritten?)))
         ((fx= c class-amp)
          (let (next (match-reference tz j #f))
            (if (fx< next 0)
              (loop (fx+ j 1) seg n rewritten?)
              (begin
                (rewrite-segment! tz rewritten? buf seg j)
                (loop next next (fx+ n (append-reference! tz)) #t)))))
         ((fx= c class-cr)
          (rewrite-segment! tz rewritten? buf seg j)
          (scratch-append-byte! tz (ascii #\newline))
          (let (next (after-cr buf j))
            (loop next next n #t)))
         ((or (fx>= j end) (fx= mode text-data))
          (text-token! tz i seg j n rewritten?))
         (else
          (rewrite-segment! tz rewritten? buf seg j)
          (scratch-append-replacement! tz)
          (loop (fx+ j 1) (fx+ j 1) (fx+ n 2) #t)))))))

;;; The index after the name of the end tag at buf[j], a <, when it is an
;;; appropriate end tag (its name, ASCII letters, is the last start tag's,
;;; followed by whitespace, / or >); otherwise -1.
(def (appropriate-end-tag (tz :- HTMLTokenizer)
                          (j  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (atom tz.last-start-tag))
    (if (or (fx= atom 0) (not (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\/))))
      -1
      (let* ((name (html-atom-name tz atom))
             (n (##string-length name))
             (s (fx+ j 2)))
        (let loop ((k 0))
          (if (fx< k n)
            (let (b (##u8vector-ref buf (fx+ s k)))
              (if (and (ascii-alpha? b)
                       (fx= (fxior b #x20) (##char->integer (##string-ref name k))))
                (loop (fx+ k 1))
                -1))
            (let (b (##u8vector-ref buf (fx+ s n)))
              (if (or (html-space-code? b) (fx= b (ascii #\/)) (fx= b (ascii #\>)))
                (fx+ s n)
                -1))))))))

;;; Index after the ASCII letters from k.
(def (skip-letters (buf :- :u8vector)
                   (k   :- :fixnum)) => :fixnum
  (if (ascii-alpha? (##u8vector-ref buf k)) (skip-letters buf (fx+ k 1)) k))

;;; True when buf[s, e) is "script", ASCII case-insensitively, and followed
;;; by whitespace, / or >.
(def (script-tag-at? (buf :- :u8vector)
                     (s   :- :fixnum)
                     (e   :- :fixnum)) => :boolean
  (and (fx= (fx- e s) 6)
       (match-ascii-ci? buf s "script")
       (let (b (##u8vector-ref buf e))
         (or (html-space-code? b) (fx= b (ascii #\/)) (fx= b (ascii #\>))))))

;;; script data sub-states
(defconst script-plain 0)
(defconst script-escaped 1)
(defconst script-escaped-dash 2)
(defconst script-escaped-dash-dash 3)
(defconst script-double 4)
(defconst script-double-dash 5)
(defconst script-double-dash-dash 6)

;;; Scans a script data character token from i up to an appropriate end tag
;;; that is not double escaped, or the end of input. script-text-ends?
;;; (./rules) runs the same states over a string for the writer; a test
;;; checks that the two agree.
(def (scan-script (tz :- HTMLTokenizer)
                  (i  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((j i) (state script-plain) (n 0) (rewrite? #f))
      (defrule (other s)
        (cond
         ((fx<= s script-escaped) s)
         ((fx<= s script-escaped-dash-dash) script-escaped)
         (else script-double)))
      (let* ((j (if (fx= state script-plain) (skip-plain buf rawtext-class j) j))
             (b (##u8vector-ref buf j)))
        (cond
         ((fx>= b #x80)
          (let (len (&utf8-sequence-length buf j))
            (when (fx= len 0)
              (invalid-utf8 j))
            (loop (fx+ j len) (other state) (fx+ n (fx- len 1)) rewrite?)))
         ((fx= b (ascii #\<))
          (cond
           ((fx>= state script-double)
            (if (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\/))
              (let (e (skip-letters buf (fx+ j 2)))
                (if (script-tag-at? buf (fx+ j 2) e)
                  (loop e script-escaped n rewrite?)
                  (loop e script-double n rewrite?)))
              (loop (fx+ j 1) script-double n rewrite?)))
           ((fx>= (appropriate-end-tag tz j) 0)
            (raw-text-token! tz i j n rewrite? #t))
           ((fx= state script-plain)
            (if (match-ascii? buf j "<!--")
              (loop (fx+ j 4) script-escaped-dash-dash n rewrite?)
              (loop (fx+ j 1) script-plain n rewrite?)))
           ((ascii-alpha? (##u8vector-ref buf (fx+ j 1)))
            (let (e (skip-letters buf (fx+ j 1)))
              (if (script-tag-at? buf (fx+ j 1) e)
                (loop e script-double n rewrite?)
                (loop e script-escaped n rewrite?))))
           (else (loop (fx+ j 1) script-escaped n rewrite?))))
         ((fx= b (ascii #\-))
          (loop (fx+ j 1)
                (cond
                 ((fx= state script-plain) script-plain)
                 ((fx= state script-escaped) script-escaped-dash)
                 ((fx<= state script-escaped-dash-dash) script-escaped-dash-dash)
                 ((fx= state script-double) script-double-dash)
                 (else script-double-dash-dash))
                n rewrite?))
         ((fx= b (ascii #\>))
          (loop (fx+ j 1)
                (if (or (fx= state script-escaped-dash-dash) (fx= state script-double-dash-dash))
                  script-plain
                  (other state))
                n rewrite?))
         ((fx= b 0)
          (if (fx>= j end)
            (raw-text-token! tz i j n rewrite? #t)
            (loop (fx+ j 1) (other state) (fx+ n 2) #t)))
         ((fx= b (ascii #\return))
          (loop (fx+ j 1) (other state) n #t))
         (else (loop (fx+ j 1) (other state) n rewrite?)))))))

;;; Scans a CDATA section character token from i up to ]]>, NUL or the end
;;; of input.
(def (scan-cdata (tz :- HTMLTokenizer)
                 (i  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((j i) (n 0) (rewrite? #f))
      (defrule (resume k m) (loop k m rewrite?))
      (let* ((j (skip-plain buf cdata-class j))
             (c (##u8vector-ref cdata-class (##u8vector-ref buf j))))
        (cond
         ((fx= c class-high) (&utf8-check-run buf j end n invalid-utf8 resume))
         ((fx= c class-bracket)
          (if (match-ascii? buf j "]]>")
            (raw-text-token! tz i j n rewrite? #f)
            (loop (fx+ j 1) n rewrite?)))
         ((fx= c class-cr) (loop (fx+ j 1) n #t))
         (else (raw-text-token! tz i j n rewrite? #f)))))))

;;; tags

(defrule (finish-tag! tz next kind)
  (using (t tz :- HTMLTokenizer)
    (set! t.i next)
    (when (fx= kind html-token-start-tag)
      (set! t.last-start-tag t.tag))
    kind))

(def (token-eof! (tz :- HTMLTokenizer)) => :fixnum
  (set! tz.i tz.end)
  html-token-eof)

;;; True the first time atom names an attribute of the current tag.
(defrule (first-attribute? tz atom)
  (using (t tz :- HTMLTokenizer)
    (let ((seen t.seen)
          (serial t.serial))
      (and (not (eq? (##vector-ref seen atom) serial))
           (begin
             (##vector-set! seen atom serial)
             #t)))))

(def (push-attribute! (tz    :- HTMLTokenizer)
                      (atom  :- :fixnum)
                      (value :- :string)) => :void
  (let* ((count tz.attribute-count)
         (k (fx* 2 count))
         (attributes tz.attributes)
         (attributes (if (fx< (fx+ k 1) (##vector-length attributes))
                       attributes
                       (let (new (vector-grow attributes k 0))
                         (set! tz.attributes new)
                         new))))
    (##vector-set! attributes k atom)
    (##vector-set! attributes (fx+ k 1) value)
    (set! tz.attribute-count (fx+ count 1))))

;;; String of a scanned value: buf[s, e) with n continuation bytes, or the
;;; scratch plus buf[seg, e) when rewritten?.
(def (value-string (tz         :- HTMLTokenizer)
                   (s          :- :fixnum)
                   (seg        :- :fixnum)
                   (e          :- :fixnum)
                   (n          :- :fixnum)
                   (rewritten? :- :boolean)) => :string
  (if rewritten?
    (begin
      (output-append! tz.scratch tz.buf seg e)
      (&utf8-decode tz.scratch.buf 0 tz.scratch.whi (fx- tz.scratch.whi n)))
    (&utf8-decode tz.buf s e (fx- (fx- e s) n))))

;;; Scans an attribute value from i, after its opening quote, through the
;;; closing quote table classes as class-quote. Returns the index after it,
;;; or -1 at the end of input; leaves the value in tz.value when keep?.
(def (scan-quoted-value (tz    :- HTMLTokenizer)
                        (i     :- :fixnum)
                        (table :- :u8vector)
                        (keep? :- :boolean)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((j i) (seg i) (n 0) (rewritten? #f))
      (defrule (resume k m) (loop k seg m rewritten?))
      (let* ((j (skip-plain buf table j))
             (c (##u8vector-ref table (##u8vector-ref buf j))))
        (cond
         ((fx= c class-quote)
          (when keep?
            (set! tz.value (value-string tz i seg j n rewritten?)))
          (fx+ j 1))
         ((fx= c class-high) (&utf8-check-run buf j end n invalid-utf8 resume))
         ((fx= c class-amp)
          (let (next (match-reference tz j #t))
            (if (fx< next 0)
              (loop (fx+ j 1) seg n rewritten?)
              (begin
                (rewrite-segment! tz rewritten? buf seg j)
                (loop next next (fx+ n (append-reference! tz)) #t)))))
         ((fx= c class-cr)
          (rewrite-segment! tz rewritten? buf seg j)
          (scratch-append-byte! tz (ascii #\newline))
          (let (next (after-cr buf j))
            (loop next next n #t)))
         ((fx>= j end) -1)
         (else
          (rewrite-segment! tz rewritten? buf seg j)
          (scratch-append-replacement! tz)
          (loop (fx+ j 1) (fx+ j 1) (fx+ n 2) #t)))))))

;;; Scans an unquoted attribute value from i. Returns the index of the
;;; whitespace or > that ends it, or -1 at the end of input; leaves the value
;;; in tz.value when keep?.
(def (scan-unquoted-value (tz    :- HTMLTokenizer)
                          (i     :- :fixnum)
                          (keep? :- :boolean)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end)
        (table unquoted-class))
    (let loop ((j i) (seg i) (n 0) (rewritten? #f))
      (defrule (resume k m) (loop k seg m rewritten?))
      (let* ((j (skip-plain buf table j))
             (c (##u8vector-ref table (##u8vector-ref buf j))))
        (cond
         ((or (fx= c class-space) (fx= c class-gt))
          (when keep?
            (set! tz.value (value-string tz i seg j n rewritten?)))
          j)
         ((fx= c class-high) (&utf8-check-run buf j end n invalid-utf8 resume))
         ((fx= c class-amp)
          (let (next (match-reference tz j #t))
            (if (fx< next 0)
              (loop (fx+ j 1) seg n rewritten?)
              (begin
                (rewrite-segment! tz rewritten? buf seg j)
                (loop next next (fx+ n (append-reference! tz)) #t)))))
         ((fx>= j end) -1)
         (else
          (rewrite-segment! tz rewritten? buf seg j)
          (scratch-append-replacement! tz)
          (loop (fx+ j 1) (fx+ j 1) (fx+ n 2) #t)))))))

;;; Scans the attributes of the current tag from i, after its name, through
;;; its >. Returns kind, or html-token-eof at the end of input (the tag is
;;; dropped). End tag attributes are scanned but not kept.
(def (scan-attributes (tz   :- HTMLTokenizer)
                      (i    :- :fixnum)
                      (kind :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end)
        (start? (fx= kind html-token-start-tag)))
    (let loop ((i i))
      (let* ((j (skip-space buf i))
             (b (##u8vector-ref buf j)))
        (cond
         ((fx= b (ascii #\>)) (finish-tag! tz (fx+ j 1) kind))
         ((fx= b (ascii #\/))
          (if (fx= (##u8vector-ref buf (fx+ j 1)) (ascii #\>))
            (begin
              (set! tz.self-closing? #t)
              (finish-tag! tz (fx+ j 2) kind))
            (loop (fx+ j 1))))
         ((and (fx= b 0) (fx>= j end)) (token-eof! tz))
         (else
          ;; an attribute name can start with =
          (let* ((e (if (fx= b (ascii #\=))
                      (scan-name tz j (fx+ j 1) (fnv fnv-basis b) attribute-name-class)
                      (scan-name tz j j fnv-basis attribute-name-class)))
                 (atom tz.atom)
                 (keep? (and start? (first-attribute? tz atom)))
                 (k (skip-space buf e)))
            (if (fx= (##u8vector-ref buf k) (ascii #\=))
              (let* ((v (skip-space buf (fx+ k 1)))
                     (q (##u8vector-ref buf v)))
                (cond
                 ((fx= q (ascii #\>))
                  (when keep?
                    (push-attribute! tz atom ""))
                  (finish-tag! tz (fx+ v 1) kind))
                 (else
                  (let (next (cond
                              ((fx= q (ascii #\"))
                               (scan-quoted-value tz (fx+ v 1) double-quoted-class keep?))
                              ((fx= q (ascii #\'))
                               (scan-quoted-value tz (fx+ v 1) single-quoted-class keep?))
                              (else (scan-unquoted-value tz v keep?))))
                    (cond
                     ((fx< next 0) (token-eof! tz))
                     (else
                      (when keep?
                        (push-attribute! tz atom tz.value))
                      (loop next)))))))
              (begin
                (when keep?
                  (push-attribute! tz atom ""))
                (loop k))))))))))

(def (start-tag! (tz   :- HTMLTokenizer)
                 (atom :- :fixnum)) => :void
  (set! tz.tag atom)
  (set! tz.self-closing? #f)
  (set! tz.attribute-count 0)
  (set! tz.serial (fx+ tz.serial 1)))

;;; Scans a tag from i, its name's first letter.
(def (scan-tag (tz   :- HTMLTokenizer)
               (i    :- :fixnum)
               (kind :- :fixnum)) => :fixnum
  (let (e (scan-name tz i i fnv-basis tag-name-class))
    (start-tag! tz tz.atom)
    (scan-attributes tz e kind)))

;;; Scans the appropriate end tag whose name ends at e.
(def (scan-appropriate-end-tag (tz :- HTMLTokenizer)
                               (e  :- :fixnum)) => :fixnum
  (start-tag! tz tz.last-start-tag)
  (set! tz.state html-state-data)
  (scan-attributes tz e html-token-end-tag))

;;; comments

(def (comment-token! (tz   :- HTMLTokenizer)
                     (s    :- :fixnum)
                     (e    :- :fixnum)
                     (next :- :fixnum)) => :fixnum
  (set! tz.data (span-text tz s e #t))
  (set! tz.i next)
  html-token-comment)

;;; Scans a bogus comment from s through > or the end of input.
(def (scan-bogus-comment (tz :- HTMLTokenizer)
                         (s  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((k s))
      (let (b (##u8vector-ref buf k))
        (cond
         ((fx= b (ascii #\>)) (comment-token! tz s k (fx+ k 1)))
         ((and (fx= b 0) (fx>= k end)) (comment-token! tz s k k))
         (else (loop (fx+ k 1))))))))

;;; comment end states: the dashes (and !) held back from the data
(defconst comment-text 0)
(defconst comment-end-dash 1)    ; -
(defconst comment-end 2)         ; --
(defconst comment-end-bang 3)    ; --!

;;; Scans a comment from s, after <!--, through its end or the end of input.
(def (scan-comment (tz :- HTMLTokenizer)
                   (s  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (cond
     ((fx= (##u8vector-ref buf s) (ascii #\>)) (comment-token! tz s s (fx+ s 1)))
     ((match-ascii? buf s "->") (comment-token! tz s s (fx+ s 2)))
     (else
      (let loop ((k s) (state comment-text))
        (let* ((k (if (fx= state comment-text) (skip-plain buf comment-class k) k))
               (b (##u8vector-ref buf k)))
          (cond
           ((fx= b (ascii #\-))
            (loop (fx+ k 1) (if (or (fx= state comment-end-dash) (fx= state comment-end))
                              comment-end
                              comment-end-dash)))
           ((fx= b (ascii #\>))
            (if (fx>= state comment-end)
              (comment-token! tz s (fx- k state) (fx+ k 1))
              (loop (fx+ k 1) comment-text)))
           ((fx= b (ascii #\!))
            (loop (fx+ k 1) (if (fx= state comment-end) comment-end-bang comment-text)))
           ((and (fx= b 0) (fx>= k end))
            (comment-token! tz s (fx- k state) k))
           (else (loop (fx+ k 1) comment-text)))))))))

;;; DOCTYPE

;;; The DOCTYPE name buf[s, e), ASCII lower-cased, NUL as U+FFFD.
(def (doctype-name-text (tz :- HTMLTokenizer)
                        (s  :- :fixnum)
                        (e  :- :fixnum)) => :string
  (let ((buf tz.buf)
        (n (check-utf8 tz s e)))
    (set! tz.scratch.whi 0)
    (let loop ((k s) (n n))
      (if (fx< k e)
        (let (b (##u8vector-ref buf k))
          (cond
           ((fx= b 0)
            (scratch-append-replacement! tz)
            (loop (fx+ k 1) (fx+ n 2)))
           ((and (fx>= b (ascii #\A)) (fx<= b (ascii #\Z)))
            (scratch-append-byte! tz (fx+ b #x20))
            (loop (fx+ k 1) n))
           (else
            (scratch-append-byte! tz b)
            (loop (fx+ k 1) n))))
        (&utf8-decode tz.scratch.buf 0 tz.scratch.whi (fx- tz.scratch.whi n))))))

;;; Scans a DOCTYPE from i, after <!DOCTYPE, through > or the end of input.
(def (scan-doctype (tz :- HTMLTokenizer)
                   (i  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (defrule (eof? k) (and (fx= (##u8vector-ref buf k) 0) (fx>= k end)))
    (def (emit k)
      (set! tz.i k)
      html-token-doctype)
    (def (quirks k)
      (set! tz.force-quirks? #t)
      (emit k))
    ;; bogus DOCTYPE: the rest up to > is ignored
    (def (bogus k)
      (let loop ((e k))
        (cond
         ((fx= (##u8vector-ref buf e) (ascii #\>))
          (check-utf8 tz k e)
          (emit (fx+ e 1)))
         ((eof? e)
          (check-utf8 tz k e)
          (emit e))
         (else (loop (fx+ e 1))))))
    (def (identifier k q public?)
      (let loop ((e k))
        (let (b (##u8vector-ref buf e))
          (defrule (set-id!)
            (let (id (span-text tz k e #t))
              (if public?
                (set! tz.public-id id)
                (set! tz.system-id id))))
          (cond
           ((fx= b q)
            (set-id!)
            (after-identifier (fx+ e 1) public?))
           ((fx= b (ascii #\>))
            (set-id!)
            (quirks (fx+ e 1)))
           ((eof? e)
            (set-id!)
            (quirks e))
           (else (loop (fx+ e 1)))))))
    ;; after a public or system keyword, or before an identifier
    (def (before-identifier k public?)
      (let* ((k (skip-space buf k))
             (b (##u8vector-ref buf k)))
        (cond
         ((or (fx= b (ascii #\")) (fx= b (ascii #\'))) (identifier (fx+ k 1) b public?))
         ((fx= b (ascii #\>)) (quirks (fx+ k 1)))
         ((eof? k) (quirks k))
         (else
          (set! tz.force-quirks? #t)
          (bogus k)))))
    (def (after-identifier k public?)
      (let* ((k (skip-space buf k))
             (b (##u8vector-ref buf k)))
        (cond
         ((fx= b (ascii #\>)) (emit (fx+ k 1)))
         ((eof? k) (quirks k))
         ((and public? (or (fx= b (ascii #\")) (fx= b (ascii #\'))))
          (identifier (fx+ k 1) b #f))
         (public?
          (set! tz.force-quirks? #t)
          (bogus k))
         (else (bogus k)))))
    (set! tz.doctype-name #f)
    (set! tz.public-id #f)
    (set! tz.system-id #f)
    (set! tz.force-quirks? #f)
    (let* ((k (skip-space buf i))
           (b (##u8vector-ref buf k)))
      (cond
       ((eof? k) (quirks k))
       ((fx= b (ascii #\>)) (quirks (fx+ k 1)))
       (else
        (let* ((e (let loop ((e (fx+ k 1)))
                    (let (b (##u8vector-ref buf e))
                      (if (or (html-space-code? b) (fx= b (ascii #\>)) (and (fx= b 0) (fx>= e end)))
                        e
                        (loop (fx+ e 1))))))
               (k (begin
                    (set! tz.doctype-name (doctype-name-text tz k e))
                    (skip-space buf e))))
          (cond
           ((fx= (##u8vector-ref buf k) (ascii #\>)) (emit (fx+ k 1)))
           ((eof? k) (quirks k))
           ((match-ascii-ci? buf k "public") (before-identifier (fx+ k 6) #t))
           ((match-ascii-ci? buf k "system") (before-identifier (fx+ k 6) #f))
           (else
            (set! tz.force-quirks? #t)
            (bogus k)))))))))

;;; processing instructions

;;; Scans a processing instruction from i, after <?.
(def (scan-processing-instruction (tz :- HTMLTokenizer)
                                  (i  :- :fixnum)) => :fixnum
  (let* ((buf tz.buf)
         (end tz.end)
         (b (##u8vector-ref buf i)))
    (cond
     ((pi-target-code? b #t)
      (let* ((e (let loop ((e (fx+ i 1)))
                  (if (pi-target-code? (##u8vector-ref buf e) #f) (loop (fx+ e 1)) e)))
             (c (##u8vector-ref buf e)))
        (cond
         ((or (html-space-code? c) (fx= c (ascii #\?)) (fx= c (ascii #\>)))
          (let (target (&utf8-decode buf i e (fx- e i)))
            (if (reserved-pi-target? target)
              (scan-bogus-comment tz (fx- i 1))
              (begin
                (set! tz.target target)
                (scan-pi-data tz (skip-space buf e))))))
         ((and (fx= c 0) (fx>= e end)) (token-eof! tz))
         (else (scan-bogus-comment tz (fx- i 1))))))
     ((and (fx= b 0) (fx>= i end)) (token-eof! tz))
     (else (scan-bogus-comment tz (fx- i 1))))))

;;; Scans processing instruction data from s through >; a ? before the > is
;;; not data. At the end of input the instruction is dropped.
(def (scan-pi-data (tz :- HTMLTokenizer)
                   (s  :- :fixnum)) => :fixnum
  (let ((buf tz.buf)
        (end tz.end))
    (let loop ((k s))
      (let (b (##u8vector-ref buf k))
        (cond
         ((fx= b (ascii #\>))
          (let (e (if (and (fx> k s) (fx= (##u8vector-ref buf (fx- k 1)) (ascii #\?))) (fx- k 1) k))
            (set! tz.data (span-text tz s e #f))
            (set! tz.i (fx+ k 1))
            html-token-pi))
         ((and (fx= b 0) (fx>= k end))
          (check-utf8 tz s k)
          (token-eof! tz))
         (else (loop (fx+ k 1))))))))

;;; states

;;; Markup declaration open state, at i after <!.
(def (scan-markup-declaration (tz :- HTMLTokenizer)
                              (i  :- :fixnum)) => :fixnum
  (let (buf tz.buf)
    (cond
     ((match-ascii? buf i "--") (scan-comment tz (fx+ i 2)))
     ((match-ascii-ci? buf i "doctype") (scan-doctype tz (fx+ i 7)))
     ((and tz.cdata? (match-ascii? buf i "[CDATA["))
      (set! tz.state html-state-cdata)
      (next-cdata tz (fx+ i 7)))
     (else (scan-bogus-comment tz i)))))

(def (next-data (tz :- HTMLTokenizer)
                (i  :- :fixnum)) => :fixnum
  (let* ((buf tz.buf)
         (b (##u8vector-ref buf i)))
    (cond
     ((fx= b (ascii #\<))
      (let (c (##u8vector-ref buf (fx+ i 1)))
        (cond
         ((ascii-alpha? c) (scan-tag tz (fx+ i 1) html-token-start-tag))
         ((fx= c (ascii #\/))
          (let (d (##u8vector-ref buf (fx+ i 2)))
            (cond
             ((ascii-alpha? d) (scan-tag tz (fx+ i 2) html-token-end-tag))
             ((fx= d (ascii #\>))
              (set! tz.start (fx+ i 3))
              (next-data tz (fx+ i 3)))
             ((and (fx= d 0) (fx>= (fx+ i 2) tz.end)) (text-token! tz i i (fx+ i 2) 0 #f))
             (else (scan-bogus-comment tz (fx+ i 2))))))
         ((fx= c (ascii #\!)) (scan-markup-declaration tz (fx+ i 2)))
         ((fx= c (ascii #\?)) (scan-processing-instruction tz (fx+ i 2)))
         (else (scan-text tz i text-data data-class)))))
     ((fx= b 0)
      (if (fx>= i tz.end)
        (token-eof! tz)
        (begin
          (set! tz.i (fx+ i 1))
          html-token-null-character)))
     (else (scan-text tz i text-data data-class)))))

;;; RCDATA, RAWTEXT and script data: an appropriate end tag, or text.
(def (next-raw (tz   :- HTMLTokenizer)
               (i    :- :fixnum)
               (mode :- :fixnum)) => :fixnum
  (let* ((buf tz.buf)
         (b (##u8vector-ref buf i))
         (e (if (fx= b (ascii #\<)) (appropriate-end-tag tz i) -1)))
    (cond
     ((fx>= e 0) (scan-appropriate-end-tag tz e))
     ((and (fx= b 0) (fx>= i tz.end)) (token-eof! tz))
     ((fx= mode text-rcdata) (scan-text tz i text-rcdata data-class))
     ((fx= mode text-rawtext) (scan-text tz i text-rawtext rawtext-class))
     (else (scan-script tz i)))))

(def (next-cdata (tz :- HTMLTokenizer)
                 (i  :- :fixnum)) => :fixnum
  (let* ((buf tz.buf)
         (b (##u8vector-ref buf i)))
    (cond
     ((fx= b 0)
      (if (fx>= i tz.end)
        (token-eof! tz)
        (begin
          (set! tz.i (fx+ i 1))
          html-token-null-character)))
     ((match-ascii? buf i "]]>")
      (set! tz.state html-state-data)
      (set! tz.start (fx+ i 3))
      (next-data tz (fx+ i 3)))
     (else (scan-cdata tz i)))))

;;; Scans the next token; returns its kind and leaves it in the registers.
;;; At the end of input, returns html-token-eof again on every call. The
;;; kind is eof while the token is scanned, so after a raise no accessor
;;; reads the half-written registers.
(def (html-tokenizer-next! (tz :- HTMLTokenizer)) => :fixnum
  (set! tz.kind html-token-eof)
  (set! tz.start tz.i)
  (let* ((state tz.state)
         (i tz.i)
         (kind (cond
                ((fx= state html-state-data) (next-data tz i))
                ((fx= state html-state-rcdata) (next-raw tz i text-rcdata))
                ((fx= state html-state-rawtext) (next-raw tz i text-rawtext))
                ((fx= state html-state-script-data) (next-raw tz i text-script))
                ((fx= state html-state-plaintext)
                 (if (fx>= i tz.end)
                   (token-eof! tz)
                   (scan-text tz i text-plaintext plaintext-class)))
                (else (next-cdata tz i)))))
    (set! tz.kind kind)
    kind))

;;; The characters of the current character token.
(def (html-token-text (tz :- HTMLTokenizer)) => :string
  (&utf8-decode tz.text-bytes tz.text-start tz.text-end tz.text-chars))

;;; The input index where the next token starts: a byte offset into the
;;; scan input (for :std/text/markup/tal's template positions).
(def (html-tokenizer-offset (tz :- HTMLTokenizer)) => :fixnum
  tz.i)

;;; Offset in the caller's input of scan input index i: i itself for byte
;;; input, the number of characters before i for input encoded from a string.
(def (html-input-offset (tz :- HTMLTokenizer)
                        (i  :- :fixnum)) => :fixnum
  (scan-input-offset tz.buf tz.end tz.mapped? i))

;;; A tokenizer over the scan input buffer buf, input in [start, end);
;;; mapped? when buf was encoded from a string.
(def (scan-input->html-tokenizer (buf     :- :u8vector)
                                 (start   :- :fixnum)
                                 (end     :- :fixnum)
                                 (mapped? :- :boolean)) => HTMLTokenizer
  (make-HTMLTokenizer buf end mapped? start start html-state-data 0 #f html-token-eof
                       (make-memory-output 256)
                       buf 0 0 0
                       0 #f (make-vector 16 #f) 0
                       "" "" #f #f #f #f
                       0 "" 0
                       (make-vector 64 #f) 0 (make-vector 16 #f) #f
                       (make-vector (fx+ known-atom-count 64) 0) 0))
