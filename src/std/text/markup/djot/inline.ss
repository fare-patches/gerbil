;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Delimiter precedence follows djot.js by John MacFarlane (MIT; testdata/LICENSE).
(import (only-in :std/error raise/context)
        (only-in :std/string/misc string-concatenate-reverse)
        ./ast
        ./attributes)
(export (struct-out source-slice)
        slice-source
        parse-inlines
        normalize-reference-label
        inline-string-content)

;;; A slice always indexes the original input, even after a block prefix is removed.
(defstruct source-slice
  ((start      : :fixnum)
   (end        : :fixnum)
   (line       : :fixnum)
   (line-start : :fixnum)
   (next       : :fixnum)))

(def (slice-source (slice : source-slice)) => djot-source-range
  (make-djot-source-range
   slice.start slice.end
   slice.line
   (+ 1 (- slice.start slice.line-start))
   slice.line
   (+ 1 (- slice.end slice.line-start))))

(defstruct inline-token
  ((start      : :fixnum)
   (end        : :fixnum)
   (kind       : :symbol)
   (mate       : :fixnum)
   (middle     : :fixnum)
   (value      : :string)
   (attributes : :list)))

(defstruct inline-opener
  ((index  : :fixnum)
   (start  : :fixnum)
   (end    : :fixnum)
   (mode   : :symbol)
   (middle : :fixnum)))

(defstruct inline-parser
  ((input        : :string)
   (text         : :string)
   (slice-starts : :vector)
   (slices       : :vector)
   (tokens       : :vector)
   (count        : :fixnum)
   (openers      : :vector)
   (destination? : :boolean)
   (locations?   : :boolean)))

(def (inline-slice-end (input : :string)
                       (slice : source-slice)
                       (last? : :boolean)) => :fixnum
  (if last?
    (let trim ((p slice.end : :fixnum)) => :fixnum
      (if (and (> p slice.start)
               (let (c (string-ref input (- p 1)))
                 (or (char=? c #\space) (char=? c #\tab))))
        (trim (- p 1)) p))
    slice.end))

(def (inline-slice-newline? (input : :string)
                            (slice : source-slice)
                            (last? : :boolean)) => :boolean
  (not (and last?
            (or (= slice.end (string-length input))
                (not (memv (string-ref input slice.end)
                           '(#\newline #\return)))))))

(def (new-inline-parser (input      : :string)
                        (slices     : :list)
                        (locations? : :boolean)) => inline-parser
  ;; Each physical slice is contiguous in the grammar string. Store its grammar
  ;; start once, not an offset and slice pointer for every character. A CRLF
  ;; occupies one grammar position but two original characters; removed prefixes
  ;; occupy neither. Both passes use the same trimming/newline rules.
  (let* ((final-end 0)
         (size (let count ((rest slices) (size 0 : :fixnum)) => :fixnum
                 (if (null? rest) size
                     (let* ((s (:- (car rest) source-slice))
                            (last? (null? (cdr rest)))
                            (end (inline-slice-end input s last?)))
                       ;; Keep the final trim boundary for the fill pass.
                       (when last? (set! final-end end))
                       (count (cdr rest)
                              (+ size (- end (source-slice-start s))
                                 (if (inline-slice-newline? input s last?) 1 0)))))))
         (text (make-string size))
         (slice-starts (make-vector (length slices)))
         (sources (list->vector slices)))
    (let loop ((rest slices) (index 0 : :fixnum) (slot 0 : :fixnum)) => inline-parser
      (if (null? rest)
        (make-inline-parser input text slice-starts sources (make-vector (min 32 (+ 1 (* 2 size))))
                            0 (make-vector inline-opener-slot-count []) #f locations?)
        (let* ((s (:- (car rest) source-slice))
               (last? (null? (cdr rest)))
               (end (if last? final-end (source-slice-end s)))
               (next (fx+ index (fx- end (source-slice-start s)))))
          (vector-set! slice-starts slot index)
          (substring-move! input (source-slice-start s) end text index)
          (if (inline-slice-newline? input s last?)
            (begin
              (string-set! text next #\newline)
              (loop (cdr rest) (fx+ next 1) (fx+ slot 1)))
            (loop (cdr rest) next (fx+ slot 1))))))))

(def (inline-length (parser : inline-parser)) => :fixnum
  (string-length parser.text))

(def (inline-char (parser : inline-parser)
                  (p      : :fixnum)) => :char
  (if (or (< p 0) (>= p (inline-length parser))) #\newline
      (string-ref parser.text p)))

;;; Find the physical slice containing a valid grammar position. Non-final slices
;;; include a newline, so their starts strictly increase, even for empty lines.
(def (inline-slice-index (parser : inline-parser)
                         (p      : :fixnum)) => :fixnum
  (let (starts parser.slice-starts)
    (let search ((low 0 : :fixnum) (high (vector-length starts) : :fixnum)) => :fixnum
      (if (fx= (fx- high low) 1) low
          (let (mid (fx+ low (fxquotient (fx- high low) 2)))
            (if (fx<= (:- (vector-ref starts mid) :fixnum) p)
              (search mid high) (search low mid)))))))

(def (inline-text (parser : inline-parser)
                  (start  : :fixnum)
                  (end    : :fixnum)) => :string
  (substring parser.text start end))

(def (inline-range (parser : inline-parser)
                   (start  : :fixnum)
                   (end    : :fixnum))
  => (Maybe djot-source-range)
  (and parser.locations? (< start end)
       (let* ((last (fx- end 1))
              (a (inline-slice-index parser start))
              (b (inline-slice-index parser last))
              (sa (:- (vector-ref parser.slices a) source-slice))
              (sb (:- (vector-ref parser.slices b) source-slice))
              (starts parser.slice-starts)
              (newline? (char=? (inline-char parser last) #\newline))
              (source-start
               (if (char=? (inline-char parser start) #\newline) (source-slice-end sa)
                   (fx+ (source-slice-start sa) (fx- start (:- (vector-ref starts a) :fixnum)))))
              (source-end
               (if newline? (source-slice-next sb)
                   (fx+ (source-slice-start sb) (fx- end (:- (vector-ref starts b) :fixnum))))))
         (make-djot-source-range
          source-start source-end
          (source-slice-line sa) (+ 1 (- source-start (source-slice-line-start sa)))
          (if newline? (+ 1 (source-slice-line sb)) (source-slice-line sb))
          (if newline? 1 (+ 1 (- source-end (source-slice-line-start sb))))))))

(def (inline-token-at (parser : inline-parser)
                      (index  : :fixnum)) => inline-token
  (:- (vector-ref parser.tokens index) inline-token))

(def (emit-inline! (parser : inline-parser)
                   (start  : :fixnum)
                   (end    : :fixnum)
                   (kind   : :symbol)) => :fixnum
  (let (i parser.count)
    ;; Ordinary text runs produce one token, not one token per character.
    ;; Grow only when full; token indexes and opener references stay unchanged.
    (when (= i (vector-length parser.tokens))
      (let (tokens (make-vector (+ 1 (* 2 i))))
        (subvector-move! parser.tokens 0 i tokens 0)
        (set! parser.tokens tokens)))
    (vector-set! parser.tokens i (make-inline-token start end kind -1 -1 "" []))
    (set! parser.count (+ i 1))
    i))

;;; Nine plain and nine braced delimiter stacks, followed by brackets and
;;; destination parentheses. Input never supplies a slot number.
(def inline-bracket-slot 18)
(def inline-paren-slot 19)
(def inline-opener-slot-count 20)

(def (delimiter-opener-slot (c       : :char)
                            (braced? : :boolean)) => :fixnum
  (fx+ (if braced? 9 0)
       (case c
         ((#\_) 0) ((#\*) 1) ((#\~) 2) ((#\^) 3) ((#\+) 4)
         ((#\=) 5) ((#\-) 6) ((#\') 7) ((#\") 8)
         (else (error "Invalid inline delimiter" c)))))

(def (inline-openers (parser : inline-parser)
                     (slot   : :fixnum)) => :list
  ;; Entries are only empty lists, consed openers, or tails of those lists.
  (:- (vector-ref parser.openers slot) :list))

(def (add-inline-opener! (parser : inline-parser)
                         (slot   : :fixnum)
                         (start  : :fixnum)
                         (end    : :fixnum)
                         (kind   : :symbol)) => :void
  (let (i (emit-inline! parser start end kind))
    (vector-set! parser.openers slot
                 (cons (make-inline-opener i start end 'plain -1) (inline-openers parser slot)))))

(def (clear-inline-openers! (parser : inline-parser)
                            (start  : :fixnum)) => :void
  ;; Each opener is removed once; retained list spines must not be revalidated.
  (let (stacks parser.openers)
    (let slots ((slot 0 : :fixnum)) => :void
      (when (fx< slot inline-opener-slot-count)
        (let loop ((rest (:- (vector-ref stacks slot) :list))) => :void
          (cond ((null? rest) (vector-set! stacks slot []))
                ((>= (inline-opener-start (:- (car rest) inline-opener)) start)
                 (loop (cdr rest)))
                (else
                 (let (opener (:- (car rest) inline-opener))
                   (when (and (>= (inline-opener-middle opener) 0)
                              (>= (inline-token-start (inline-token-at parser (inline-opener-middle opener))) start))
                     (inline-opener-mode-set! opener 'plain)
                     (inline-opener-middle-set! opener -1)))
                 (vector-set! stacks slot rest))))
        (slots (fx+ slot 1))))))

(def (ascii-punctuation? (c : :char)) => :boolean
  (or (char<=? #\! c #\/) (char<=? #\: c #\@)
      (char<=? #\[ c #\`) (char<=? #\{ c #\~)))

(def (inline-delimiter? (c : :char)) => :boolean
  (case c
    ((#\_ #\* #\~ #\^ #\+ #\= #\- #\' #\") #t)
    (else #f)))

(defrule (inline-special? c)
  (case c
    ((#\_ #\* #\~ #\^ #\+ #\= #\- #\' #\"
      #\newline #\` #\\ #\< #\{ #\: #\. #\[ #\] #\( #\) #\$ #\!) #t)
    (else #f)))

(def (inline-run-end (parser : inline-parser)
                     (start  : :fixnum)
                     (c      : :char)) => :fixnum
  (let loop ((p start : :fixnum)) => :fixnum
    (if (and (< p (inline-length parser)) (char=? (inline-char parser p) c))
      (loop (+ p 1)) p)))

(def (delimiter-kind (c : :char)) => :symbol
  (case c ((#\_) 'emph) ((#\*) 'strong) ((#\~) 'subscript) ((#\^) 'superscript)
        ((#\+) 'insert) ((#\=) 'mark) ((#\-) 'delete) ((#\') 'single-quoted)
        (else 'double-quoted)))

(def (match-inline-delimiter! (parser  : inline-parser)
                              (start   : :fixnum)
                              (p       : :fixnum)
                              (marked? : :boolean)) => :fixnum
  (let* ((c (inline-char parser p))
         (close? (char=? (inline-char parser (+ p 1)) #\}))
         (end (fx+ p (if (and close? (not marked?)) 2 1)))
         (slot (delimiter-opener-slot c close?))
         (openers (inline-openers parser slot))
         (can-close? (and (not marked?) (or close? (not (ascii-space? (inline-char parser (- p 1)))))))
         (can-open? (or marked?
                        (and (not close?) (not (ascii-space? (inline-char parser (+ p 1))))
                             (not (memv c '(#\+ #\= #\-)))
                             (or (not (char=? c #\')) (= p 0)
                                 (memv (inline-char parser (- p 1))
                                       '(#\space #\tab #\newline #\" #\' #\- #\( #\[))))))
         (default (cond ((char=? c #\') (if marked? 'left-single-quote 'right-single-quote))
                        ((char=? c #\") (if close? 'right-double-quote 'left-double-quote))
                        (else 'text)))
         (opener (and (pair? openers) (car openers))))
    (if (and can-close? opener (< (inline-opener-end opener) p))
      (begin
        ;; A closer blocked by the link boundary is literal, not a new opener.
        ;; Reopening it can wrongly discard balanced destination parentheses.
        (if (and parser.destination?
                 (let (links (inline-openers parser inline-bracket-slot))
                   (and (pair? links)
                        (eq? (inline-opener-mode (car links)) 'destination)
                        (< (inline-opener-start opener) (inline-opener-start (car links))))))
          (emit-inline! parser p end default)
          (let* ((token (inline-token-at parser (inline-opener-index opener)))
                 (closer (emit-inline! parser p end 'close)))
            (inline-token-kind-set! token (delimiter-kind c))
            (inline-token-mate-set! token closer)
            (clear-inline-openers! parser (inline-opener-start opener))))
        end)
      (begin
        (if can-open?
          (add-inline-opener! parser (delimiter-opener-slot c marked?) start (+ p 1) default)
          (emit-inline! parser start end default))
        end))))

(def (normalize-reference-label (label : :string)) => :string
  (let loop ((p 0) (space? #f) (characters [])) => :string
    (if (= p (string-length label)) (list->string (reverse characters))
        (let (c (string-ref label p))
          (if (ascii-space? c) (loop (+ p 1) (pair? characters) characters)
              (loop (+ p 1) #f (cons c (if space? (cons #\space characters) characters))))))))

(def (inline-string-content (nodes : :list)) => :string
  (let (fragments [])
    (def (visit (nodes : :list)) => :void
      (for-each
        (lambda ((node : djot-node)) => :void
          (cond ((djot-footnote-reference? node)
                 (void))
                ((djot-textual? node)
                 (using (node :- djot-textual) (set! fragments (cons node.text fragments))))
                ((or (djot-soft-break? node) (djot-hard-break? node)) (set! fragments (cons "\n" fragments)))
                ((djot-container? node)
                 (using (node :- djot-container) (visit node.children)))))
        nodes))

    (visit nodes)
    (string-concatenate-reverse fragments)))

(def (scan-inline-attribute-end (parser : inline-parser)
                                (start  : :fixnum)
                                (attrs  : attribute-parser)) => :fixnum
  ;; Attribute grammar treats CRLF and LF identically: scan whitespace is ignored,
  ;; and quoted/escaped line endings collapse to one space. The grammar string
  ;; already removes block prefixes; source ranges still use the original slices.
  (feed-attributes! attrs parser.text start (inline-length parser)))

(def (trim-inline-hard-break! (parser : inline-parser)) => :void
  (when (> parser.count 0)
    (let (token (inline-token-at parser (- parser.count 1)))
      (when (eq? (inline-token-kind token) 'text)
        (let loop ((p (inline-token-end token))) => :void
          (if (and (> p (inline-token-start token)) (memv (inline-char parser (- p 1)) '(#\space #\tab)))
            (loop (- p 1))
            (inline-token-end-set! token p)))))))

(def (scan-inline-verbatim! (parser : inline-parser)
                            (start  : :fixnum)
                            (ticks  : :fixnum)
                            (kind   : :symbol)) => :fixnum
  (let* ((content (inline-run-end parser ticks #\`))
         (width (- content ticks))
         (i (emit-inline! parser start content kind))
         (token (inline-token-at parser i)))
    (inline-token-middle-set! token content)
    (let loop ((p content : :fixnum)) => :fixnum
      (cond
       ((= p (inline-length parser))
        (let (end (if (and (> p content) (char=? (inline-char parser (- p 1)) #\newline)) (- p 1) p))
          (inline-token-end-set! token end)
          (inline-token-mate-set! token end))
        p)
       ((char=? (inline-char parser p) #\`)
        (let (end (inline-run-end parser p #\`))
          (if (= (- end p) width)
            (begin
              (inline-token-end-set! token end)
              (inline-token-mate-set! token p)
              (if (and (eq? kind 'verbatim) (char=? (inline-char parser end) #\{)
                       (char=? (inline-char parser (+ end 1)) #\=))
                (let raw ((q (+ end 2) : :fixnum)) => :fixnum
                  (let (c (inline-char parser q))
                    (cond
                     ((and (> q (+ end 2)) (char=? c #\}))
                      (inline-token-kind-set! token 'raw)
                      (inline-token-value-set! token (inline-text parser (+ end 2) q))
                      (inline-token-end-set! token (+ q 1))
                      (fx+ q 1))
                     ((or (= q (inline-length parser)) (char-whitespace? c) (memv c '(#\{ #\} #\`))) end)
                     (else (raw (+ q 1)))))) end))
            (loop end))))
       (else (loop (+ p 1)))))))

(def (finish-inline-link! (parser     : inline-parser)
                          (opener     : inline-opener)
                          (end        : :fixnum)
                          (reference? : :boolean)) => :void
  (let* ((token (inline-token-at parser opener.index))
         (start opener.start)
         (i opener.index)
         (image? (and (> i 0) (char=? (inline-char parser (- start 1)) #\!)
                      (let (previous (inline-token-at parser (- i 1)))
                        (and (eq? (inline-token-kind previous) 'text)
                             (= (inline-token-start previous) (- start 1)))))))
    (when image?
      (inline-token-kind-set! (inline-token-at parser (- i 1)) 'ignore)
      (inline-token-start-set! token (- start 1)))
    (inline-token-kind-set! token (if image? 'image 'link))
    (inline-token-value-set! token (if reference? "reference" "destination"))
    (inline-token-middle-set! token opener.middle)
    (inline-token-mate-set! token (emit-inline! parser (- end 1) end 'close))
    (clear-inline-openers! parser start)
    ;; A reference inside a destination must not close the enclosing destination.
    (unless reference? (set! parser.destination? #f))))

(def (scan-inline-tokens! (parser                   : inline-parser)
                          (literal-attributes-until : :fixnum)) => :void
  (let* ((grammar parser.text)
         (size (string-length grammar))
         (cutoff
          ;; Failed block attributes may cover many lines. Walk the slice map in
          ;; order rather than binary-searching it for every replayed character.
          (let scan ((p 0 : :fixnum) (slot 0 : :fixnum)) => :fixnum
            (if (= p (inline-length parser)) p
                (let* ((starts parser.slice-starts)
                       (next-slot (fx+ slot 1)))
                  (if (and (fx< next-slot (vector-length starts))
                           (fx>= p (:- (vector-ref starts next-slot) :fixnum)))
                    (scan p next-slot)
                    (let* ((slice (:- (vector-ref parser.slices slot) source-slice))
                           (offset (if (char=? (inline-char parser p) #\newline) (source-slice-end slice)
                                       (fx+ (source-slice-start slice)
                                            (fx- p (:- (vector-ref starts slot) :fixnum))))))
                      (if (< offset literal-attributes-until) (scan (fx+ p 1) slot) p))))))))
    (let loop ((p 0) (no-attrs-before cutoff)) => :void
      (when (< p (inline-length parser))
        (let* ((c (string-ref parser.text p))
               (next (inline-char parser (+ p 1)))
               (end
                (cond
                 ((char=? c #\newline)
                  (emit-inline! parser p (+ p 1) 'soft-break)
                  (+ p 1))
                 ((char=? c #\`)
                  (scan-inline-verbatim! parser p p 'verbatim))
                 ((and (char=? c #\$)
                       (or (char=? next #\`)
                           (and (char=? next #\$)
                                (char=? (inline-char parser (+ p 2)) #\`))))
                  (scan-inline-verbatim! parser p (+ p (if (char=? next #\$) 2 1))
                                         (if (char=? next #\$) 'display-math 'inline-math)))
                 ((char=? c #\\)
                  (let skip ((q (+ p 1))) => :fixnum
                    (cond
                     ((and (< q (inline-length parser))
                           (memv (inline-char parser q) '(#\space #\tab)))
                      (skip (+ q 1)))
                     ((and (< q (inline-length parser))
                           (char=? (inline-char parser q) #\newline))
                      (trim-inline-hard-break! parser)
                      (emit-inline! parser p (+ q 1) 'hard-break)
                      (fx+ q 1))
                     ((ascii-punctuation? next)
                      (emit-inline! parser p (+ p 1) 'ignore)
                      (emit-inline! parser (+ p 1) (+ p 2) 'escaped-text)
                      (fx+ p 2))
                     ((char=? next #\space)
                      (emit-inline! parser p (+ p 2) 'nonbreaking-space)
                      (fx+ p 2))
                     (else
                      (emit-inline! parser p (+ p 1) 'text)
                      (fx+ p 1)))))
                 ((and (char=? c #\{) (inline-delimiter? next))
                  (match-inline-delimiter! parser p (+ p 1) #t))
                 ((and (char=? c #\{) (>= p no-attrs-before))
                  (let* ((attrs (new-attribute-parser))
                         (q (scan-inline-attribute-end parser p attrs)))
                    (if (eq? (attribute-parser-state attrs) 'done)
                      (begin
                        (inline-token-attributes-set!
                         (inline-token-at parser (emit-inline! parser p q 'attributes))
                         (attribute-parser-attributes attrs))
                        q)
                      (begin
                        (set! no-attrs-before q)
                        (emit-inline! parser p (+ p 1) 'text)
                        (+ p 1)))))
                 ((char=? c #\-)
                  (if (char=? next #\})
                    (match-inline-delimiter! parser p p #f)
                    (let* ((q (inline-run-end parser p #\-))
                           (q (if (char=? (inline-char parser q) #\}) (fx- q 1) q))
                           (n (- q p)))
                      (let dashes ((p p) (left n)) => :fixnum
                        (if (= left 0) q
                            (let* ((width (cond
                                           ((zero? (modulo n 3)) 3)
                                           ((zero? (modulo n 2)) 2)
                                           ((and (>= left 3) (or (odd? left) (> left 4))) 3)
                                           ((>= left 2) 2)
                                           (else 1)))
                                   (kind (case width
                                           ((3) 'em-dash)
                                           ((2) 'en-dash)
                                           (else 'text))))
                              (emit-inline! parser p (+ p width) kind)
                              (dashes (+ p width) (- left width))))))))
                 ((inline-delimiter? c)
                  (match-inline-delimiter! parser p p #f))
                 ((and (char=? c #\.) (char=? next #\.)
                       (char=? (inline-char parser (+ p 2)) #\.))
                  (emit-inline! parser p (+ p 3) 'ellipses)
                  (+ p 3))
                 ((char=? c #\:)
                  (let symbol ((q (+ p 1))) => :fixnum
                    (let (c (inline-char parser q))
                      (cond
                       ((or (char<=? #\a c #\z) (char<=? #\A c #\Z)
                            (char<=? #\0 c #\9) (memv c '(#\_ #\+ #\-)))
                        (symbol (+ q 1)))
                       ((and (> q (+ p 1)) (char=? c #\:))
                        (emit-inline! parser p (+ q 1) 'symbol)
                        (fx+ q 1))
                       (else
                        (emit-inline! parser p (+ p 1) 'text)
                        (fx+ p 1))))))
                 ((char=? c #\<)
                  (let auto ((q (+ p 1)) (email? #f) (url? #f)) => :fixnum
                    (let (c (inline-char parser q))
                      (cond
                       ((and (> q (+ p 1)) (char=? c #\>) (or email? url?))
                        (emit-inline! parser p (+ q 1) (if email? 'email 'url))
                        (fx+ q 1))
                       ((or (= q (inline-length parser))
                            (char-whitespace? c) (memv c '(#\< #\>)))
                        (emit-inline! parser p (+ p 1) 'text)
                        (fx+ p 1))
                       (else
                        (auto (+ q 1)
                              (or email?
                                  (and (> q (+ p 1)) (char=? c #\@)
                                       (not (char=? (inline-char parser (- q 1)) #\:))))
                              (or url?
                                  (and (char=? c #\:)
                                       (let (prev (inline-char parser (- q 1)))
                                         (or (char<=? #\a prev #\z)
                                             (char<=? #\A prev #\Z)))))))))))
                 ((char=? c #\[)
                  (add-inline-opener! parser inline-bracket-slot p (+ p 1) 'text)
                  (+ p 1))
                 ((char=? c #\])
                  (let* ((openers (inline-openers parser inline-bracket-slot))
                         (opener (and (pair? openers) (car openers))))
                    (cond
                     ((and opener
                           (fx> p (fx+ (inline-opener-start opener) 2))
                           (char=? (inline-char parser (+ (inline-opener-start opener) 1)) #\^))
                      (let (token (inline-token-at parser (inline-opener-index opener)))
                        (set! parser.count (+ (inline-opener-index opener) 1))
                        (inline-token-kind-set! token 'footnote)
                        (inline-token-end-set! token (+ p 1))
                        (clear-inline-openers! parser (inline-opener-start opener)))
                      (+ p 1))
                     ((and opener (eq? (inline-opener-mode opener) 'reference))
                      (finish-inline-link! parser opener (+ p 1) #t)
                      (+ p 1))
                     ((and opener (memv next '(#\[ #\()))
                      (clear-inline-openers! parser (+ (inline-opener-start opener) 1))
                      (inline-opener-mode-set! opener
                                               (if (char=? next #\[) 'reference 'destination))
                      (inline-opener-middle-set! opener parser.count)
                      (emit-inline! parser p (+ p 1) 'text)
                      (emit-inline! parser (+ p 1) (+ p 2) 'text)
                      (when (char=? next #\()
                        (vector-set! parser.openers inline-paren-slot [])
                        (set! parser.destination? #t))
                      (+ p 2))
                     ((and opener (char=? next #\{) (>= (+ p 1) no-attrs-before)
                           (not (inline-delimiter? (inline-char parser (+ p 2)))))
                      (let* ((attrs (new-attribute-parser))
                             (q (scan-inline-attribute-end parser (+ p 1) attrs)))
                        ;; Bracket closure blocks crossing openers even when the
                        ;; required attribute later recovers as literal text.
                        (clear-inline-openers! parser (inline-opener-start opener))
                        (if (eq? (attribute-parser-state attrs) 'done)
                          (let ((token (inline-token-at parser (inline-opener-index opener)))
                                (closer (emit-inline! parser p (+ p 1) 'close)))
                            (inline-token-kind-set! token 'span)
                            (inline-token-mate-set! token closer)
                            (clear-inline-openers! parser (inline-opener-start opener))
                            (inline-token-attributes-set!
                             (inline-token-at parser (emit-inline! parser (+ p 1) q 'attributes))
                             (attribute-parser-attributes attrs))
                            q)
                          (begin
                            (set! no-attrs-before q)
                            (emit-inline! parser p (+ p 1) 'text)
                            (+ p 1)))))
                     (else
                      (emit-inline! parser p (+ p 1) 'text)
                      (+ p 1)))))
                 ((and (char=? c #\() parser.destination?)
                  (add-inline-opener! parser inline-paren-slot p (+ p 1) 'text)
                  (+ p 1))
                 ((and (char=? c #\)) parser.destination?)
                  (let ((parens (inline-openers parser inline-paren-slot))
                        (links (inline-openers parser inline-bracket-slot)))
                    (cond
                     ((pair? parens)
                      (vector-set! parser.openers inline-paren-slot (cdr parens))
                      (emit-inline! parser p (+ p 1) 'text))
                     ((and (pair? links) (eq? (inline-opener-mode (car links)) 'destination))
                      (finish-inline-link! parser (car links) (+ p 1) #f))
                     (else
                      (emit-inline! parser p (+ p 1) 'text)))
                    (+ p 1)))
                 (else
                  (let text ((q (fx+ p 1) : :fixnum)) => :fixnum
                    ;; Grammar text is immutable during scanning. q advances
                    ;; to, but never past, its end; retain checked string access.
                    (if (or (fx= q size)
                            (inline-special? (string-ref grammar q)))
                      (begin
                        (emit-inline! parser p q 'text)
                        q)
                      (text (fx+ q 1))))))))
          (loop end no-attrs-before))))))

(def (inline-container (kind     : :symbol)
                       (source   :? djot-source-range)
                       (children : :list)) => djot-container
  (case kind
    ((emph) (make-djot-emph [] [] source children))
    ((strong) (make-djot-strong [] [] source children))
    ((subscript) (make-djot-subscript [] [] source children))
    ((superscript) (make-djot-superscript [] [] source children))
    ((insert) (make-djot-insert [] [] source children))
    ((delete) (make-djot-delete [] [] source children))
    ((mark) (make-djot-mark [] [] source children))
    ((single-quoted) (make-djot-single-quoted [] [] source children))
    ((double-quoted) (make-djot-double-quoted [] [] source children))
    (else (make-djot-span [] [] source children))))

(def (trim-verbatim (text : :string)) => :string
  (let* ((n (string-length text))
         (start (if (and (> n 1)
                         (char=? (string-ref text 0) #\space)
                         (char=? (string-ref text 1) #\`))
                  1 0))
         (end (if (and (> n 1)
                       (char=? (string-ref text (- n 1)) #\space)
                       (char=? (string-ref text (- n 2)) #\`))
                (- n 1) n)))
    (substring text start end)))

(def (inline-literal (parser : inline-parser)
                     (start  : :fixnum)
                     (end    : :fixnum)) => :string
  (let loop ((i start) (fragments [])) => :string
    (if (= i end) (:- (string-concatenate-reverse fragments) :string)
        (let (token (inline-token-at parser i))
          (loop (+ i 1) (if (eq? (inline-token-kind token) 'ignore) fragments
                            (cons (inline-text parser (inline-token-start token) (inline-token-end token)) fragments)))))))

(def (inline-destination (text : :string)) => :string
  (if (not (string-index text #\newline)) text
      (let loop ((p 0) (start 0) (fragments [])) => :string
        (if (or (= p (string-length text)) (char=? (string-ref text p) #\newline))
          (let* ((a (let trim ((q start : :fixnum)) => :fixnum
                      (if (and (< q p) (memv (string-ref text q) '(#\space #\tab))) (trim (+ q 1)) q)))
                 (b (let trim ((q p : :fixnum)) => :fixnum
                      (if (and (> q a) (memv (string-ref text (- q 1)) '(#\space #\tab))) (trim (- q 1)) q)))
                 (fragments (cons (substring text a b) fragments)))
            (if (= p (string-length text)) (:- (string-concatenate-reverse fragments) :string)
                (loop (+ p 1) (+ p 1) fragments)))
          (loop (+ p 1) start fragments)))))

(def (inline-atom (parser : inline-parser)
                  (token  : inline-token)) => djot-node
  (let* ((start token.start)
         (end token.end)
         (source (inline-range parser start end))
         (kind token.kind))
    (case kind
      ((text escaped-text) (make-djot-text [] [] source (inline-text parser start end)))
      ((soft-break) (make-djot-soft-break [] [] source))
      ((hard-break) (make-djot-hard-break [] [] source))
      ((nonbreaking-space) (make-djot-nonbreaking-space [] [] source))
      ((symbol) (make-djot-symbol [] [] source (inline-text parser (+ start 1) (- end 1))))
      ((footnote)
       (make-djot-footnote-reference [] [] source
                                     (normalize-reference-label (inline-text parser (+ start 2) (- end 1)))))
      ((url) (make-djot-url [] [] source (inline-text parser (+ start 1) (- end 1))))
      ((email) (make-djot-email [] [] source (inline-text parser (+ start 1) (- end 1))))
      ((verbatim raw inline-math display-math)
       (let (text (trim-verbatim (inline-text parser token.middle token.mate)))
         (case kind
           ((verbatim) (make-djot-verbatim [] [] source text))
           ((raw) (make-djot-raw-inline [] [] source text token.value))
           ((inline-math) (make-djot-inline-math [] [] source text))
           (else (make-djot-display-math [] [] source text)))))
      (else (make-djot-smart-punctuation [] [] source
                                         (case kind ((left-single-quote right-single-quote) "'")
                                               ((left-double-quote right-double-quote) "\"") ((ellipses) "...")
                                               ((en-dash) "--") (else "---")) kind)))))

;;; Attribute text targets only the last non-whitespace word, not the whole run.
(def (attach-inline-attributes (nodes      : :list)
                               (attributes : :list)) => :list
  (if (or (null? nodes) (null? attributes)) nodes
      (let (node (:- (car nodes) djot-node))
        (cond
         ((djot-text? node)
          (using (node :- djot-text)
            (let* ((text node.text)
                   (n (string-length text))
                   (start (let word ((p n : :fixnum)) => :fixnum
                            (if (and (> p 0) (not (ascii-space? (string-ref text (- p 1))))) (word (- p 1)) p))))
              (cond ((= start n) nodes)
                    ((= start 0)
                     (set! node.attributes (if (null? node.attributes) attributes
                                               (merge-attributes node.attributes attributes)))
                     nodes)
                    (else
                     (let* ((source node.source)
                            (split (and source (- (djot-source-range-end source) (- n start))))
                            (word-source (and source (make-djot-source-range split (djot-source-range-end source)
                                                                             (djot-source-range-end-line source)
                                                                             (- (djot-source-range-end-column source) (- n start))
                                                                             (djot-source-range-end-line source) (djot-source-range-end-column source))))
                            (word (make-djot-text attributes [] word-source (substring text start n))))
                       (set! node.text (substring text 0 start))
                       (when source
                         (set! node.source (make-djot-source-range (djot-source-range-start source) split
                                                                   (djot-source-range-start-line source) (djot-source-range-start-column source)
                                                                   (djot-source-range-end-line source) (- (djot-source-range-end-column source) (- n start)))))
                       (cons word nodes)))))))
         ((or (djot-soft-break? node) (djot-hard-break? node)) nodes)
         (else
          (djot-node-attributes-set! node
                                     (if (null? (djot-node-attributes node)) attributes
                                         (merge-attributes (djot-node-attributes node) attributes)))
          nodes)))))

(def (inline-nodes (parser : inline-parser)
                   (start  : :fixnum)
                   (end    : :fixnum)
                   (depth  : :fixnum)) => :list
  (when (> depth 512)
    (raise/context (DjotResourceError "Djot nesting limit exceeded"
                                      irritants: [depth: depth limit: 512])
                   where: inline-nodes))
  (let loop ((i start) (nodes [])) => :list
    (if (= i end) (reverse nodes)
        (let* ((token (inline-token-at parser i))
               (kind (inline-token-kind token))
               (mate (inline-token-mate token)))
          (cond
           ((eq? kind 'ignore) (loop (+ i 1) nodes))
           ((or (eq? kind 'text) (eq? kind 'escaped-text))
            ;; The ignored backslash remains a boundary before an escaped token;
            ;; following contiguous text belongs to its attribute target.
            (let text ((j (+ i 1)) (stop (inline-token-end token))) => :list
              (if (and (< j end) (eq? (inline-token-kind (inline-token-at parser j)) 'text)
                       (= stop (inline-token-start (inline-token-at parser j))))
                (text (+ j 1) (inline-token-end (inline-token-at parser j)))
                (loop j (cons (make-djot-text [] [] (inline-range parser (inline-token-start token) stop)
                                              (inline-text parser (inline-token-start token) stop))
                              nodes)))))
           ((eq? kind 'attributes)
            (let groups ((j i) (attrs [])) => :list
              (if (and (< j end) (eq? (inline-token-kind (inline-token-at parser j)) 'attributes))
                (groups (+ j 1) (cons (inline-token-attributes (inline-token-at parser j)) attrs))
                ;; Each token already contains unique, ordered attribute keys.
                ;; Most attachments have one group; avoid rebuilding its hash table.
                (loop j (attach-inline-attributes nodes
                                                  (if (null? (cdr attrs)) (car attrs)
                                                      (merge-attribute-groups (reverse attrs))))))))
           ((memq kind '(emph strong subscript superscript insert delete mark single-quoted double-quoted span link image))
            (let* ((link? (memq kind '(link image)))
                   (middle (inline-token-middle token))
                   (children (inline-nodes parser (+ i 1) (if link? middle mate) (+ depth 1)))
                   (source (inline-range parser
                                         (inline-token-start token)
                                         (inline-token-end (inline-token-at parser mate))))
                   (node
                    (if link?
                      (let* ((literal (inline-literal parser (+ middle 2) mate))
                             (reference? (string=? (inline-token-value token) "reference"))
                             (reference (and reference? (normalize-reference-label
                                                         (if (string=? literal "") (inline-string-content children) literal))))
                             (destination (and (not reference?) (inline-destination literal))))
                        (if (eq? kind 'image) (make-djot-image [] [] source children destination reference)
                            (make-djot-link [] [] source children destination reference)))
                      (inline-container kind source children))))
              (loop (+ mate 1) (cons node nodes))))
           (else (loop (+ i 1) (cons (inline-atom parser token) nodes))))))))

(def (parse-inlines (input      : :string)
                    (slices     : :list)
                    (locations? : :boolean)
                    literal-attributes-until: (literal-attributes-until : :fixnum := 0)) => :list
  (let (parser (new-inline-parser input slices locations?))
    (scan-inline-tokens! parser literal-attributes-until)
    (when (and (> (inline-parser-count parser) 0)
               (eq? (inline-token-kind (inline-token-at parser (- (inline-parser-count parser) 1))) 'soft-break))
      (inline-parser-count-set! parser (- (inline-parser-count parser) 1)))
    (inline-nodes parser 0 (inline-parser-count parser) 0)))
