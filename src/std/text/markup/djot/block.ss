;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Container continuation follows djot.js by John MacFarlane (MIT; testdata/LICENSE).
(import (only-in :std/error raise/context)
        (only-in :std/string/misc string-concatenate-reverse)
        ./ast
        ./inline
        ./attributes)
(export parse-blocks
        document-source)

(def (document-source (input : :string)) => djot-source-range
  (let loop ((index 0) (line 1) (column 1)) => djot-source-range
    (if (= index (string-length input))
      (make-djot-source-range 0 index 1 1 line column)
      (case (string-ref input index)
        ((#\return)
         (loop (if (and (< (+ index 1) (string-length input))
                        (char=? (string-ref input (+ index 1)) #\newline))
                 (+ index 2) (+ index 1)) (+ line 1) 1))
        ((#\newline) (loop (+ index 1) (+ line 1) 1))
        (else (loop (+ index 1) line (+ column 1)))))))

(def (skip-horizontal (input : :string)
                      (start : :fixnum)
                      (end   : :fixnum)) => :fixnum
  (let loop ((p start : :fixnum)) => :fixnum
    (if (and (< p end)
             (let (c (string-ref input p))
               (or (char=? c #\space) (char=? c #\tab))))
      (loop (+ p 1)) p)))

(def (trim-horizontal (input : :string)
                      (start : :fixnum)
                      (end   : :fixnum)) => :fixnum
  (let loop ((p end : :fixnum)) => :fixnum
    (if (and (> p start)
             (let (c (string-ref input (- p 1)))
               (or (char=? c #\space) (char=? c #\tab))))
      (loop (- p 1)) p)))

(def (character-run (input : :string)
                    (start : :fixnum)
                    (end   : :fixnum)
                    (c     : :char)) => :fixnum
  (let loop ((p start : :fixnum)) => :fixnum
    (if (and (< p end) (char=? (string-ref input p) c)) (loop (+ p 1)) p)))

(def (read-source-line (input : :string)
                       (start : :fixnum)
                       (line  : :fixnum)) => source-slice
  (let* ((size (string-length input))
         (end (let scan ((index start : :fixnum)) => :fixnum
                (if (= index size) index
                    (let (c (string-ref input index))
                      (if (or (char=? c #\newline) (char=? c #\return))
                        index (scan (+ index 1)))))))
         (next (cond ((= end size) end)
                     ((and (char=? (string-ref input end) #\return) (< (+ end 1) size)
                           (char=? (string-ref input (+ end 1)) #\newline)) (+ end 2))
                     (else (+ end 1)))))
    (make-source-slice start end line start next)))

(def (subslice (slice : source-slice)
               (start : :fixnum)
               (end   : :fixnum)) => source-slice
  (make-source-slice start end slice.line slice.line-start
                     slice.next))

(def (block-range (first : source-slice)
                  (last  : source-slice)) => djot-source-range
  (make-djot-source-range
   first.start last.next
   first.line (+ 1 (- first.start first.line-start))
   (if (> last.next last.end)
     (+ 1 last.line) last.line)
   (if (> last.next last.end)
     1 (+ 1 (- last.end last.line-start)))))

(defstruct block-token
  ((kind     : :symbol)
   (end      : :fixnum)
   (width    : :fixnum)
   (text     : :string)
   (styles   : :list)
   (checked? : :boolean)))

(def (no-token (p : :fixnum)) => block-token
  (make-block-token 'none p 0 "" [] #f))

(def (all-characters? (text      : :string)
                      (predicate : :procedure)) => :boolean
  (let loop ((p 0)) => :boolean
    (or (= p (string-length text))
        (and (predicate (string-ref text p)) (loop (+ p 1))))))

(def (roman-character? (c : :char)) => :boolean
  (and (memv c '(#\i #\v #\x #\l #\c #\d #\m #\I #\V #\X #\L #\C #\D #\M)) #t))

(def (list-styles (marker : :string)) => :list
  (let (size (string-length marker))
    (cond
     ((and (= size 1) (memv (string-ref marker 0) '(#\- #\+ #\* #\:))) [marker])
     ((< size 2) [])
     (else
      (let* ((parenthesized? (char=? (string-ref marker 0) #\())
             (last (string-ref marker (- size 1)))
             (prefix (if parenthesized? "(" ""))
             (suffix (string last))
             (number (substring marker (if parenthesized? 1 0) (- size 1))))
        (if (or (string=? number "")
                (not (if parenthesized? (char=? last #\)) (memv last '(#\. #\)))))) []
                (cond
                 ((all-characters? number (lambda ((c : :char)) => :boolean (char<=? #\0 c #\9)))
                  [(string-append prefix "1" suffix)])
                 ((and (all-characters? number roman-character?)
                       (or (all-characters? number char-lower-case?) (all-characters? number char-upper-case?)))
                  (let* ((lower? (char-lower-case? (string-ref number 0)))
                         (roman (string-append prefix (if lower? "i" "I") suffix)))
                    (if (= (string-length number) 1)
                      [roman (string-append prefix (if lower? "a" "A") suffix)] [roman])))
                 ((and (= (string-length number) 1)
                       (or (char<=? #\a (string-ref number 0) #\z)
                           (char<=? #\A (string-ref number 0) #\Z)))
                  [(string-append prefix (if (char-lower-case? (string-ref number 0)) "a" "A") suffix)])
                 (else []))))))))

(def (list-token (input : :string)
                 (p     : :fixnum)
                 (end   : :fixnum)) => block-token
  (let* ((stop (let scan ((i p : :fixnum)) => :fixnum
                 (if (or (= i end) (ascii-space? (string-ref input i))) i (scan (+ i 1)))))
         (marker (substring input p stop))
         (styles (list-styles marker)))
    (if (null? styles) (no-token p)
        (if (and (= (- stop p) 1) (memv (string-ref input p) '(#\- #\+ #\*))
                 (< (+ p 4) end) (char=? (string-ref input (+ p 1)) #\space)
                 (char=? (string-ref input (+ p 2)) #\[)
                 (memv (string-ref input (+ p 3)) '(#\space #\x #\X))
                 (char=? (string-ref input (+ p 4)) #\])
                 (or (= (+ p 5) end) (ascii-space? (string-ref input (+ p 5)))))
          (make-block-token 'item (+ p 5) 0 marker [(string-append marker "X")]
                            (not (char=? (string-ref input (+ p 3)) #\space)))
          (make-block-token 'item stop 0 marker styles #f)))))

(def (fence-token (input : :string)
                  (p     : :fixnum)
                  (end   : :fixnum)) => block-token
  ;; Ordinary lines cannot be fences; do not trim or copy their suffixes.
  (if (or (= p end) (not (memv (string-ref input p) '(#\` #\~ #\:)))) (no-token p)
      (let* ((c (string-ref input p))
             (stop (character-run input p end c))
             (width (- stop p))
             (info-start (skip-horizontal input stop end))
             (info-end (trim-horizontal input info-start end))
             (info (substring input info-start info-end)))
        (if (and (>= width 3)
                 (all-characters? info
                                  (lambda ((ch : :char)) => :boolean
                                    (if (char=? c #\:)
                                      (and (attribute-key-char? ch) (not (char=? ch #\:)))
                                      (not (or (ascii-space? ch) (char=? ch #\`)))))))
          (make-block-token (if (char=? c #\:) 'div 'code) stop width info [] #f)
          (no-token p)))))

(def (definition-token (input : :string)
       (p     : :fixnum)
       (end   : :fixnum)) => block-token
  (if (or (= p end) (not (char=? (string-ref input p) #\[))) (no-token p)
      (let (close (let scan ((i (+ p 1) : :fixnum)) => :fixnum
                    (if (or (= i end) (char=? (string-ref input i) #\])) i (scan (+ i 1)))))
        (if (and (< (+ close 1) end) (char=? (string-ref input (+ close 1)) #\:)
                 (or (= (+ close 2) end) (ascii-space? (string-ref input (+ close 2)))))
          (let* ((note? (and (< (+ p 2) close) (char=? (string-ref input (+ p 1)) #\^)))
                 (label (substring input (+ p (if note? 2 1)) close))
                 (value-start (skip-horizontal input (+ close 2) end))
                 (value-end (trim-horizontal input value-start end)))
            (if (or note? (all-characters? (substring input value-start value-end)
                                           (lambda ((c : :char)) => :boolean (not (ascii-space? c)))))
              (make-block-token (if note? 'footnote 'reference) value-start 0 label [] #f)
              (no-token p)))
          (no-token p)))))

(def (thematic? (input : :string)
                (p     : :fixnum)
                (end   : :fixnum)) => :boolean
  (let loop ((i p) (count 0)) => :boolean
    (cond ((= i end) (>= count 3))
          ((memv (string-ref input i) '(#\- #\*)) (loop (+ i 1) (+ count 1)))
          ((memv (string-ref input i) '(#\space #\tab)) (loop (+ i 1) count))
          (else #f))))

;;; Frames own unfinished leaves and reversed completed children. The root is never popped.
(defstruct block-frame
  ((kind                     : :symbol)
   (first                    : source-slice)
   (last                     : source-slice)
   (indent                   : :fixnum)
   (width                    : :fixnum)
   (text                     : :string)
   (styles                   : :list)
   (checked?                 : :boolean)
   (lines                    : :list)
   (children                 : :list)
   (attributes               : :list)
   (pending                  : :list)
   (tight?                   : :boolean)
   (blank?                   : :boolean)
   (alignments               : :list)
   (attribute-state          :? attribute-parser)
   (literal-attributes-until : :fixnum)))

(defstruct block-parser
  ((input      : :string)
   (locations? : :boolean)
   (frames     : :list)
   (depth      : :fixnum)
   (line       : source-slice)
   (position   : :fixnum)
   (finished?  : :boolean)))

(def (new-frame (kind   : :symbol)
                (slice  : source-slice)
                (indent : :fixnum)) => block-frame
  (make-block-frame kind slice slice indent 0 "" [] #f [] [] [] [] #t #f [] #f 0))

(def (tip (parser : block-parser)) => block-frame
  (:- (car parser.frames) block-frame))

(def (block-parent? (frame : block-frame)) => :boolean
  (and (memq frame.kind '(root quote div item footnote)) #t))

(def (inline-leaf? (frame : block-frame)) => :boolean
  (and (memq frame.kind '(paragraph heading caption)) #t))

;;; Parser lines come only from read-source-line; frames come only from
;;; new-frame. These private-state facts need not be rechecked per line/frame.
(def (skip-space! (parser : block-parser)) => :void
  (set! parser.position (skip-horizontal parser.input parser.position
                                         (source-slice-end (:- parser.line source-slice)))))

(def (current-slice (parser : block-parser)) => source-slice
  (using (slice parser.line :- source-slice)
    (subslice slice parser.position slice.end)))

(def (indentation (parser : block-parser)) => :fixnum
  (fx- parser.position (source-slice-line-start (:- parser.line source-slice))))

(def (touch-frames! (parser : block-parser)) => :void
  (let (slice (:- parser.line source-slice))
    (for-each (lambda ((frame :- block-frame)) => :void
                (set! frame.last slice))
              parser.frames)))

;;; A closing div fence belongs to the div, not to an implicitly closed leaf inside it.
(def (touch-through-frame! (parser : block-parser)
                           (target : block-frame)) => :void
  (let loop ((frames parser.frames) (inside? #t)) => :void
    (when (pair? frames)
      (let* ((frame (:- (car frames) block-frame))
             (inside? (and inside? (not (eq? frame target)))))
        (unless inside? (block-frame-last-set! frame (:- parser.line source-slice)))
        (loop (cdr frames) inside?)))))

(def (near-list (parser : block-parser)) => :list
  (let (frames parser.frames)
    (cond ((eq? (block-frame-kind (:- (car frames) block-frame)) 'list) frames)
          ((and (pair? (cdr frames)) (eq? (block-frame-kind (:- (cadr frames) block-frame)) 'list)) (cdr frames))
          (else []))))

(def (open-frame! (parser : block-parser)
                  (kind   : :symbol)) => block-frame
  (when (>= parser.depth 513)
    (raise/context (DjotResourceError "Djot block nesting exceeds 512"
                                      irritants: [depth: parser.depth limit: 512])
                   where: open-frame!))
  (let* ((parent (tip parser))
         (near (near-list parser))
         (frame (new-frame kind (current-slice parser) (indentation parser))))
    (when (and (pair? near) (not (eq? kind 'item)))
      (let (list-frame (:- (car near) block-frame))
        (when (and (block-frame-blank? list-frame) (not (eq? kind 'list)))
          (block-frame-tight?-set! list-frame #f))
        (block-frame-blank?-set! list-frame #f)))
    (unless (eq? kind 'attributes)
      (block-frame-attributes-set! frame (merge-attribute-groups (reverse (block-frame-pending parent))))
      (block-frame-pending-set! parent []))
    (set! parser.frames (cons frame parser.frames))
    (set! parser.depth (+ 1 parser.depth))
    frame))

(def (roman-value (c : :char)) => :fixnum
  (case (char-downcase c) ((#\i) 1) ((#\v) 5) ((#\x) 10) ((#\l) 50)
        ((#\c) 100) ((#\d) 500) ((#\m) 1000) (else 0)))

(def (list-start (marker : :string)
                 (style  : :string)) => :integer
  (let* ((offset (if (char=? (string-ref style 0) #\() 1 0))
         (kind (string-ref style offset))
         (number (substring marker offset (- (string-length marker) 1))))
    (case kind
      ((#\1) (:- (string->number number) :integer))
      ((#\a #\A) (fx+ 1 (fx- (char->integer (char-downcase (string-ref number 0))) (char->integer #\a))))
      (else
       (let loop ((p (- (string-length number) 1)) (next 0) (total 0 : :integer)) => :integer
         (if (< p 0) total
             (let (value (roman-value (string-ref number p)))
               (loop (- p 1) value (+ total (if (< value next) (- value) value))))))))))

(def (frame-node (parser : block-parser)
                 (frame  : block-frame)) => djot-node
  (let* ((kind frame.kind)
         (attrs frame.attributes)
         (source (and parser.locations?
                      (block-range frame.first frame.last)))
         (children (reverse frame.children))
         (inlines (if (inline-leaf? frame)
                    (parse-inlines parser.input (reverse frame.lines)
                                   parser.locations?
                                   literal-attributes-until: frame.literal-attributes-until) [])))
    (case kind
      ((paragraph) (make-djot-paragraph attrs [] source inlines))
      ((heading) (make-djot-heading attrs [] source inlines frame.width))
      ((caption) (make-djot-caption attrs [] source inlines))
      ((quote) (make-djot-block-quote attrs [] source children))
      ((div) (make-djot-div attrs [] source children))
      ((thematic) (make-djot-thematic-break attrs [] source))
      ((footnote) (make-djot-footnote attrs [] source children frame.text))
      ((reference) (make-djot-reference attrs [] source frame.text
                                        (string-concatenate-reverse frame.lines)))
      ((code)
       (let ((text (string-concatenate-reverse frame.lines))
             (info frame.text))
         (if (and (> (string-length info) 0) (char=? (string-ref info 0) #\=))
           (make-djot-raw-block attrs [] source text (substring info 1 (string-length info)))
           (make-djot-code-block attrs [] source text (and (not (string=? info "")) info)))))
      ((table) (make-djot-table attrs [] source (cons (make-djot-caption [] [] #f []) children)))
      ((list)
       (let (style (:- (car frame.styles) :string))
         (cond ((string=? style ":") (make-djot-definition-list attrs [] source children))
               ((char=? (string-ref style (- (string-length style) 1)) #\X)
                (make-djot-task-list attrs [] source children frame.tight?))
               ((= (string-length style) 1)
                (make-djot-bullet-list attrs [] source children frame.tight? style))
               (else (make-djot-ordered-list attrs [] source children frame.tight?
                                             style (list-start frame.text style))))))
      ((item)
       (let (style (:- (car frame.styles) :string))
         (cond
          ((string=? style ":")
           (let skip-definitions ((rest children) (hidden [])) => djot-definition-list-item
             (if (and (pair? rest) (or (djot-reference? (car rest)) (djot-footnote? (car rest))))
               (skip-definitions (cdr rest) (cons (car rest) hidden))
               (let* ((term? (and (pair? rest) (djot-paragraph? (car rest))))
                      (term (make-djot-term [] [] (and term? (djot-node-source (car rest)))
                                            (if term? (djot-container-children (car rest)) [])))
                      (definition (make-djot-definition [] [] source
                                                        (append (reverse hidden) (if term? (cdr rest) rest)))))
                 (make-djot-definition-list-item attrs [] source [term definition])))))
          ((char=? (string-ref style (- (string-length style) 1)) #\X)
           (make-djot-task-list-item attrs [] source children frame.checked?))
          (else (make-djot-list-item attrs [] source children)))))
      (else (error "Invalid Djot block frame" kind)))))

(def (close-frame! (parser : block-parser)) => :void
  (let (frame (tip parser))
    (set! parser.frames (cdr parser.frames))
    (set! parser.depth (- parser.depth 1))
    (let (parent (tip parser))
      (if (and (eq? (block-frame-kind frame) 'attributes)
               (eq? (attribute-parser-state (block-frame-attribute-state frame)) 'done))
        (block-frame-pending-set! parent
                                  (cons (attribute-parser-attributes (block-frame-attribute-state frame))
                                        (block-frame-pending parent)))
        (begin
          (when (eq? (block-frame-kind frame) 'attributes)
            (block-frame-kind-set! frame 'paragraph)
            (block-frame-attributes-set! frame (merge-attribute-groups (reverse (block-frame-pending parent))))
            (block-frame-pending-set! parent []))
          (let (node (frame-node parser frame))
            (if (and (djot-caption? node) (pair? (block-frame-children parent))
                     (djot-table? (car (block-frame-children parent))))
              (let* ((table (:- (car (block-frame-children parent)) djot-table))
                     (table-source (djot-node-source table))
                     (caption-source (djot-node-source node)))
                (djot-container-children-set! table (cons node (cdr (djot-container-children table))))
                (when (and table-source caption-source)
                  (djot-node-source-set! table
                                         (make-djot-source-range
                                          (djot-source-range-start table-source) (djot-source-range-end caption-source)
                                          (djot-source-range-start-line table-source) (djot-source-range-start-column table-source)
                                          (djot-source-range-end-line caption-source) (djot-source-range-end-column caption-source)))))
              (block-frame-children-set! parent (cons node (block-frame-children parent))))))))))

(def (close-to! (parser : block-parser)
                (depth  : :fixnum)) => :void
  (let loop () => :void
    (when (> parser.depth depth)
      (close-frame! parser)
      (loop))))

;;; Pipes inside escaped characters or equal-length backtick spans are not boundaries.
(def (table-slices (input : :string)
                   (slice : source-slice)
                   (p     : :fixnum)) => :list
  ;; Reject non-table prefixes before scanning potentially long trailing space.
  (let (end (if (and (< p slice.end) (char=? (string-ref input p) #\|))
              (trim-horizontal input p slice.end) p))
    (if (or (>= (+ p 1) end) (not (char=? (string-ref input p) #\|))
            (not (char=? (string-ref input (- end 1)) #\|))) []
            (let loop ((i (+ p 1)) (start (+ p 1)) (ticks 0) (cells [])) => :list
              (cond
               ((= i end) (if (= start end) (reverse cells) []))
               ((char=? (string-ref input i) #\`)
                (let* ((next (character-run input i end #\`))
                       (width (- next i)))
                  (loop next start (cond ((= ticks 0) width) ((= ticks width) 0) (else ticks)) cells)))
               ((and (= ticks 0) (char=? (string-ref input i) #\\) (< (+ i 1) end))
                (loop (+ i 2) start ticks cells))
               ((and (= ticks 0) (char=? (string-ref input i) #\|))
                (loop (+ i 1) (+ i 1) ticks (cons (subslice slice start i) cells)))
               (else (loop (+ i 1) start ticks cells)))))))

(def (separator-alignment (input : :string)
                          (slice : source-slice)) => :symbol
  (let* ((start slice.start)
         (end (trim-horizontal input start slice.end))
         (left? (and (< start end) (char=? (string-ref input start) #\:)))
         (p (if left? (+ start 1) start))
         (stop (character-run input p end #\-))
         (right? (and (< stop end) (char=? (string-ref input stop) #\:))))
    (if (and (> stop p) (= (if right? (+ stop 1) stop) end))
      (cond ((and left? right?) 'center) (left? 'left) (right? 'right) (else 'default))
      'none)))

(def (align-row! (row        : djot-row)
                 (alignments : :list)
                 (head?      : :boolean)) => :void
  (set! row.head? head?)
  (let loop ((cells row.children) (aligns alignments)) => :void
    (when (pair? cells)
      (djot-cell-head?-set! (car cells) head?)
      (djot-cell-alignment-set! (car cells) (if (pair? aligns) (car aligns) 'default))
      (loop (cdr cells) (if (pair? aligns) (cdr aligns) [])))))

(def (add-table-row! (parser : block-parser)
                     (frame  : block-frame)
                     (slices : :pair)) => :void
  (let* ((input parser.input)
         ;; Only the first separator cell must begin immediately after its pipe.
         (alignments
          (cons (separator-alignment input (car slices))
                (map (lambda ((s : source-slice)) => :symbol
                       (separator-alignment input
                                            (subslice s (skip-horizontal input s.start s.end)
                                                      s.end)))
                     (cdr slices)))))
    (if (not (memq 'none alignments))
      (begin
        (set! frame.alignments alignments)
        (when (pair? frame.children)
          (align-row! (car frame.children) alignments #t)))
      (let* ((cells (map (lambda ((s : source-slice)) => djot-cell
                           (let* ((start (skip-horizontal input s.start s.end))
                                  (content (subslice s start s.end)))
                             (make-djot-cell [] [] (and parser.locations? (slice-source s))
                                             (if (= start s.end) []
                                                 (parse-inlines input [content] parser.locations?))
                                             #f 'default)))
                         slices))
             (row (make-djot-row [] []
                                 (and parser.locations?
                                      (block-range (current-slice parser) parser.line))
                                 cells #f)))
        (align-row! row frame.alignments #f)
        (set! frame.children (cons row frame.children)))))
  (touch-frames! parser)
  (set! parser.finished? #t))

(def (fence-closes? (parser : block-parser)
                    (frame  : block-frame)) => :boolean
  (let* ((input parser.input)
         (p parser.position)
         (end (source-slice-end (:- parser.line source-slice)))
         (c (string-ref input (source-slice-start (:- frame.first source-slice))))
         (stop (character-run input p end c)))
    (and (>= (- stop p) frame.width) (= (skip-horizontal input stop end) end))))

(def (recover-attributes! (parser : block-parser)
                          (frame  : block-frame)) => :void
  (let (parent (:- (cadr parser.frames) block-frame))
    (set! frame.kind 'paragraph)
    (set! frame.attributes (merge-attribute-groups (reverse (block-frame-pending parent))))
    (block-frame-pending-set! parent [])))

(def (continue-frame? (parser : block-parser)
                      (frame  : block-frame)) => :boolean
  (let* ((input parser.input)
         (p parser.position)
         (end (source-slice-end (:- parser.line source-slice)))
         (blank? (= p end)))
    (case frame.kind
      ((root) #t)
      ((quote)
       (and (< p end) (char=? (string-ref input p) #\>)
            (or (= (+ p 1) end) (ascii-space? (string-ref input (+ p 1))))
            (begin
              (touch-through-frame! parser frame)
              (set! parser.position (+ p 1))
              #t)))
      ((paragraph caption) (not blank?))
      ((heading)
       (let (stop (character-run input p end #\#))
         (and (= (- stop p) frame.width)
              (or (= stop end) (ascii-space? (string-ref input stop)))
              (begin
                (touch-through-frame! parser frame)
                (set! parser.position stop)
                #t))))
      ((item footnote) (or blank? (> (indentation parser) frame.indent)))
      ((list)
       (or blank? (> (indentation parser) frame.indent)
           (let* ((token (list-token input p end))
                  (styles (filter (lambda ((style : :string)) => :boolean
                                    (and (member style (block-token-styles token)) #t))
                                  frame.styles)))
             (and (pair? styles)
                  (begin
                    (set! frame.styles styles)
                    #t)))))
      ((div)
       (if (and (not (eq? (block-frame-kind (tip parser)) 'code)) (fence-closes? parser frame))
         (begin
           (touch-through-frame! parser frame)
           (set! parser.finished? #t)
           #f)
         #t))
      ((code)
       (if (fence-closes? parser frame)
         (begin
           (touch-frames! parser)
           (set! parser.finished? #t)
           #f)
         #t))
      ((table)
       (let (slices (table-slices input parser.line p))
         (and (pair? slices)
              (begin
                (add-table-row! parser frame slices)
                #t))))
      ((reference)
       (let (value-end (trim-horizontal input p end))
         (and (> (indentation parser) frame.indent) (not blank?)
              (all-characters? (substring input p value-end)
                               (lambda ((c : :char)) => :boolean
                                 (not (ascii-space? c))))
              (begin
                (set! frame.lines (cons (substring input p value-end) frame.lines))
                (touch-frames! parser)
                (set! parser.finished? #t)
                #t))))
      ((attributes)
       (let (attributes (:- frame.attribute-state attribute-parser))
         (cond
          ((eq? (attribute-parser-state attributes) 'done) #f)
          ((> (indentation parser) frame.indent)
           (let (stop (feed-attributes! attributes input p end))
             (set! frame.literal-attributes-until stop)
             (set! frame.lines (cons (current-slice parser) frame.lines))
             (when (or (eq? (attribute-parser-state attributes) 'fail)
                       (and (eq? (attribute-parser-state attributes) 'done)
                            (< (skip-horizontal input stop end) end)))
               (recover-attributes! parser frame))
             (unless (memq (attribute-parser-state attributes) '(done fail))
               (feed-attributes! attributes "\n" 0 1))
             (touch-frames! parser)
             (set! parser.finished? #t)
             #t))
          (else
           (recover-attributes! parser frame)
           (not blank?)))))
      (else #f))))

(def (classify-block (parser : block-parser)
                     (parent : block-frame)) => block-token
  (let* ((input parser.input)
         (p parser.position)
         (end (source-slice-end (:- parser.line source-slice))))
    (cond
     ((= p end) (no-token p))
     ((eq? parent.kind 'list) (list-token input p end))
     ((and (char=? (string-ref input p) #\>)
           (or (= (+ p 1) end) (ascii-space? (string-ref input (+ p 1)))))
      (make-block-token 'quote (+ p 1) 0 "" [] #f))
     ((char=? (string-ref input p) #\#)
      (let (stop (character-run input p end #\#))
        (if (or (= stop end) (ascii-space? (string-ref input stop)))
          (make-block-token 'heading stop (- stop p) "" [] #f) (no-token p))))
     ((and (char=? (string-ref input p) #\^) (< (+ p 1) end)
           (ascii-space? (string-ref input (+ p 1)))
           (pair? parent.children) (djot-table? (car parent.children)))
      (make-block-token 'caption (+ p 1) 0 "" [] #f))
     ((char=? (string-ref input p) #\[) (definition-token input p end))
     ((thematic? input p end) (make-block-token 'thematic end 0 "" [] #f))
     (else
      (let ((list (list-token input p end))
            (fence (fence-token input p end)))
        (cond ((eq? (block-token-kind list) 'item) list)
              ((pair? (table-slices input parser.line p)) (make-block-token 'table p 0 "" [] #f))
              ((char=? (string-ref input p) #\{) (make-block-token 'attributes p 0 "" [] #f))
              (else fence)))))))

(def (open-token! (parser : block-parser)
                  (token  : block-token)) => :boolean
  (let* ((kind token.kind)
         (input parser.input)
         (p parser.position)
         (end (source-slice-end (:- parser.line source-slice))))
    (cond
     ((eq? kind 'none) #f)
     ((eq? kind 'attributes)
      (let* ((attributes (new-attribute-parser))
             (stop (feed-attributes! attributes input p end)))
        (if (or (eq? (attribute-parser-state attributes) 'fail)
                (and (eq? (attribute-parser-state attributes) 'done) (< (skip-horizontal input stop end) end))) #f
                (let (frame (open-frame! parser 'attributes))
                  (block-frame-attribute-state-set! frame attributes)
                  ;; A failed block attribute cannot restart as an inline attribute over
                  ;; the same prefix, particularly across an unindented continuation.
                  (block-frame-literal-attributes-until-set! frame stop)
                  (block-frame-lines-set! frame [(current-slice parser)])
                  (unless (eq? (attribute-parser-state attributes) 'done)
                    (feed-attributes! attributes "\n" 0 1))
                  (touch-frames! parser)
                  (set! parser.finished? #t)
                  #t))))
     (else
      (when (and (eq? kind 'item) (not (eq? (block-frame-kind (tip parser)) 'list)))
        (let (list (open-frame! parser 'list))
          (block-frame-styles-set! list token.styles)
          (block-frame-text-set! list token.text)))
      (let (frame (open-frame! parser kind))
        (block-frame-width-set! frame token.width)
        (block-frame-text-set! frame token.text)
        (block-frame-styles-set! frame token.styles)
        (block-frame-checked?-set! frame token.checked?)
        (when (and (eq? kind 'div) (not (string=? token.text "")))
          (block-frame-attributes-set! frame
                                       (merge-attributes (block-frame-attributes frame) [(make-djot-attribute "class" token.text)])))
        (set! parser.position token.end)
        (case kind
          ((code div thematic)
           (touch-frames! parser)
           (set! parser.finished? #t))
          ((reference)
           (block-frame-lines-set! frame
                                   [(substring input token.end (trim-horizontal input token.end end))])
           (touch-frames! parser)
           (set! parser.finished? #t))
          ((table) (add-table-row! parser frame (table-slices input parser.line p))))
        #t)))))

(def (feed-content! (parser     : block-parser)
                    (new-start? : :boolean)) => :void
  (skip-space! parser)
  (let* ((input parser.input)
         (p parser.position)
         (slice (:- parser.line source-slice))
         (end (source-slice-end slice))
         (blank? (= p end)))
    (when (and (block-parent? (tip parser)) (not blank?)) (open-frame! parser 'paragraph))
    (let (frame (tip parser))
      (cond
       ((eq? (block-frame-kind frame) 'code)
        (let (start (max (source-slice-line-start slice)
                         (- p (max 0 (- (indentation parser) (block-frame-indent frame))))))
          (block-frame-lines-set! frame
                                  (cons (if (= end (source-slice-next slice))
                                          (string-append (substring input start end) "\n")
                                          (substring input start (source-slice-next slice)))
                                        (block-frame-lines frame)))
          (touch-frames! parser)))
       ((and (inline-leaf? frame) (not blank?))
        (block-frame-lines-set! frame (cons (current-slice parser) (block-frame-lines frame)))
        (touch-frames! parser))
       ((and blank? (not new-start?))
        (block-frame-pending-set! frame [])
        (let (near (near-list parser))
          (when (and (pair? near)
                     (or (pair? (block-frame-children frame))
                         (pair? (block-frame-children (car near)))))
            (block-frame-blank?-set! (car near) #t))))))))

(def (parse-blocks (input      : :string)
                   (locations? : :boolean)) => :list
  (let* ((initial (make-source-slice 0 0 1 0 0))
         (root (new-frame 'root initial 0))
         (parser (make-block-parser input locations? [root] 1 initial 0 #f)))
    (let lines ((offset 0) (number 1)) => :list
      (if (= offset (string-length input))
        (begin
          (close-to! parser 1)
          (reverse (block-frame-children root)))
        (let (slice (read-source-line input offset number))
          (block-parser-line-set! parser slice)
          (block-parser-position-set! parser offset)
          (block-parser-finished?-set! parser #f)
          (let (matched
                (let continue ((frames (reverse (block-parser-frames parser))) (count 0 : :fixnum)) => :fixnum
                  (if (null? frames) count
                      (begin
                        (skip-space! parser)
                        (if (continue-frame? parser (:- (car frames) block-frame))
                          (continue (cdr frames) (+ count 1)) count)))))
            (when (and (< matched (block-parser-depth parser)) (not (inline-leaf? (tip parser))))
              (close-to! parser matched))
            (if (block-parser-finished? parser)
              (close-to! parser matched)
              (let start ((matched matched) (new-start? #f)) => :void
                (skip-space! parser)
                (let* ((parent (:- (list-ref (block-parser-frames parser)
                                             (- (block-parser-depth parser) matched))
                                   block-frame))
                       (token (if (or (block-parent? parent) (eq? (block-frame-kind parent) 'list))
                                (classify-block parser parent) (no-token (block-parser-position parser)))))
                  (if (not (eq? (block-token-kind token) 'none))
                    (begin
                      (close-to! parser matched)
                      (if (open-token! parser token)
                        (unless (block-parser-finished? parser) (start (block-parser-depth parser) #t))
                        (feed-content! parser new-start?)))
                    (begin
                      (unless (and (< (block-parser-position parser) (source-slice-end slice))
                                   (not new-start?) (< matched (block-parser-depth parser))
                                   (inline-leaf? (tip parser)))
                        (close-to! parser matched))
                      (feed-content! parser new-start?)))))))
          (lines (source-slice-next slice) (+ number 1)))))))
