;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import (only-in :gerbil/core/runtime char-set:punctuation char-set-contains?)
        (only-in :std/error raise/context)
        ./ast
        ./block
        (only-in ./inline normalize-reference-label inline-string-content))
(export string->djot)

;;; Check combined block/inline nesting before recursive document finalization.
;;; Text and other atomic nodes do not introduce another open container.
(def (check-document-nesting! (nodes : :list)
                              (depth : :fixnum)) => :void
  (for-each
    (lambda ((node : djot-node)) => :void
      (when (djot-container? node)
        (using (node :- djot-container)
          (when (>= depth 512)
            (raise/context (DjotResourceError "Djot nesting limit exceeded"
                                              irritants: [depth: (fx+ depth 1) limit: 512])
                           where: check-document-nesting!))
          (check-document-nesting! node.children (+ depth 1)))))
    nodes))

;;; Index definitions while collecting their ordered public alists. Definitions never
;;; remain in visible children, including definitions nested in quotes or lists.
(def (collect-definitions! (document : djot-document)) => :void
  (let ((references (make-hash-table))
        (footnotes (make-hash-table))
        (reference-entries [])
        (footnote-entries []))
    (def (collect (nodes : :list)) => :list
      (let loop ((rest nodes) (result [])) => :list
        (if (null? rest) (reverse result)
            (let (node (:- (car rest) djot-node))
              (when (djot-container? node)
                (using (node :- djot-container)
                  (set! node.children (collect node.children))))
              (cond
               ((djot-reference? node)
                (using (node :- djot-reference)
                  (unless (string=? node.label "")
                    (let* ((label (normalize-reference-label node.label))
                           (entry (hash-get references label)))
                      (set! node.label label)
                      (if entry (set-cdr! entry node)
                          (let (entry (cons label node))
                            (hash-put! references label entry)
                            (set! reference-entries (cons entry reference-entries))))))
                  (loop (cdr rest) result)))
               ((djot-footnote? node)
                (using (node :- djot-footnote)
                  (let* ((label (normalize-reference-label node.label))
                         (entry (hash-get footnotes label)))
                    (set! node.label label)
                    (if entry (set-cdr! entry node)
                        (let (entry (cons label node))
                          (hash-put! footnotes label entry)
                          (set! footnote-entries (cons entry footnote-entries)))))
                  (loop (cdr rest) result)))
               (else (loop (cdr rest) (cons node result))))))))
    (set! document.children (collect document.children))
    (set! document.references (reverse reference-entries))
    (set! document.footnotes (reverse footnote-entries))))

;;; Djot prose removes punctuation rather than replacing it with separators.
;;; Gambit's Unicode punctuation set preserves letters and combining marks.
(def (heading-identifier-base (text : :string)) => :string
  (let ((port (open-output-string))
        (separator? #f)
        (written? #f))
    (string-for-each
     (lambda ((char : :char)) => :void
       (let (code (char->integer char))
         (cond
          ((char-whitespace? char) (when written? (set! separator? #t)))
          ((and (not (memv char '(#\_ #\-)))
                (or (char-set-contains? char-set:punctuation char)
                    (<= 33 code 47) (<= 58 code 64) (<= 91 code 96) (<= 123 code 126)))
           (void))
          (else
           (when separator?
             (write-char #\- port)
             (set! separator? #f))
           (write-char char port)
           (set! written? #t)))))
     text)
    (get-output-string port)))

(def (node-identifier (node : djot-node)) => (Maybe :string)
  (let loop ((attributes node.attributes)) => (Maybe :string)
    (and (pair? attributes)
         (let (attribute (:- (car attributes) djot-attribute))
           (if (string=? (djot-attribute-name attribute) "id")
             (djot-attribute-value attribute) (loop (cdr attributes)))))))

(def (finalize-headings! (document : djot-document)) => :void
  (let ((identifiers (make-hash-table))
        (suffixes (make-hash-table))
        (references (make-hash-table))
        (automatic []))
    (for-each
      (lambda ((entry : :pair)) => :void
        (hash-put! references (car entry) #t))
      document.references)

    (def (unique-identifier (text : :string)) => :string
      (let* ((base (heading-identifier-base text))
             (prefix (if (string=? base "") "s" base)))
        (if (and (not (string=? base "")) (not (hash-get identifiers base))) base
            (let loop ((suffix (or (hash-get suffixes prefix) 1))) => :string
              (let (candidate (string-append prefix "-" (number->string suffix)))
                (if (hash-get identifiers candidate) (loop (+ suffix 1))
                    (begin
                      (hash-put! suffixes prefix (+ suffix 1))
                      candidate)))))))

    (def (visit (node : djot-node)) => :void
      (let (identifier (node-identifier node))
        (when identifier (hash-put! identifiers identifier #t)))
      (when (djot-container? node)
        (using (node :- djot-container) (for-each visit node.children)))
      (when (djot-heading? node)
        (using (node :- djot-heading)
          (let* ((text (inline-string-content node.children))
                 (explicit (node-identifier node))
                 (identifier (if (and explicit (not (string=? explicit "")))
                               explicit
                               (unique-identifier text)))
                 (label (normalize-reference-label text)))
            (unless (and explicit (not (string=? explicit "")))
              (set! node.auto-attributes [(make-djot-attribute "id" identifier)]))
            (hash-put! identifiers identifier #t)
            (unless (hash-get references label)
              (hash-put! references label #t)
              (set! automatic
                (cons (cons label
                            (make-djot-reference [] [] #f label (string-append "#" identifier)))
                      automatic)))))))

    (for-each visit document.children)
    (for-each
      (lambda ((entry : :pair)) => :void (visit (cdr entry)))
      document.footnotes)
    (set! document.auto-references (reverse automatic))))

(defstruct section-frame
  ((node     : djot-section)
   (level    : :fixnum)
   (reversed : :list)))

;;; Sections exist only at document level, not inside quotes, divs, lists or notes.
(def (sectionize! (document : djot-document)) => :void
  (let ((stack []) (result []))
    (def (add! (node : djot-node)) => :void
      (if (null? stack) (set! result (cons node result))
          (using (frame (car stack) :- section-frame)
            (set! frame.reversed (cons node frame.reversed)))))

    (def (close!) => :void
      (using (frame (car stack) :- section-frame)
        (using (section frame.node :- djot-section)
          (let* ((reversed frame.reversed)
                 (start section.source)
                 (end (and (pair? reversed) (djot-node-source (car reversed)))))
            (set! section.children (reverse reversed))
            (when (and start end)
              (set! section.source
                (make-djot-source-range (djot-source-range-start start) (djot-source-range-end end)
                                        (djot-source-range-start-line start) (djot-source-range-start-column start)
                                        (djot-source-range-end-line end) (djot-source-range-end-column end))))
            (set! stack (cdr stack))
            (add! section)))))

    (for-each
      (lambda ((node : djot-node)) => :void
        (when (djot-heading? node)
          (using (node :- djot-heading)
            (let (level node.level)
              (let close-sections () => :void
                (when (and (pair? stack) (>= (section-frame-level (car stack)) level))
                  (close!)
                  (close-sections)))
              (let* ((identifier (node-identifier node))
                     (explicit? (and identifier (not (string=? identifier ""))))
                     (section (make-djot-section
                               (if explicit? node.attributes [])
                               node.auto-attributes node.source [])))
                (when explicit? (set! node.attributes []))
                (set! node.auto-attributes [])
                (set! stack (cons (make-section-frame section level []) stack))))))
        (add! node))
      document.children)
    (let close-sections () => :void
      (unless (null? stack)
        (close!)
        (close-sections)))
    (set! document.children (reverse result))))

(def (string->djot (input : :string)
                   source-locations: (locations? : :boolean := #f))
  => djot-document
  (let (document (make-djot-document [] [] (and locations? (document-source input))
                                     (parse-blocks input locations?) [] [] []))
    (check-document-nesting! (djot-container-children document) 0)
    (collect-definitions! document)
    (finalize-headings! document)
    (sectionize! document)
    (check-document-nesting! (djot-container-children document) 0)
    document))
