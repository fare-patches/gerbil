;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Attribute grammar follows djot.js by John MacFarlane (MIT; testdata/LICENSE).
(import (only-in :std/string/misc string-concatenate-reverse)
        ./ast)
(export (struct-out attribute-parser)
        new-attribute-parser
        feed-attributes!
        attribute-parser-attributes
        merge-attributes
        merge-attribute-groups
        attribute-key-char?
        ascii-space?)

(def (ascii-space? (c : :char)) => :boolean
  (or (char=? c #\space) (char=? c #\tab)
      (char=? c #\newline) (char=? c #\return)))

(def (attribute-key-char? (c : :char)) => :boolean
  (or (char<=? #\a c #\z) (char<=? #\A c #\Z) (char<=? #\0 c #\9)
      (and (memv c '(#\_ #\: #\-)) #t)))

;;; Values are accumulated as fragments: repeated classes never copy their prefix.
(defstruct attribute-entry ((name : :string) (values : :list)))

;;; Pending key/id/bare values hold characters; quoted values also hold string chunks.
(defstruct attribute-parser
  ((state      : :symbol)
   (key        : :string)
   (fragments  : :list)
   (entries    : :list)
   (index      :? HashTable)))

(def (new-attribute-parser) => attribute-parser
  (make-attribute-parser 'start "" [] [] #f))

;;; Most groups have one key. Scan at most eight entries before promoting to a
;;; hash index, retaining bounded work even for adversarial large groups.
(def (find-attribute-entry (parser : attribute-parser)
                           (name   : :string)) => (Maybe attribute-entry)
  (let (index parser.index)
    (if index (hash-get index name)
        (let loop ((entries parser.entries)) => (Maybe attribute-entry)
          (and (pair? entries)
               (let (entry (:- (car entries) attribute-entry))
                 (if (string=? name (attribute-entry-name entry)) entry
                     (loop (cdr entries)))))))))

(def (add-attribute! (parser : attribute-parser)
                     (name   : :string)
                     (value  : :string)) => :void
  (let (old (find-attribute-entry parser name))
    (if old
      (attribute-entry-values-set! old
                                   (if (and (string=? name "class") (pair? (attribute-entry-values old)))
                                     (cons value (cons " " (attribute-entry-values old)))
                                     (if (string=? value "") [] [value])))
      (let* ((entry (make-attribute-entry name (if (string=? value "") [] [value])))
             (entries (cons entry parser.entries))
             (index parser.index))
        (set! parser.entries entries)
        (cond
         (index (hash-put! index name entry))
         ((fx> (length entries) 8)
          (let (index (make-hash-table))
            (for-each
              (lambda ((value : :t)) => :void
                (let (value (:- value attribute-entry))
                  (hash-put! index (attribute-entry-name value) value)))
              entries)
            (set! parser.index index))))))))

(def (reset-attribute! (parser : attribute-parser)
                       (name   : :string)) => :void
  (let (entry (find-attribute-entry parser name))
    (if entry
      (attribute-entry-values-set! entry [])
      (add-attribute! parser name ""))))

(def (attribute-parser-attributes (parser : attribute-parser)) => :list
  (map (lambda ((entry : attribute-entry)) => djot-attribute
         (make-djot-attribute entry.name
                              (string-concatenate-reverse entry.values)))
       (reverse parser.entries)))

;;; Preserve first-key order, combine classes, and let the last other value win.
(def (merge-attribute-groups (groups : :list)) => :list
  (if (null? groups) []
      (let (parser (new-attribute-parser))
        (for-each
          (lambda ((group : :list)) => :void
            (for-each
              (lambda ((a : djot-attribute)) => :void
                (add-attribute! parser
                                a.name
                                a.value))
              group))
          groups)
        (attribute-parser-attributes parser))))

(def (merge-attributes (left  : :list)
                       (right : :list)) => :list
  (merge-attribute-groups [left right]))

(def (finish-attribute! (parser : attribute-parser)) => :void
  (unless (and (memq parser.state '(id class))
               (null? parser.fragments))
    (let (fragments parser.fragments)
      (add-attribute! parser parser.key
                      (if (eq? parser.state 'quoted)
                        (string-concatenate-reverse
                         (map (lambda ((fragment : :t)) => :string
                                (if (char? fragment) (string fragment) (:- fragment :string)))
                              fragments))
                        (list->string (reverse fragments))))))
  (set! parser.fragments [])
  (set! parser.state 'scan))

(def (attribute-value-character! (parser : attribute-parser)
                                 (c      : :char)) => :void
  (let ((normalized (if (memv c '(#\return #\newline)) #\space c))
        (fragments parser.fragments))
    (unless (and (char=? normalized #\space)
                 (pair? fragments)
                 (eqv? (car fragments) #\space))
      (set! parser.fragments (cons normalized fragments)))))

(def (attribute-escape? (c : :char)) => :boolean
  (and (memv c '(#\. #\, #\\ #\/ #\# #\! #\$ #\% #\^ #\& #\* #\; #\: #\{ #\}
                 #\= #\- #\_ #\` #\~ #\+ #\[ #\] #\( #\) #\' #\" #\? #\|)) #t))

;;; Feed original-input characters, returning the first unconsumed offset.
;;; The state is done, fail, or an unfinished grammar state; no rescanning on continuation.
(def (feed-attributes! (parser : attribute-parser)
                       (input  : :string)
                       (start  : :fixnum)
                       (end    : :fixnum)) => :fixnum
  (let loop ((p start : :fixnum)) => :fixnum
    (if (or (= p end) (memq parser.state '(done fail))) p
        (let ((c (string-ref input p))
              (state parser.state))
          (case state
            ((start) (set! parser.state (if (char=? c #\{) 'scan 'fail)))
            ((scan)
             (cond
              ((ascii-space? c) (void))
              ((char=? c #\}) (set! parser.state 'done))
              ((char=? c #\%) (set! parser.state 'comment))
              ((memv c '(#\# #\.))
               (set! parser.key (if (char=? c #\#) "id" "class"))
               (set! parser.state (if (char=? c #\#) 'id 'class)))
              ((attribute-key-char? c)
               (set! parser.fragments [c])
               (set! parser.state 'key))
              (else (set! parser.state 'fail))))
            ((comment)
             (cond ((char=? c #\%) (set! parser.state 'scan))
                   ((char=? c #\}) (set! parser.state 'done))))
            ((id class bare)
             (cond
              ((or (ascii-space? c) (char=? c #\}))
               (finish-attribute! parser)
               (when (char=? c #\}) (set! parser.state 'done)))
              ((if (eq? state 'id)
                 (not (or (char-whitespace? c)
                          (memv c '(#\] #\[ #\~ #\! #\@ #\# #\$ #\% #\^ #\& #\* #\( #\)
                                    #\{ #\} #\` #\, #\. #\< #\> #\\ #\| #\= #\+ #\/ #\?))))
                 (attribute-key-char? c))
               (set! parser.fragments (cons c parser.fragments)))
              (else (set! parser.state 'fail))))
            ((key)
             (cond
              ((char=? c #\=)
               (set! parser.key (list->string (reverse parser.fragments)))
               (reset-attribute! parser parser.key)
               (set! parser.fragments [])
               (set! parser.state 'value))
              ((attribute-key-char? c)
               (set! parser.fragments (cons c parser.fragments)))
              (else (set! parser.state 'fail))))
            ((value)
             (cond ((char=? c #\") (set! parser.state 'quoted))
                   ((attribute-key-char? c)
                    (set! parser.fragments [c])
                    (set! parser.state 'bare))
                   (else (set! parser.state 'fail))))
            ((quoted)
             (cond ((char=? c #\") (finish-attribute! parser))
                   ((char=? c #\\) (set! parser.state 'escaped))
                   ((or (char=? c #\space) (char=? c #\newline) (char=? c #\return))
                    (attribute-value-character! parser c))
                   (else
                    ;; Preserve normalization at whitespace/escape boundaries, but
                    ;; retain ordinary quoted text as a chunk, not a pair per char.
                    (let scan ((q (fx+ p 1) : :fixnum)) => :void
                      (if (or (fx= q end)
                              (case (string-ref input q)
                                ((#\" #\\ #\newline #\return) #t)
                                ((#\space)
                                 ;; Internal single spaces need no normalization.
                                 ;; Keep boundary spaces separate so the next feed
                                 ;; or escape can still collapse adjacent spaces.
                                 (or (fx= (fx+ q 1) end)
                                     (case (string-ref input (fx+ q 1))
                                       ((#\" #\\ #\space #\newline #\return) #t)
                                       (else #f))))
                                (else #f)))
                        (begin
                          (set! parser.fragments (cons (substring input p q) parser.fragments))
                          (set! p (fx- q 1)))
                        (scan (fx+ q 1)))))))
            ((escaped)
             (unless (attribute-escape? c)
               (set! parser.fragments (cons #\\ parser.fragments)))
             (attribute-value-character! parser c)
             (set! parser.state 'quoted)))
          (loop (fx+ p 1))))))
