;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/text/markup/xml/node
        :std/text/markup/html/atoms
        :std/text/markup/html/rules
        :std/text/markup/html/tokenizer)
(export rules-test)

;;; Calls (check-atom k name) for every known atom k and its name.
(def (for-each-known-atom check-atom)
  (let loop ((k 1))
    (when (<= k known-atom-count)
      (check-atom k (vector-ref known-atom-names k))
      (loop (+ k 1)))))

;;; True when the tokenizer reads data</script> in the script data state
;;; as the characters data, then the end tag script, then the end.
(def (tokenizer-script-ends? data)
  (let (tz (make-html-tokenizer (string-append data "</script>")))
    (html-tokenizer-state-set! tz html-state-script-data)
    (html-tokenizer-last-start-tag-set! tz "script")
    (let loop ((text "") (kinds '()))
      (let (kind (html-tokenizer-next! tz))
        (cond
         ((= kind html-token-eof)
          (and (string=? text data)
               (equal? (reverse kinds) (if (string=? data "") '(end) '(chars end)))))
         ((= kind html-token-characters)
          (loop (string-append text (html-token-text tz))
                (if (and (pair? kinds) (eq? (car kinds) 'chars)) kinds (cons 'chars kinds))))
         ((= kind html-token-end-tag)
          (html-tokenizer-state-set! tz html-state-data)
          (loop text (cons (if (string=? (html-token-tag-name tz) "script") 'end 'other-end) kinds)))
         (else (loop text (cons 'other kinds))))))))

;;; Random script text over an alphabet heavy in the characters and words
;;; the script data states switch on.
(def script-alphabet (list->vector (string->list "<<<//!!---->>scriptSCRIPT x\t\n\f")))
(def script-words
  '#("<script" "</script" "<!--" "-->" "<SCRIPT " "</script>" "<script>" "--" "<!-" "</scrip"
     "<scripts"))

(def (random-script-text random)
  (let loop ((k (+ 1 (random 12))) (parts '()))
    (if (= k 0)
      (apply string-append parts)
      (loop (- k 1)
            (cons (if (= (random 3) 0)
                    (vector-ref script-words (random (vector-length script-words)))
                    (string (vector-ref script-alphabet (random (vector-length script-alphabet)))))
                  parts)))))

(def rules-test
  (test-suite "test :std/text/markup/html/rules"
    (test-case "the atom and name views of element classes agree"
      (for-each-known-atom
       (lambda (k name)
         (check (element-class-of-atom k) => (element-class-of-name name))))
      (check (element-class-of-name "textarea") => (fxior class-rcdata class-newline))
      (check (element-class-of-name "Textarea") => 0)
      (check (element-class-of-name "x-unknown") => 0))

    (test-case "the atom and name views of the foreign breakout set agree"
      (for-each-known-atom
       (lambda (k name)
         (check (foreign-breakout-atom? k) => (foreign-breakout-name? name))))
      (check (foreign-breakout-name? "font") => #f)
      (check (start-tag-namespace context-svg "font" #f) => ns-svg)
      (check (start-tag-namespace context-svg "font" #t) => -1)
      (check (start-tag-namespace context-svg "p" #f) => -1)
      (check (start-tag-namespace context-text-point "mglyph" #f) => ns-mathml)
      (check (start-tag-namespace context-annotation "svg" #f) => ns-svg))

    (test-case "the atom and name views of the font breakout attributes agree"
      (for-each-known-atom
       (lambda (k name)
         (check (cons name (font-breakout-attribute-atom? k))
                => (cons name (font-breakout-attributes? [(unchecked-node XMLAttribute (known-name k) "")]))))))

    (test-case "known names are the parser's names of the known atoms"
      (for-each-known-atom
       (lambda (k name)
         (using (xname (known-name k) : XMLName)
           (check xname.local => name)
           (check xname.uri => "")
           (check xname.prefix => "")))))

    (test-case "start tags that close a p, by context"
      (check (start-tag-closes-p? atom-div #f #f) => #t)
      (check (start-tag-closes-p? atom-li #f #f) => #t)
      (check (start-tag-closes-p? atom-span #f #f) => #f)
      (check (start-tag-closes-p? atom-table #f #f) => #t)
      (check (start-tag-closes-p? atom-table #t #f) => #f)
      (check (start-tag-closes-p? atom-form #f #f) => #t)
      (check (start-tag-closes-p? atom-form #f #t) => #f))

    (test-case "a p sets p in button scope, a scope boundary clears it, others keep it"
      (defrule (after ns atom below?)
        (p-in-button-scope-after ns atom (element-flags ns atom #f) below?))
      (check (after ns-html atom-p #f) => #t)
      (check (after ns-svg atom-p #f) => #f)
      (check (after ns-html atom-button #t) => #f)
      (check (after ns-html atom-object #t) => #f)
      (check (after ns-svg atom-foreignobject #t) => #f)
      (check (after ns-svg atom-svg #t) => #t)
      (check (after ns-html atom-span #t) => #t)
      (check (after ns-html atom-div #f) => #f))

    (test-case "class tokenizer states"
      (check (class-tokenizer-state (element-class-of-name "script") #f) => html-state-script-data)
      (check (class-tokenizer-state (element-class-of-name "style") #f) => html-state-rawtext)
      (check (class-tokenizer-state (element-class-of-name "title") #f) => html-state-rcdata)
      (check (class-tokenizer-state (element-class-of-name "plaintext") #f) => html-state-plaintext)
      (check (class-tokenizer-state (element-class-of-name "noscript") #t) => html-state-rawtext)
      (check (class-tokenizer-state (element-class-of-name "noscript") #f) => html-state-data)
      (check (class-tokenizer-state (element-class-of-name "div") #t) => html-state-data))

    (test-case "script-text-ends? agrees with the tokenizer's script data states"
      (let (source (make-random-source))
        (random-source-pseudo-randomize! source 1 0)
        (let ((random (random-source-make-integers source))
              (ends 0))
          (let loop ((k 0))
            (when (< k 2000)
              (let* ((data (random-script-text random))
                     (expected (tokenizer-script-ends? data)))
                (when expected (set! ends (+ ends 1)))
                (check (cons data (script-text-ends? data)) => (cons data expected)))
              (loop (+ k 1))))
          ;; both outcomes occur
          (check (< 0 ends 2000) => #t))))))
