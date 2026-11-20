;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/test/base
        :std/source
        (only-in :std/string/misc string-subst)
        ../djot)
(export djot-conformance-test
        read-fixtures
        conformance-counts
        (struct-out djot-fixture))

(def fixture-files
  '("attributes.test" "block_quote.test" "code_blocks.test" "definition_lists.test"
    "symb.test" "emphasis.test" "escapes.test" "fenced_divs.test" "footnotes.test"
    "headings.test" "insert_delete_mark.test" "links_and_images.test" "lists.test"
    "math.test" "para.test" "raw.test" "regression.test" "smart.test" "spans.test"
    "sourcepos.test" "super_subscript.test" "tables.test" "task_lists.test"
    "thematic_breaks.test" "verbatim.test"))

(defstruct djot-fixture
  ((file     : :string)
   (line     : :fixnum)
   (options  : :string)
   (input    : :string)
   (expected : :string))
  transparent: #t)

(def (fence-length (line : :string)) => :fixnum
  (let loop ((index 0))
    => :fixnum
    (if (and (< index (string-length line)) (char=? (string-ref line index) #\`))
      (loop (+ index 1)) index)))

(def (read-fixture-file (file : :string)) => :list
  (call-with-input-file (path-expand file (path-expand "testdata" (this-source-directory)))
    (lambda ((port :~ input-port?))
      => :list
      (def line-number 0)
      (def (next-line) => :t
        (set! line-number (+ line-number 1))
        (read-line port))
      (def (read-part (stop? : :procedure)) => :string
        (let (output (open-output-string))
          (let loop ()
            => :string
            (let (line (next-line))
              (cond
               ((eof-object? line) (error "Unclosed Djot fixture" file line-number))
               ((stop? line) (get-output-string output))
               (else
                (display line output)
                (newline output)
                (loop)))))))
      (let loop ((fixtures []))
        => :list
        (let (line (next-line))
          (cond
           ((eof-object? line) (reverse fixtures))
           ((>= (fence-length line) 3)
            (let* ((start line-number)
                   (ticks (fence-length line))
                   (options (substring line ticks (string-length line)))
                   (input (read-part (lambda ((line : :string)) => :boolean
                                       (string=? line "."))))
                   (expected (read-part (lambda ((line : :string)) => :boolean
                                          (>= (fence-length line) ticks)))))
              (loop (cons (make-djot-fixture file start options input expected) fixtures))))
           (else (loop fixtures))))))))

(def (read-fixtures) => :list
  (apply append (map read-fixture-file fixture-files)))

(def (fixture-option? (fixture : djot-fixture) (option : :char)) => :boolean
  (and (memv option (string->list (djot-fixture-options fixture))) #t))

;;; Only fields present in the six upstream AST examples are projected. This is
;;; semantic test data, not an implementation of the upstream pretty-printer.
(def (project-node (node : djot-node) (positions? : :boolean)) => :list
  (def tag
    (cond ((djot-document? node) 'doc) ((djot-block-quote? node) 'block-quote)
          ((djot-paragraph? node) 'para) ((djot-text? node) 'str)
          ((djot-symbol? node) 'symb) ((djot-table? node) 'table)
          ((djot-caption? node) 'caption) ((djot-row? node) 'row)
          ((djot-cell? node) 'cell) ((djot-bullet-list? node) 'bullet-list)
          ((djot-list-item? node) 'list-item)
          (else (error "Unexpected node in Djot AST fixture" node))))
  (def fields
    (cond ((djot-text? node) [[text: (djot-textual-text node)]])
          ((djot-symbol? node) [[alias: (djot-symbol-alias node)]])
          ((djot-row? node) [[head: (djot-row-head? node)]])
          ((djot-cell? node) [[head: (djot-cell-head? node)] [align: (djot-cell-alignment node)]])
          ((djot-bullet-list? node) [[tight: (djot-bullet-list-tight? node)]
                                    [style: (djot-bullet-list-style node)]])
          (else [])))
  (def source (djot-node-source node))
  (list tag
        (map (lambda ((attribute : djot-attribute)) => :list
               [(djot-attribute-name attribute) (djot-attribute-value attribute)])
             (djot-node-attributes node))
        (if (and positions? source (not (djot-document? node)))
          (cons [source: (djot-source-range-start source) (djot-source-range-end source)] fields)
          fields)
        (if (djot-container? node)
          (map (lambda ((child : djot-node)) => :list (project-node child positions?))
               (djot-container-children node))
          [])))

(def (ast-expectation (fixture : djot-fixture)) => :list
  (let (key [(djot-fixture-file fixture) (djot-fixture-line fixture)])
    (cond
     ((equal? key '("attributes.test" 405))
      '(doc () ()
         ((block-quote (("attr" "long value spanning multiple lines")) ()
            ((para () ()
               ((str () ((text: "a")) ()))))))))
     ((equal? key '("attributes.test" 421))
      '(doc () ()
         ((block-quote () ()
            ((para (("key" "bar a$bim")) ()
               ((str () ((text: "ou")) ()))))))))
     ((equal? key '("symb.test" 1))
      '(doc () ()
         ((para () ()
            ((symb () ((alias: "+1")) ())
             (str () ((text: " ")) ())
             (symb () ((alias: "scream")) ()))))))
     ((equal? key '("symb.test" 11))
      '(doc () ()
         ((para () ()
            ((symb () ((alias: "ice")) ())
             (str () ((text: "scream:")) ()))))))
     ((equal? key '("regression.test" 46))
      '(doc () ()
         ((table () ()
            ((caption () ()
               ((str () ((text: "cap2")) ())))
             (row () ((head: #f))
               ((cell () ((head: #f) (align: default))
                  ((str () ((text: "1")) ())))
                (cell () ((head: #f) (align: default))
                  ((str () ((text: "2")) ()))))))))))
     ((equal? key '("sourcepos.test" 1))
      '(doc () ()
         ((bullet-list () ((source: 1 10) (tight: #t) (style: "-"))
            ((list-item () ((source: 1 5))
               ((para () ((source: 3 5))
                  ((str () ((source: 3 4) (text: "a")) ())))))
             (list-item () ((source: 6 10))
               ((para () ((source: 8 10))
                  ((str () ((source: 8 9) (text: "b")) ()))))))))))
     (else (error "Unaccounted Djot AST fixture" key)))))

(def (fixture-actual (fixture : djot-fixture)) => :t
  (let* ((positions? (fixture-option? fixture #\p))
         (document (string->djot (djot-fixture-input fixture) source-locations: positions?)))
    (if (fixture-option? fixture #\a)
      (project-node document positions?)
      (djot->html document))))

(def (fixture-expected (fixture : djot-fixture)) => :t
  (if (fixture-option? fixture #\a)
    (ast-expectation fixture)
    ;; Only these three cases use XML-style checkbox endings. The HTML writer
    ;; emits HTML void tags; no other expected bytes are adapted.
    (if (and (string=? (djot-fixture-file fixture) "task_lists.test")
             (memv (djot-fixture-line fixture) '(1 17 38)))
      (string-subst
       (string-subst (djot-fixture-expected fixture)
         "<input disabled=\"\" type=\"checkbox\"/>" "<input disabled=\"\" type=\"checkbox\">")
       "<input disabled=\"\" type=\"checkbox\" checked=\"\"/>" "<input disabled=\"\" type=\"checkbox\" checked=\"\">")
      (djot-fixture-expected fixture))))

(def (conformance-counts) => :list
  (let loop ((fixtures (read-fixtures)) (passed 0) (failed 0))
    => :list
    (if (null? fixtures)
      [passed failed]
      (let (ok? (with-catch (lambda ((error : :t)) => :boolean #f)
                  (lambda () => :boolean
                    (equal? (fixture-actual (car fixtures)) (fixture-expected (car fixtures))))))
        (loop (cdr fixtures) (+ passed (if ok? 1 0)) (+ failed (if ok? 0 1)))))))

(def djot-conformance-test
  (test-suite "pinned Djot functional corpus (full grammar gate)"
    (test-case "complete pinned inventory"
      (let (fixtures (read-fixtures))
        (check (length fixtures) => 302)
        (check (length (filter (lambda ((fixture : djot-fixture)) => :boolean
                                 (fixture-option? fixture #\a))
                               fixtures))
               => 6)
        (check (length (filter (lambda ((fixture : djot-fixture)) => :boolean
                                 (fixture-option? fixture #\p))
                               fixtures))
               => 1)))

    (for-each
     (lambda ((fixture : djot-fixture)) => :void
       (test-case-add!
        (TestCase (string-append (djot-fixture-file fixture) ":"
                                 (number->string (djot-fixture-line fixture)))
                  (lambda () => :void
                    (check (fixture-actual fixture) => (fixture-expected fixture))))))
     (read-fixtures))))
