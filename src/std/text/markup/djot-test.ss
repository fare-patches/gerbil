;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import (only-in :gerbil/core/runtime char-set:punctuation char-set-contains?)
        :std/test
        :std/io
        :std/text/markup/sxml
        ./djot
        (only-in ./djot/inline parse-inlines make-source-slice)
        (only-in ./djot/attributes merge-attribute-groups new-attribute-parser
                 feed-attributes! attribute-parser-attributes attribute-parser-state)
        (only-in :std/string/misc string-concatenate))
(export djot-test
        djot-block-test
        djot-inline-test
        djot-render-test)

(def (first-text (document : djot-document)) => djot-text
  (car (djot-container-children (car (djot-container-children document)))))

(def (first-block (input : :string)) => djot-node
  (car (djot-container-children (string->djot input))))

(def (plain-inline-text (node : djot-container)) => :string
  (apply string-append
         (map (lambda ((child : djot-node)) => :string
                (cond ((djot-textual? child) (djot-textual-text child))
                      ((djot-soft-break? child) "\n")
                      (else (plain-inline-text child))))
              (djot-container-children node))))

(def (inline-children (input : :string)) => :list
  (djot-container-children (first-block input)))

(def (first-inline (input : :string)) => djot-node
  (car (inline-children input)))

(def (attribute-values (node : djot-node)) => :list
  (map (lambda ((a : djot-attribute)) => :list
         [(djot-attribute-name a) (djot-attribute-value a)])
       (djot-node-attributes node)))

(def (resource-error-details? (thunk   : :procedure)
                              (message : :string)) => :boolean
  (with-catch
    (lambda ((exception : :t)) => :boolean
      (and (DjotResourceError? exception)
           (equal? (error-message exception) message)
           (equal? (error-irritants exception) [depth: 513 limit: 512])
           (string? (error-trace exception))
           (> (string-length (error-trace exception)) 0)))
    (lambda () => :boolean (thunk) #f)))

(def djot-inline-test
  (test-suite "Djot inlines"
    (test-case "reference links inside destinations preserve enclosing links and images"
      (for-each
       (lambda ((located? : :boolean)) => :void
         (check (djot->html (string->djot "[x](a[b][c])" source-locations: located?))
           => "<p><a href=\"a[b][c]\">x</a></p>\n")
         (check (djot->html (string->djot "![x](a[b][c])" source-locations: located?))
           => "<p><img alt=\"x\" src=\"a[b][c]\"></p>\n"))
       '(#f #t)))

    (test-case "destination delimiters cannot reopen a blocked external opener"
      ;; Minimized from tartan-wikipedia; pinned djot.js treats these as literals
      ;; inside the destination, not new openers that consume its parentheses.
      (check (djot->html (string->djot "_[a](x_(y_z))_"))
             => "<p><em><a href=\"x_(y_z)\">a</a></em></p>\n")
      (check (djot->html (string->djot "_a [a](x_(y_z)_w_q){title=\"v\"}"))
             => "<p>_a <a href=\"x_(y_z)_w_q\" title=\"v\">a</a></p>\n")
      (let* ((document (string->djot "_é[名](x_(y_z))_" source-locations: #t))
             (emphasis (car (djot-container-children (car (djot-container-children document)))))
             (link (cadr (djot-container-children emphasis)))
             (source (djot-node-source link)))
        (check (djot-link-destination link) => "x_(y_z)")
        (check [(djot-source-range-start source) (djot-source-range-end source)] => [2 14])))
    (test-case "link literal spans preserve escapes and destination normalization"
      (for-each
       (lambda ((example : :list)) => :void
         (for-each
          (lambda ((located? : :boolean)) => :void
            (let* ((doc (string->djot (car example) source-locations: located?))
                   (link (car (djot-container-children (car (djot-container-children doc))))))
              (check (djot-link-destination link) => (cadr example))
              (check (djot-link-reference link) => (caddr example))
              (when located?
                (check (djot-source-range-end (djot-node-source link))
                  => (string-length (car example))))))
          '(#f #t)))
       '(("[x](a_(b)_c)" "a_(b)_c" #f)
         ("[x](a\\)b)" "a)b" #f)
         ("[x](a\\ b)" "a\\ b" #f)
         ("[x](a\\\r\n  b)" "a\\b" #f)
         ("[x](a`code`b)" "a`code`b" #f)
         ("[x](a{.c}b)" "a{.c}b" #f)
         ("[x][ a\\_b\r\n c ]" #f "a_b c")
         ("[x]()" "" #f))))

    (test-case "long link literals preserve contiguous and escaped token spans"
      (let* ((plain (apply string-append (make-list 1000 "a_b.(c)")))
             (escaped (apply string-append (make-list 1000 "a\\_b\\)")))
             (expected (apply string-append (make-list 1000 "a_b)"))))
        (check (djot-link-destination (first-inline (string-append "[x](" plain ")"))) => plain)
        (check (djot-link-destination (first-inline (string-append "[x](" escaped ")"))) => expected)))

    (test-case "fragmented link destinations exceed procedure argument limits"
      (let* ((destination (string-concatenate (make-list 10000 "a_b")))
             (link (first-inline (string-append "[x](" destination ")"))))
        (check (djot-link-destination link) => destination)))

    (test-case "multiline link destinations exceed procedure argument limits"
      (let* ((lines (string-concatenate (make-list 20000 " a \n")))
             (link (first-inline (string-append "[x](" lines " b)"))))
        (check (djot-link-destination link) => (string-append (make-string 20000 #\a) "b"))))

    (test-case "inline view preserves empty slices and trims only the final slice"
      (check (parse-inlines "" [] #t) => [])
      (check (parse-inlines "\r\n" [(make-source-slice 0 0 1 0 2)] #t) => [])
      (let* ((input "aaα \t\r\nbbβ \rcc😀 \t")
             (nodes (parse-inlines input
                      [(make-source-slice 2 5 1 0 7)
                       (make-source-slice 9 11 2 7 12)
                       (make-source-slice 14 17 3 12 17)] #t)))
        (check (map (lambda ((node : djot-node)) => :string
                      (if (djot-soft-break? node) "\n" (djot-textual-text node))) nodes)
               => ["α \t" "\n" "β " "\n" "😀"])
        (check (map (lambda ((node : djot-node)) => :list
                      (let (source (djot-node-source node))
                        [(djot-source-range-start source) (djot-source-range-end source)
                         (djot-source-range-start-line source) (djot-source-range-start-column source)
                         (djot-source-range-end-line source) (djot-source-range-end-column source)])) nodes)
               => [[2 5 1 3 1 6] [5 7 1 6 2 1] [9 11 2 3 2 5]
                   [11 12 2 5 3 1] [14 15 3 3 3 4]])))

    (test-case "inline token growth preserves links, attributes and original ranges"
      (let* ((unit "[α](url){#i} ")
             (input (apply string-append (make-list 100 unit)))
             (document (string->djot input source-locations: #t))
             (nodes (djot-container-children (car (djot-container-children document))))
             (links (filter djot-link? nodes)))
        (check (length nodes) => 199)
        (check (length links) => 100)
        (let loop ((rest links) (offset 0 : :fixnum)) => :void
          (unless (null? rest)
            (let* ((link (:- (car rest) djot-link))
                   (source (djot-node-source link)))
              (check (djot-link-destination link) => "url")
              (check (plain-inline-text link) => "α")
              (check (attribute-values link) => [["id" "i"]])
              (check [(djot-source-range-start source) (djot-source-range-end source)]
                     => [offset (+ offset 8)]))
            (loop (cdr rest) (+ offset (string-length unit)))))))

    (test-case "inline slice mapping preserves empty lines and trimmed final newlines"
      (let* ((input "α\r\n\r\nβ \t\r\n")
             (nodes (parse-inlines input
                      [(make-source-slice 0 1 1 0 3)
                       (make-source-slice 3 3 2 3 5)
                       (make-source-slice 5 8 3 5 10)] #t)))
        (check (map (lambda ((node : djot-node)) => :string
                      (if (djot-soft-break? node) "\n" (djot-textual-text node))) nodes)
               => ["α" "\n" "\n" "β"])
        (check (map (lambda ((node : djot-node)) => :list
                      (let (source (djot-node-source node))
                        [(djot-source-range-start source) (djot-source-range-end source)
                         (djot-source-range-start-line source) (djot-source-range-start-column source)
                         (djot-source-range-end-line source) (djot-source-range-end-column source)])) nodes)
               => [[0 1 1 1 1 2] [1 3 1 2 2 1] [3 5 2 1 3 1] [5 6 3 1 3 2]])))

    (test-case "attribute slice chunks preserve continuation, CRLF failure and trimming"
      (let* ((input (string-append "x{title=\"" (apply string-append (make-list 1000 "a\r\n")) "z\"} _y_"))
             (nodes (inline-children input)))
        (check (attribute-values (car nodes))
               => [["title" (string-append (apply string-append (make-list 1000 "a ")) "z")]])
        (check (djot-emph? (last nodes)) => #t))
      (let* ((document (string->djot "x{k=\r\n_yes_" source-locations: #t))
             (paragraph (car (djot-container-children document)))
             (nodes (djot-container-children paragraph))
             (source (djot-node-source (cadr nodes))))
        (check (plain-inline-text paragraph) => "x{k=\nyes")
        (check (djot-emph? (last nodes)) => #t)
        (check [(djot-source-range-start source) (djot-source-range-end source)] => [4 6]))
      (check (plain-inline-text (first-block "x{title=\"a   \t\r\n")) => "x{title=\"a"))

    (test-case "inline classification preserves ordinary ASCII and Unicode text"
      (let loop ((code 0))
        (when (< code 128)
          (unless (memv code '(10 13 33 34 36 39 40 41 42 43 45 46 58 60 61 91 92 93 94 95 96 123 126))
            (let (text (string #\a (integer->char code) #\b))
              (check (plain-inline-text (first-block text)) => text)))
          (loop (+ code 1))))
      (check (plain-inline-text (first-block "é日本語😀＂＊＿［］～")) => "é日本語😀＂＊＿［］～"))

    (test-case "retained unmatched openers do not interfere with later closed spans"
      (let* ((prefix (apply string-append (make-list 2000 "[a ")))
             (input (string-append prefix (apply string-append (make-list 2000 "_x_ "))))
             (nodes (inline-children input)))
        (check (djot-textual-text (car nodes)) => prefix)
        (check (length (filter djot-emph? nodes)) => 2000)
        (check (plain-inline-text (first-block input))
               => (string-append prefix (apply string-append (make-list 1999 "x ")) "x"))))

    (test-case "first closed opener wins across formatting and links"
      (let (nodes (inline-children "_a *b_ c*"))
        (check (djot-emph? (car nodes)) => #t)
        (check (plain-inline-text (car nodes)) => "a *b")
        (check (djot-textual-text (cadr nodes)) => " c*"))
      (check (djot-link? (first-inline "[a *](url)*")) => #t)
      (check (djot-strong? (first-inline "*a [*](url)")) => #t))

    (test-case "closest opener wins and empty emphasis is literal"
      (let (nodes (inline-children "*a *b*"))
        (check (djot-textual-text (car nodes)) => "*a ")
        (check (djot-strong? (cadr nodes)) => #t))
      (check (djot-textual-text (first-inline "___")) => "___"))

    (test-case "nested formats and explicit markers are distinct"
      (check (djot-strong? (cadr (djot-container-children (first-inline "_a *b* c_")))) => #t)
      (check (djot-emph? (first-inline "{_ a _}")) => #t)
      (check (plain-inline-text (first-block "{_a_")) => "{_a_")
      (check (plain-inline-text (first-block "_a_}")) => "_a_}"))

    (test-case "all braced delimiter kinds retain distinct opener stacks"
      (check (djot-emph? (first-inline "{_x_}")) => #t)
      (check (djot-strong? (first-inline "{*x*}")) => #t)
      (check (djot-subscript? (first-inline "{~x~}")) => #t)
      (check (djot-superscript? (first-inline "{^x^}")) => #t)
      (check (djot-insert? (first-inline "{+x+}")) => #t)
      (check (djot-mark? (first-inline "{=x=}")) => #t)
      (check (djot-delete? (first-inline "{-x-}")) => #t)
      (check (djot-single-quoted? (first-inline "{'x'}")) => #t)
      (check (djot-double-quoted? (first-inline "{\"x\"}")) => #t))

    (test-case "braced and plain stacks coexist with links and destination parentheses"
      (let* ((node (first-inline "{_a _b_ [c](u(v)) d_}"))
             (children (djot-container-children node))
             (link (car (filter djot-link? children))))
        (check (djot-emph? node) => #t)
        (check (djot-emph? (cadr children)) => #t)
        (check (plain-inline-text node) => "a b c d")
        (check (djot-link-destination link) => "u(v)")))

    (test-case "long trailing space preserves ordinary text, fences and tables"
      (let (padding (make-string 20000 #\space))
        (check (plain-inline-text (first-block (string-append "alpha" padding))) => "alpha")
        (check (plain-inline-text (first-block (string-append "alpha" padding "\r\n"))) => "alpha")
        (check (djot-code-block? (first-block (string-append "```" padding "\nx\n```" padding))) => #t)
        (check (djot-table? (first-block (string-append "| x |" padding))) => #t)))

    (test-case "formatting delimiters produce their corresponding node types"
      (check (djot-mark? (first-inline "{=x=}")) => #t)
      (check (djot-insert? (first-inline "{+x+}")) => #t)
      (check (djot-delete? (first-inline "{-x-}")) => #t)
      (check (djot-superscript? (first-inline "^x^")) => #t)
      (check (djot-subscript? (first-inline "~x~")) => #t)
      (check (djot-textual-text (first-inline "+x+ =x=")) => "+x+ =x="))

    (test-case "verbatim delimiters and unclosed recovery"
      (check (djot-textual-text (first-inline "`` `a` ``")) => "`a`")
      (check (djot-textual-text (first-inline "`a `` b`")) => "a `` b")
      (check (djot-textual-text (first-inline "`a _b_\\c\n")) => "a _b_\\c")
      (check (djot-textual-text (first-inline "`a\nb`")) => "a\nb"))

    (test-case "math and raw formats retain text and format"
      (check (djot-inline-math? (first-inline "$`x`")) => #t)
      (check (djot-display-math? (first-inline "$$`x`")) => #t)
      (let (node (first-inline "`<b>x</b>`{=html}"))
        (check (djot-raw-inline-format node) => "html")
        (check (djot-textual-text node) => "<b>x</b>"))
      (check (djot-verbatim? (cadr (inline-children "\\$`x`"))) => #t))

    (test-case "all ASCII punctuation escapes and nonpunctuation preservation"
      (check (plain-inline-text (first-block "\\*\\_\\[\\]\\{\\}\\<\\>\\!\\$\\@")) => "*_[]{}<>!$@")
      (check (plain-inline-text (first-block "\\a")) => "\\a")
      (check (djot-nonbreaking-space? (cadr (inline-children "a\\ b"))) => #t))

    (test-case "hard breaks consume neighboring horizontal space and CRLF"
      (let (nodes (inline-children "a  \t\\ \t\r\nb"))
        (check (djot-textual-text (car nodes)) => "a")
        (check (djot-hard-break? (cadr nodes)) => #t)
        (check (djot-textual-text (caddr nodes)) => "b"))
      (check (djot-hard-break? (cadr (inline-children "a\\\n"))) => #t)
      (check (length (inline-children "a\n")) => 1))

    (test-case "smart quote containers and apostrophe heuristic"
      (check (djot-double-quoted? (first-inline "\"hello\"")) => #t)
      (check (djot-single-quoted? (first-inline "'hello'")) => #t)
      (check (djot-smart-punctuation-kind (cadr (inline-children "don't"))) => 'right-single-quote)
      (check (djot-smart-punctuation-kind (first-inline "'}Tis")) => 'right-single-quote)
      (check (djot-smart-punctuation-kind (first-inline "{\"a")) => 'left-double-quote))

    (test-case "dash runs prefer uniform divisions and ellipses"
      (check (map djot-smart-punctuation-kind
                  (filter djot-smart-punctuation?
                          (inline-children "a----b")))
             => ['en-dash 'en-dash])
      (check (map djot-smart-punctuation-kind
                  (filter djot-smart-punctuation?
                          (inline-children "a------b...")))
             => ['em-dash 'em-dash 'ellipses]))

    (test-case "symbols remain distinct and do not consume following colon text"
      (let (nodes (inline-children ":ice:scream:"))
        (check (djot-symbol-alias (car nodes)) => "ice")
        (check (djot-textual-text (cadr nodes)) => "scream:"))
      (check (djot-symbol-alias (first-inline ":+1:")) => "+1"))

    (test-case "inline links preserve nested parentheses and escaped punctuation"
      (let (node (first-inline "[a _b_](a(b)\\)c)"))
        (check (djot-link-destination node) => "a(b))c")
        (check (djot-emph? (cadr (djot-container-children node))) => #t))
      (check (djot-link-destination (first-inline "[x](a*b*)")) => "a*b*")
      (check (plain-inline-text (first-block "[x](broken")) => "[x](broken"))

    (test-case "multiline link and image URLs trim line boundaries only"
      (check (djot-link-destination (first-inline "[x]( a b \t\n  c d\t )")) => "a bc d")
      (check (djot-image-destination (first-inline "![x]( a\t\r\n b )")) => "ab")
      (check (djot-link-destination (first-inline "[x]( a b )")) => " a b "))

    (test-case "reference labels normalize whitespace without changing case"
      (check (djot-link-reference (first-inline "[x][ A\n B ]")) => "A B")
      (check (djot-link-reference (first-inline "[a _b_][]")) => "a b")
      (check (djot-link-reference (first-inline "[missing][NotDefined]")) => "NotDefined")
      (check (djot-image-reference (first-inline "![x][]")) => "x"))

    (test-case "escaped image markers do not create images"
      (let (nodes (inline-children "\\![x](url)"))
        (check (djot-textual-text (car nodes)) => "!")
        (check (djot-link? (cadr nodes)) => #t))
      (check (djot-image? (cadr (inline-children "a![x](url)"))) => #t))

    (test-case "autolinks are literal and require an address"
      (check (djot-textual-text (first-inline "<https://a/\\b>")) => "https://a/\\b")
      (check (djot-email? (first-inline "<a@b>")) => #t)
      (check (plain-inline-text (first-block "<no> <a b>")) => "<no> <a b>"))

    (test-case "footnotes retain normalized labels and local recognition"
      (check (djot-textual-text (first-inline "[^ A\n B ]")) => "A B")
      (check (djot-footnote-reference? (first-inline "[^missing]")) => #t))

    (test-case "empty footnote references remain literal"
      (for-each
       (lambda ((located? : :boolean)) => :void
         (let (document (string->djot "x[^]y" source-locations: located?))
           (check (djot->html document) => "<p>x[^]y</p>\n")
           (check (djot-document-footnotes document) => [])))
       '(#f #t))
      (check (djot-footnote-reference? (first-inline "[^n]")) => #t)
      (check (djot-textual-text (first-inline "[^n]")) => "n"))

    (test-case "bracket spans require valid attributes"
      (let (node (first-inline "[a _b_]{.x}"))
        (check (djot-span? node) => #t)
        (check (attribute-values node) => [["class" "x"]]))
      (check (plain-inline-text (first-block "[a]{broken}")) => "[a]{broken}")
      (check (plain-inline-text (first-block "[a_x]{broken}_y")) => "[a_x]{broken}_y"))

    (test-case "attributes include escaped punctuation with following text"
      (let* ((input "a\\*b{.c}")
             (document (string->djot input source-locations: #t))
             (nodes (djot-container-children (car (djot-container-children document))))
             (word (cadr nodes))
             (source (djot-node-source word)))
        (check (length nodes) => 2)
        (check (djot-text? word) => #t)
        (check (djot-textual-text (car nodes)) => "a")
        (check (djot-textual-text word) => "*b")
        (check (attribute-values word) => [["class" "c"]])
        (check [(djot-source-range-start source) (djot-source-range-end source)
                (djot-source-range-start-line source) (djot-source-range-start-column source)
                (djot-source-range-end-line source) (djot-source-range-end-column source)]
               => [2 4 1 3 1 5])
        (check (djot->html document) => "<p>a<span class=\"c\">*b</span></p>\n")))

    (test-case "attributes attach to trailing word and stack in order"
      (let (nodes (inline-children "a word{#x .a}{.b title=t}"))
        (check (djot-textual-text (car nodes)) => "a ")
        (check (attribute-values (cadr nodes)) => [["id" "x"] ["class" "a b"] ["title" "t"]]))
      (check (attribute-values (first-inline "_x_{class=a .b}")) => [["class" "a b"]]))

    (test-case "multiline inline attributes and comments reuse shared grammar"
      (check (attribute-values (first-inline "x{title=\"a\r\n b\"}")) => [["title" "a b"]])
      (check (plain-inline-text (first-block "a{%comment\nmore%}b")) => "ab")
      (check (attribute-values (first-inline "a {.x}")) => []))

    (test-case "failed attribute candidates replay formatting once"
      (let (nodes (inline-children "x{a=?_yes_ }"))
        (check (djot-emph? (cadr nodes)) => #t))
      (check (plain-inline-text (first-block "x{a=\"unterminated")) => "x{a=\"unterminated"))

    (test-case "failed block attributes stay literal without suppressing later inline attributes"
      (let (node (first-block "{%\nunindented\n%} later{.ok}"))
        (check (plain-inline-text node) => "{%\nunindented\n%} later")
        (check (attribute-values (last (djot-container-children node))) => [["class" "ok"]]))
      (check (djot->html (string->djot "{%\nSPDX-FileCopyrightText: 2025\n%}\n"))
             => "<p>{%\nSPDX-FileCopyrightText: 2025\n%}</p>\n"))

    (test-case "formatting spans prefixed original slices"
      (let* ((doc (string->djot "> _a\r\n> b_" source-locations: #t))
             (quote (car (djot-container-children doc)))
             (para (car (djot-container-children quote)))
             (emph (car (djot-container-children para)))
             (source (djot-node-source emph))
             (soft (djot-node-source (cadr (djot-container-children emph)))))
        (check (djot-emph? emph) => #t)
        (check [(djot-source-range-start source) (djot-source-range-end source)] => [2 10])
        (check [(djot-source-range-start soft) (djot-source-range-end soft)] => [4 6])
        (check [(djot-source-range-end-line source) (djot-source-range-end-column source)] => [2 5])))

    (test-case "non-BMP character spans remain original-character offsets"
      (let* ((input (string-append "_" (string (integer->char 128512)) "_{#x}"))
             (node (car (djot-container-children
                         (car (djot-container-children
                                (string->djot input source-locations: #t))))))
             (source (djot-node-source node)))
        (check [(djot-source-range-start source) (djot-source-range-end source)] => [0 3])
        (check (attribute-values node) => [["id" "x"]])))

    (test-case "table cells and captions use inline semantics"
      (let* ((table (first-block "| _a_ | [x](u) |\n^ *caption*"))
             (caption (car (djot-container-children table)))
             (row (cadr (djot-container-children table))))
        (check (djot-strong? (car (djot-container-children caption))) => #t)
        (check (djot-emph?
                (car (djot-container-children (car (djot-container-children row)))))
               => #t)))

    (test-case "empty and stacked attribute groups preserve merging semantics"
      (check (merge-attribute-groups []) => [])
      (check (merge-attribute-groups [[] []]) => [])
      (let (attributes (merge-attribute-groups
                         [[(make-djot-attribute "class" "a") (make-djot-attribute "id" "first")]
                          [(make-djot-attribute "class" "b") (make-djot-attribute "id" "last")]]))
        (check (attribute-values (make-djot-text attributes [] #f "x"))
               => [["class" "a b"] ["id" "last"]])))

    (test-case "resource errors retain messages and report location and attempted depth"
      (check (resource-error-details?
               (lambda ()
                 (string->djot
                  (string-append (make-string 513 #\*) "x" (make-string 513 #\*))))
               "Djot nesting limit exceeded")
             => #t)
      (check (resource-error-details?
               (lambda ()
                 (string->djot
                  (string-append (apply string-append (make-list 513 "> ")) "x")))
               "Djot block nesting exceeds 512")
             => #t)
      (check (resource-error-details?
               (lambda ()
                 (string->djot
                  (string-append (apply string-append (make-list 511 "> ")) "_x_")))
               "Djot nesting limit exceeded")
             => #t)
      (let* ((node (let wrap ((remaining 513 : :fixnum)
                             (node (make-djot-text [] [] #f "x") : djot-node))
                     => djot-node
                     (if (fxzero? remaining) node
                       (wrap (fx- remaining 1) (make-djot-emph [] [] #f [node])))))
             (document (make-djot-document [] [] #f [node] [] [] [])))
        (check (resource-error-details? (lambda () (djot->sxml document))
                                       "Djot rendering nesting limit exceeded") => #t)))

    (test-case "pure inline nesting is bounded without rejecting unmatched openers"
      (let ((allowed (string-append (make-string 511 #\*) "x" (make-string 511 #\*)))
            (excess (string-append (make-string 512 #\*) "x" (make-string 512 #\*))))
        (check (djot-document? (string->djot allowed)) => #t)
        (check-exception (string->djot excess) DjotResourceError?)))

    (test-case "combined inline and block nesting has one 512 bound"
      (let ((allowed (string-append (apply string-append (make-list 510 "> ")) "_x_"))
            (excess (string-append (apply string-append (make-list 511 "> ")) "_x_")))
        (check (djot-document? (string->djot allowed)) => #t)
        (check-exception (string->djot excess) DjotResourceError?)))

    (test-case "modest adversarial openers and attribute recovery terminate"
      (check (djot-document? (string->djot (make-string 4000 #\[))) => #t)
      (check (djot-document? (string->djot (string-append "a{key=\"" (make-string 4000 #\{)))) => #t))))

(def djot-block-test
  (test-suite "Djot blocks"
    (test-case "paragraph cannot be interrupted by block-looking lines"
      (let (node (first-block "a\n# b\n- c\n> d\n| e |"))
        (check (djot-paragraph? node) => #t)
        (check (plain-inline-text node) => "a\n# b\n- c\n> d\n| e |")))

    (test-case "arbitrary heading levels and prefixed or lazy continuation"
      (let (node (car (djot-container-children
                       (first-block "######## heading\n######## more\nlazy\n\ntext"))))
        (check (djot-heading-level node) => 8)
        (check (plain-inline-text node) => "heading\nmore\nlazy")))

    (test-case "quote nesting and lazy continuation"
      (let* ((quote (first-block "> > one\nlazy\n> >\n> > two"))
             (inner (car (djot-container-children quote))))
        (check (djot-block-quote? inner) => #t)
        (check (map plain-inline-text (djot-container-children inner)) => ["one\nlazy" "two"])))

    (test-case "blank line ends lazy quote continuation"
      (let (nodes (djot-container-children (string->djot "> a\n\nb")))
        (check (map djot-block-quote? nodes) => [#t #f])
        (check (plain-inline-text (cadr nodes)) => "b")))

    (test-case "mixed thematic marker characters and indentation"
      (let (nodes (djot-container-children (string->djot "  * - *\ntext\n\n--")))
        (check (djot-thematic-break? (car nodes)) => #t)
        (check (plain-inline-text (caddr nodes)) => "--")))

    (test-case "code fence preserves relative indentation and closes with longer fence"
      (let (node (first-block "  ``` scheme\n    x\n  y\n  ````\ntail"))
        (check (djot-code-block-language node) => "scheme")
        (check (djot-textual-text node) => "  x\ny\n")))

    (test-case "fenced blocks exceed procedure argument limits"
      (let (text (string-concatenate (make-list 10000 "a\nb\n")))
        (for-each
         (lambda ((info : :string)) => :void
           (let (node (first-block (string-append "``` " info "\n" text "```\n")))
             (check (djot-textual-text node) => text)))
         ["scheme" "=html"])))

    (test-case "unclosed code fence stops when quote closes"
      (let (nodes (djot-container-children (string->djot "> ```\n> code\n\npara")))
        (check (djot-textual-text (car (djot-container-children (car nodes)))) => "code\n")
        (check (plain-inline-text (cadr nodes)) => "para")))

    (test-case "raw format remains semantic and EOF supplies text newline"
      (let (node (first-block "~~~ =html\n<b>"))
        (check (djot-raw-block-format node) => "html")
        (check (djot-textual-text node) => "<b>\n")))

    (test-case "code preserves original CRLF and lone CR line endings"
      (check (djot-textual-text (first-block "```\r\na\r\nb\r```\r")) => "a\r\nb\r"))

    (test-case "div classes do not inherit attribute-key colon syntax"
      (check (djot-div? (first-block "::: note_1-x\na\n:::")) => #t)
      (check (djot-paragraph? (first-block "::: note:x\na")) => #t))

    (test-case "div closing fence does not terminate code"
      (let* ((div (first-block "::: note\n```\n:::\n```\n:::"))
             (code (car (djot-container-children div))))
        (check (djot-div? div) => #t)
        (check (djot-attribute-value (car (djot-node-attributes div))) => "note")
        (check (djot-textual-text code) => ":::\n")))

    (test-case "bullet style changes split lists"
      (let (nodes (djot-container-children (string->djot "- a\n- b\n+ c\n* d")))
        (check (map djot-bullet-list-style nodes) => ["-" "+" "*"])
        (check (map (lambda ((n : djot-container)) => :fixnum
                      (length (djot-container-children n)))
                    nodes)
               => [2 1 1])))

    (test-case "list lazy continuation versus blank-delimited sublist"
      (let* ((list (first-block "- a\n  - literal\n\n  - nested\n- b"))
             (item (car (djot-container-children list))))
        (check (plain-inline-text (car (djot-container-children item))) => "a\n- literal")
        (check (djot-bullet-list? (cadr (djot-container-children item))) => #t)
        (check (djot-bullet-list-tight? list) => #t)))

    (test-case "loose list applies to all items and does not contaminate previous lists"
      (let (nodes (djot-container-children (string->djot "- a\n- b\n\ntext\n\n- x\n\n- y")))
        (check (djot-bullet-list-tight? (car nodes)) => #t)
        (check (djot-bullet-list-tight? (caddr nodes)) => #f)))

    (test-case "blank between item blocks makes the list loose"
      (let (list (first-block "- a\n\n  b\n- c"))
        (check (djot-bullet-list-tight? list) => #f)
        (check (length (djot-container-children (car (djot-container-children list)))) => 2)))

    (test-case "blank before first list content does not make list loose"
      (check (djot-bullet-list-tight? (first-block "-\n\n  a")) => #t))

    (test-case "roman-alpha ambiguity narrows across the list"
      (let ((alpha (first-block "i. one\nj. two"))
            (roman (first-block "(xix) one\n(xx) two")))
        (check (djot-ordered-list-style alpha) => "a.")
        (check (djot-ordered-list-start alpha) => 9)
        (check (djot-ordered-list-style roman) => "(i)")
        (check (djot-ordered-list-start roman) => 19)))

    (test-case "decimal start is the first marker and has no machine integer cap"
      (let (node (first-block "12345678901234567890) a\n8) b"))
        (check (djot-ordered-list-start node) => 12345678901234567890)
        (check (djot-ordered-list-style node) => "1)")))

    (test-case "task lists retain checked state and split on bullet change"
      (let (nodes (djot-container-children (string->djot "- [ ] a\n- [x] b\n+ [X] c")))
        (check (length nodes) => 2)
        (check (map djot-task-list-item-checked? (djot-container-children (car nodes))) => [#f #t])))

    (test-case "definition list separates term from definition blocks"
      (let* ((list (first-block ": orange\n\n  a fruit\n: banana"))
             (items (djot-container-children list))
             (first (djot-container-children (car items)))
             (second (djot-container-children (cadr items))))
        (check (djot-definition-list? list) => #t)
        (check (plain-inline-text (car first)) => "orange")
        (check (plain-inline-text (car (djot-container-children (cadr first)))) => "a fruit")
        (check (djot-container-children (cadr second)) => []))
      (let* ((doc (string->djot ": [x]: /url\n\n  term\n\n  definition"))
             (parts (djot-container-children
                     (car (djot-container-children
                            (car (djot-container-children doc)))))))
        (check (plain-inline-text (car parts)) => "term")
        (check (plain-inline-text (car (djot-container-children (cadr parts)))) => "definition")
        (check (length (djot-document-references doc)) => 1)))

    (test-case "bare definition marker has empty term and definition"
      (let (parts (djot-container-children (car (djot-container-children (first-block ":")))))
        (check (map djot-container-children parts) => [[] []])))

    (test-case "table header separator updates previous and subsequent rows"
      (let* ((table (first-block "|a|b|\n|:-|---:|\n|c|d|\n|-:|:-:|\n|e|f|"))
             (rows (cdr (djot-container-children table))))
        (check (map djot-row-head? rows) => [#t #t #f])
        (check (map djot-cell-alignment (djot-container-children (car rows))) => ['left 'right])
        (check (map djot-cell-alignment (djot-container-children (caddr rows))) => ['right 'center])))

    (test-case "space after leading pipe prevents separator recognition"
      (let (rows (cdr (djot-container-children (first-block "|a|\n| --- |"))))
        (check (map djot-row-head? rows) => [#f #f])))

    (test-case "escaped and verbatim pipes do not split cells"
      (let (row (cadr (djot-container-children (first-block "| just \\| `|` | two |"))))
        (check (length (djot-container-children row)) => 2)))

    (test-case "unclosed verbatim consuming final pipe prevents table recognition"
      (check (djot-paragraph? (first-block "| `a |")) => #t))

    (test-case "caption attaches to preceding table with or without blank line"
      (for-each
       (lambda ((gap : :string)) => :void
         (let* ((table (first-block (string-append "|a|\n" gap "^ caption\nlazy")))
                (caption (car (djot-container-children table))))
           (check (djot-caption? caption) => #t)
           (check (plain-inline-text caption) => "caption\nlazy")))
       ["" "\n"]))

    (test-case "unattached caption is a literal paragraph in its own container"
      (check (plain-inline-text (first-block "^ keep me")) => "^ keep me")
      (let (nodes (djot-container-children (string->djot "> |a|\n\n^ outside")))
        (check (plain-inline-text (cadr nodes)) => "^ outside")))

    (test-case "references collect attributes and concatenate indented URL chunks"
      (let* ((doc (string->djot "{title=hello}\n[ foo  bar ]: /one\n  two\n\n[foo bar]: /last\n"))
             (entry (car (djot-document-references doc))))
        (check (djot-container-children doc) => [])
        (check (car entry) => "foo bar")
        (check (djot-reference-destination (cdr entry)) => "/last"))
      (let (ref (cdar (djot-document-references (string->djot "{title=hello}\n[x]: /one\n  two"))))
        (check (djot-reference-destination ref) => "/onetwo")
        (check (djot-attribute-value (car (djot-node-attributes ref))) => "hello")))

    (test-case "reference URL chunks trim horizontal trailing whitespace only"
      (let* ((doc (string->djot "[a]: /one \t\r\n  two\t \r\n" source-locations: #t))
             (ref (cdar (djot-document-references doc))))
        (check (djot-reference-destination ref) => "/onetwo")
        (check (djot-source-range-end (djot-node-source ref)) => 22))
      (check (djot-paragraph? (first-block "[a]: /one two")) => #t)
      (check (djot-reference-destination
              (cdar (djot-document-references (string->djot "[a]: /one  "))))
             => "/one"))

    (test-case "reference definitions exceed procedure argument limits"
      (let* ((lines (string-concatenate (make-list 10000 "  a\n  b\n")))
             (document (string->djot (string-append "[r]: /\n" lines)))
             (reference (cdar (djot-document-references document))))
        (check (djot-reference-destination reference)
               => (string-append "/" (string-concatenate (make-list 10000 "ab"))))))

    (test-case "footnotes have nested blocks and lazy paragraph continuation"
      (let* ((doc (string->djot "[^n]: first\nlazy\n\n  > second\n\nbody"))
             (note (cdar (djot-document-footnotes doc))))
        (check (djot-footnote-label note) => "n")
        (check (plain-inline-text (car (djot-container-children note))) => "first\nlazy")
        (check (djot-block-quote? (cadr (djot-container-children note))) => #t)
        (check (plain-inline-text (car (djot-container-children doc))) => "body")))

    (test-case "block attributes accumulate in stable order and reset on blank"
      (let (attrs (djot-node-attributes (first-block "{#one .a}\n{k=v}\n{#two .b}\ntext")))
        (check (map djot-attribute-name attrs) => ["id" "class" "k"])
        (check (map djot-attribute-value attrs) => ["two" "a b" "v"]))
      (check (djot-node-attributes (first-block "{#id}\n\ntext")) => []))

    (test-case "multiline attributes and malformed attribute recovery"
      (let (attrs (djot-node-attributes (first-block "{#id\n  title=\"two words\"}\ntext")))
        (check (map djot-attribute-value attrs) => ["id" "two words"]))
      (check (plain-inline-text (first-block "{#id\nnot indented")) => "{#id\nnot indented")
      (check (plain-inline-text (first-block "{a=x\n# non-heading")) => "{a=x\n# non-heading")
      (check (plain-inline-text (first-block "{.bad*}\ntext")) => "{.bad*}\ntext")
      (check (djot-attribute-value
              (car (djot-node-attributes (first-block "{#kept}\n{bad\n# text"))))
             => "kept"))

    (test-case "attribute key assignment, shorthand merging, and quoted normalization"
      (for-each
       (lambda ((example : :list)) => :void
         (let (node (first-block (string-append (car example) "\ntext")))
           (check (map djot-attribute-value (djot-node-attributes node)) => (cadr example))))
       '(("{.a class=b}" ("b"))
         ("{class=a .b}" ("a b"))
         ("{.a}\n{class=b}" ("a b"))
         ("{class=\"\" .b}" ("b"))
         ("{key=\"a  b\"}" ("a b"))
         ("{key=\"a\n  b\"}" ("a b"))
         ("{key=\"a\t\tb\"}" ("a\t\tb"))
         ("{key=\"a\\$b\\@c\"}" ("a$b\\@c")))))

    (test-case "attribute class fragments and stacked blocks have bounded accumulation"
      (let* ((input (string-append (apply string-append (make-list 100 "{.x}\n")) "text"))
             (attrs (djot-node-attributes (first-block input))))
        (check (length attrs) => 1)
        (check (string-length (djot-attribute-value (car attrs))) => 199)))

    (test-case "lone CR is an original one-character line ending"
      (let* ((doc (string->djot "a\rb\r\r# c" source-locations: #t))
             (nodes (djot-container-children doc)))
        (check (plain-inline-text (car nodes)) => "a\nb")
        (check (djot-section? (cadr nodes)) => #t)
        (check (djot-heading? (car (djot-container-children (cadr nodes)))) => #t)
        (check (djot-source-range-start-line (djot-node-source (cadr nodes))) => 4)
        (check (djot-source-range-end-line (djot-node-source doc)) => 4)))

    (test-case "nested original character ranges survive prefixes and CRLF"
      (let* ((input (string-append "> - " (string (integer->char 128512)) "é\r\n>   next\r\n"))
             (doc (string->djot input source-locations: #t))
             (quote (car (djot-container-children doc)))
             (list (car (djot-container-children quote)))
             (item (car (djot-container-children list)))
             (para (car (djot-container-children item)))
             (children (djot-container-children para))
             (text (car children))
             (next (caddr children)))
        (check (djot-source-range-start (djot-node-source quote)) => 0)
        (check (djot-source-range-start (djot-node-source list)) => 2)
        (check (djot-source-range-start (djot-node-source text)) => 4)
        (check (djot-source-range-end (djot-node-source text)) => 6)
        (check (djot-source-range-start (djot-node-source next)) => 12)
        (check (djot-source-range-start-column (djot-node-source next)) => 5)
        (check (djot-source-range-end (djot-node-source quote)) => (string-length input))))

    (test-case "closing fence belongs to div but not its implicitly closed leaf"
      (let* ((div (car (djot-container-children (string->djot "::: note\ntext\n:::" source-locations: #t))))
             (para (car (djot-container-children div))))
        (check (djot-source-range-end (djot-node-source para)) => 14)
        (check (djot-source-range-end (djot-node-source div)) => 17)))

    (test-case "table span includes attached caption and empty quote includes consumed prefixes"
      (let* ((input "|a|\n\n^ caption")
             (table (car (djot-container-children (string->djot input source-locations: #t))))
             (quote (car (djot-container-children (string->djot ">\n>\n>" source-locations: #t)))))
        (check (djot-source-range-end (djot-node-source table)) => (string-length input))
        (check (djot-source-range-end (djot-node-source quote)) => 5)))

    (test-case "empty definition labels do not create empty footnotes"
      (let (doc (string->djot "[^]: /caret\n\n[]: /empty"))
        (check (djot-document-footnotes doc) => [])
        (check (map car (djot-document-references doc)) => ["^"])))

    (test-case "block nesting resource limit is distinct from malformed markup"
      (check (string->djot (string-append (apply string-append (make-list 512 "> ")) "x"))
             =>! DjotResourceError?)
      (check (djot-block-quote? (first-block (string-append (apply string-append (make-list 511 "> ")) "x"))) => #t))

    (test-case "combined block document retains all visible structures and metadata"
      (let (doc (string->djot
                 "# Title\n\n::: note\n> quote\n\n- [x] task\n\n|a|\n|--|\n\n^ caption\n:::\n\n[x]: /url\n\n[^n]: note"))
        (check (length (djot-container-children doc)) => 1)
        (let (section (car (djot-container-children doc)))
          (check (djot-section? section) => #t)
          (check (length (djot-container-children section)) => 2)
          (check (length (djot-container-children (cadr (djot-container-children section)))) => 3))
        (check (length (djot-document-references doc)) => 1)
        (check (length (djot-document-footnotes doc)) => 1)))))

(def djot-test
  (test-suite "Djot foundation"
    (test-case "empty document"
      (check (djot-container-children (string->djot "")) => [])
      (check (djot->html (string->djot "")) => "")
      (check (djot->sxml (string->djot "")) => '(*TOP*)))

    (test-case "blank lines do not create paragraphs"
      (check (djot->html (string->djot " \t\r\n\n  \n")) => ""))

    (test-case "paragraph closes at EOF without newline"
      (check (djot->html (string->djot "hello")) => "<p>hello</p>\n"))

    (test-case "paragraph closes at final newline"
      (check (djot->html (string->djot "hello\n")) => "<p>hello</p>\n"))

    (test-case "paragraph separation"
      (check (djot->html (string->djot "one\n \t\n\n two\n"))
             => "<p>one</p>\n<p>two</p>\n"))

    (test-case "soft breaks retain intermediate trailing spaces"
      (check (djot->html (string->djot "hi  \nthere  \n")) => "<p>hi  \nthere</p>\n"))

    (test-case "CRLF maps to a single soft break"
      (check (djot->html (string->djot "one\r\ntwo\r\n")) => "<p>one\ntwo</p>\n"))

    (test-case "indentation is insignificant in paragraphs"
      (check (djot->html (string->djot "  one\n\t two")) => "<p>one\ntwo</p>\n"))

    (test-case "HTML and entity-looking text are escaped, not interpreted"
      (check (djot->html (string->djot "<tag> &amp; &"))
             => "<p>&lt;tag&gt; &amp;amp; &amp;</p>\n"))

    (test-case "SXML carries text rather than preescaped HTML"
      (check (djot->sxml (string->djot "<&>")) => '(*TOP* (p (@) "<&>") "\n")))

    (test-case "semantic text and metadata"
      (let (document (string->djot "text"))
        (check (djot-textual-text (first-text document)) => "text")
        (check (djot-document-references document) => [])
        (check (djot-document-auto-references document) => [])
        (check (djot-document-footnotes document) => [])
        (check (djot-node-source document) => #f)
        (check (djot-node-source (first-text document)) => #f)))

    (test-case "source offsets count characters, not bytes or UTF-16 units"
      (let* ((emoji (string (integer->char 128512)))
             (input (string-append "  " emoji "é\r\n  x"))
             (document (string->djot input source-locations: #t))
             (text (first-text document))
             (source (djot-node-source text)))
        (check (djot-textual-text text) => (string-append emoji "é"))
        (check (djot-source-range-start source) => 2)
        (check (djot-source-range-end source) => 4)
        (check (djot-source-range-start-line source) => 1)
        (check (djot-source-range-start-column source) => 3)
        (check (djot-source-range-end-column source) => 5)
        (check (djot-source-range-end (djot-node-source document)) => 9)
        (check (djot-source-range-end-line (djot-node-source document)) => 2)
        (check (djot-source-range-end-column (djot-node-source document)) => 4)))

    (test-case "UTF-8 bytes and binary input port preserve non-BMP source locations"
      (let* ((input (string-append (string (integer->char 128512)) "é"))
             (bytes (string->utf8 input)))
        (for-each
         (lambda ((document : djot-document))
           (check (djot-textual-text (first-text document)) => input)
           (check (djot-source-range-end (djot-node-source (first-text document))) => 2)
           (check (string->utf8 (djot->html document))
                  => (string->utf8 (string-append "<p>" input "</p>\n"))))
         [(read-djot bytes source-locations: #t)
          (read-djot (open-input-u8vector bytes) source-locations: #t)])))

    (test-case "UTF-8 file input preserves non-BMP characters and locations"
      (call-with-temporary-file-name
       "djot-test-"
       (lambda ((path : :string)) => :string
         (let (input (string-append (string (integer->char 128512)) "é"))
           (with-buffered-writer (writer path) (writer.write-string-utf8 input))
           (let (document (read-djot [path: path] source-locations: #t))
             (check (djot-textual-text (first-text document)) => input)
             (check (djot-source-range-end (djot-node-source document)) => 2)))
         path)))

    (test-case "locations never enter SXML or HTML and rendering is repeatable"
      (let* ((input "  one\r\n two\n\nthree")
             (plain (string->djot input))
             (located (string->djot input source-locations: #t))
             (before (djot-node-source (first-text located))))
        (check (djot->sxml located) => (djot->sxml plain))
        (check (djot->html located) => (djot->html plain))
        (check (djot->html located) => (djot->html located))
        (check (djot-node-source (first-text located)) => before)))

    (test-case "std/io string and textual port input"
      (check (djot->html (read-djot "one")) => "<p>one</p>\n")
      (check (djot->html (read-djot (open-input-string "two"))) => "<p>two</p>\n"))

    (test-case "std/io buffered reader input"
      (with-buffered-reader (reader "hello")
        (check (djot->html (read-djot reader)) => "<p>hello</p>\n")))

    (test-case "output-first writer returns string or UTF-8 bytes"
      (let (document (string->djot "a & b"))
        (check (write-djot-html #f document) => "<p>a &amp; b</p>\n")
        (check (write-djot-html 'string document) => "<p>a &amp; b</p>\n")
        (check (write-djot-html 'u8vector document) => (string->utf8 "<p>a &amp; b</p>\n"))))

    (test-case "output port remains open"
      (let (port (open-output-string))
        (write-djot-html port (string->djot "hello"))
        (display "tail" port)
        (check (get-output-string port) => "<p>hello</p>\ntail")))

    (test-case "ordered string-keyed attributes and explicit override"
      (let* ((paragraph (make-djot-paragraph
                         [(make-djot-attribute "id" "explicit") (make-djot-attribute "title" "a<&\"")]
                         [(make-djot-attribute "id" "generated") (make-djot-attribute "class" "auto")]
                         #f [(make-djot-text [] [] #f "text")]))
             (document (make-djot-document [] [] #f [paragraph] [] [] [])))
        (check (djot->html document)
               => "<p class=\"auto\" id=\"explicit\" title=\"a&lt;&amp;&quot;\">text</p>\n")
        (check (length (djot-node-auto-attributes paragraph)) => 2)))

    (test-case "thematic breaks render as HTML void elements"
      (let (document (make-djot-document [] [] #f [(make-djot-thematic-break [] [] #f)] [] [] []))
        (check (djot->html document) => "<hr>\n")))

    (test-case "public constructors retain semantic properties"
      (let ((list (make-djot-ordered-list [] [] #f [] #t "(I)" 19))
            (raw (make-djot-raw-inline [] [] #f "<b>" "html"))
            (link (make-djot-link [] [] #f [] #f "reference")))
        (check (djot-ordered-list-start list) => 19)
        (check (djot-ordered-list-style list) => "(I)")
        (check (djot-ordered-list-tight? list) => #t)
        (check (djot-raw-inline-format raw) => "html")
        (check (djot-link-reference link) => "reference")))

    (test-case "modest long text and many paragraphs"
      (let* ((text (make-string 20000 #\a))
             (input (apply string-append (make-list 100 "a\n\n"))))
        (check (djot->html (string->djot text)) => (string-append "<p>" text "</p>\n"))
        (check (length (djot-container-children (string->djot input))) => 100)))

    (test-case "CRLF break ranges point into original input"
      (let* ((document (string->djot "a\r\nb\r\n" source-locations: #t))
             (paragraph (car (djot-container-children document)))
             (break (cadr (djot-container-children paragraph)))
             (source (djot-node-source break)))
        (check (djot-source-range-start source) => 1)
        (check (djot-source-range-end source) => 3)
        (check (djot-source-range-end-line source) => 2)
        (check (djot-source-range-end-column source) => 1)
        (check (djot-source-range-end-line (djot-node-source document)) => 3)))))

(def (generated-id (input : :string)) => :string
  (djot-attribute-value (car (djot-node-auto-attributes (first-block input)))))

(def (document-snapshot (document : djot-document)) => :string
  (let (port (open-output-string))
    (write document port)
    (get-output-string port)))

(def djot-render-test
  (test-suite "Djot finalization and rendering"
    (test-case "Unicode punctuation is available from the runtime without local externs"
      (check (char-set-contains? char-set:punctuation #\!) => #t)
      (check (char-set-contains? char-set:punctuation (integer->char #x2014)) => #t)
      (check (char-set-contains? char-set:punctuation #\a) => #f)
      (check-exception (char-set-contains? #f #\!) type-exception?))
    (test-case "Djot HTML uses shared SXML escaping for public ASTs"
      (let* ((payload "<&>\"'é🙂")
             (attributes [(make-djot-attribute "123" payload)
                          (make-djot-attribute "title" payload)])
             (document (make-djot-document [] [] #f
                         [(make-djot-paragraph [] [] #f
                            [(make-djot-text attributes [] #f payload)
                             (make-djot-image attributes [] #f
                               [(make-djot-text [] [] #f payload)] payload #f)
                             (make-djot-raw-inline [] [] #f "<b>raw</b>" "html")
                             (make-djot-hard-break [] [] #f)])
                          (make-djot-thematic-break [] [] #f)
                          (make-djot-heading [] [] #f [(make-djot-text [] [] #f payload)] 7)]
                         [] [] []))
             (port (open-output-string)))
        (write-sxml (cdr (djot->sxml document)) port: port xml?: #f indent: #f)
        (check (djot->html document) => (get-output-string port))
        (check (djot->html (make-djot-document [] [] #f
                            [(make-djot-paragraph [] [] #f
                               [(make-djot-text attributes [] #f payload)])] [] [] []))
               => "<p><span 123=\"&lt;&amp;&gt;&quot;'é🙂\" title=\"&lt;&amp;&gt;&quot;'é🙂\">&lt;&amp;&gt;\"'é🙂</span></p>\n")))
    (test-case "Djot HTML preserves customized SXML tag policies"
      (let ((document (string->djot "*x* & <tag>\n"))
            (port (open-output-string)))
        (parameterize ((current-html-void-tags '(p))
                       (current-html-raw-tags '(strong)))
          (write-sxml (cdr (djot->sxml document)) port: port xml?: #f indent: #f)
          (check (djot->html document) => (get-output-string port)))))
    (test-case "attribute index promotion preserves order replacement and classes"
      (check (attribute-values (first-inline
               "[x]{a=0 b=1 c=2 d=3 e=4 f=5 g=6 h=7 i=8 .one .two a=last}"))
             => [["a" "last"] ["b" "1"] ["c" "2"] ["d" "3"] ["e" "4"]
                 ["f" "5"] ["g" "6"] ["h" "7"] ["i" "8"] ["class" "one two"]]))
    (test-case "quoted attribute chunks retain normalization across slices and escapes"
      (check (djot->html (string->djot "[x]{title=\"é🙂  a\\\"b\\\\c\r\n  d\"}"))
             => "<p><span title=\"é🙂 a&quot;b\\c d\">x</span></p>\n")
      (let* ((value (make-string 20000 #\a))
             (document (string->djot (string-append "[x]{title=\"" value "\"}"))))
        (check (djot-attribute-value (car (djot-node-attributes (first-inline
                   (string-append "[x]{title=\"" value "\"}"))))) => value)
        (check (djot->html document)
               => (string-append "<p><span title=\"" value "\">x</span></p>\n"))))
    (test-case "attribute chunks and repeated classes exceed procedure argument limits"
      (let* ((value (string-concatenate (make-list 10000 "word ")))
             (input (string-append "[x]{title=\"" value "\"}")))
        (check (attribute-values (first-inline input)) => [["title" value]]))
      (let* ((groups (string-concatenate (make-list 10000 ".a ")))
             (value (string-append (string-concatenate (make-list 9999 "a ")) "a")))
        (check (attribute-values (first-inline (string-append "[x]{" groups "}")))
               => [["class" value]])))
    (test-case "heading text exceeds procedure argument limits"
      (let ((text (string-concatenate (make-list 10000 "a _b_ ")))
            (identifier (string-append (string-concatenate (make-list 9999 "a-b-")) "a-b")))
        (check (generated-id (string-append "# " text)) => identifier)))

    (test-case "image alternative text exceeds procedure argument limits"
      (let* ((text (string-concatenate (make-list 10000 "a _b_ ")))
             (alternative (string-concatenate (make-list 10000 "a b ")))
             (document (string->djot (string-append "![" text "](url)"))))
        (check (djot->html document)
               => (string-append "<p><img alt=\"" alternative "\" src=\"url\"></p>\n"))))

    (test-case "heading identifiers follow prose punctuation removal"
      (check (generated-id "# a+b") => "ab")
      (check (generated-id "# a:b;c") => "abc")
      (check (generated-id "# a_b-c") => "a_b-c")
      (check (generated-id "# a--b") => "a--b")
      (check (generated-id "# a—b") => "ab")
      (check (djot->html (string->djot "{id=\"\"}\n# empty"))
        => "<section id=\"empty\">\n<h1 id=\"\">empty</h1>\n</section>\n")
      (check (generated-id "# café、“你好”— é") => "café你好-é")
      (check (generated-id "# \"smart\" -- punctuation...") => "smart----punctuation")
      (check (generated-id (string-append "# " (string (integer->char 128512)) "！"))
             => (string (integer->char 128512))))

    (test-case "heading collisions empty identifiers and explicit identifiers"
      (let* ((doc (string->djot "# a+b\n\n# ab\n\n# !!!\n\n# !!!\n\n{#Keep:Me}\n# ab"))
             (sections (djot-container-children doc)))
        (check (map (lambda ((node : djot-node)) => :string
                      (djot-attribute-value (car (djot-node-auto-attributes node))))
                    (take sections 4)) => ["ab" "ab-1" "s-1" "s-2"])
        (check (djot-attribute-value (car (djot-node-attributes (list-ref sections 4)))) => "Keep:Me")
        (check (djot-reference-destination
                (cdr (assoc "ab" (djot-document-auto-references doc))))
               => "#ab-1")))

    (test-case "sections nest only in the document and retain heading classes"
      (check (djot->html (string->djot "{.title}\n# A\n\n## B\n\n> # C\n\n# D"))
        => "<section id=\"A\">\n<h1 class=\"title\">A</h1>\n<section id=\"B\">\n<h2>B</h2>\n<blockquote>\n<h1 id=\"C\">C</h1>\n</blockquote>\n</section>\n</section>\n<section id=\"D\">\n<h1>D</h1>\n</section>\n"))

    (test-case "section character ranges contain children without synthetic characters"
      (let* ((input (string-append "# " (string (integer->char 128512)) "\r\n\r\n## B\r\n\r\ntail"))
             (doc (string->djot input source-locations: #t))
             (section (car (djot-container-children doc)))
             (subsection (cadr (djot-container-children section))))
        (check (djot-source-range-start (djot-node-source section)) => 0)
        (check (djot-source-range-end (djot-node-source section)) => (string-length input))
        (check (djot-source-range-start (djot-node-source subsection)) => 7)
        (check (djot-source-range-start-line (djot-node-source subsection)) => 3)
        (check (djot->html doc) => (djot->html (string->djot input)))))

    (test-case "explicit references override automatic references and node attrs override definitions"
      (check (djot->html (string->djot "[A][]{title=own}\n\n{title=ref .shared}\n[A]: /explicit\n\n# A"))
        => "<p><a href=\"/explicit\" class=\"shared\" title=\"own\">A</a></p>\n<section id=\"A\">\n<h1>A</h1>\n</section>\n"))

    (test-case "later table separator cells accept ASCII padding but the first does not"
      (for-each
       (lambda ((padding : :string)) => :void
         (let (input (string-append "|a|b|\n|---|" padding ":---:|\n|c|d|"))
           (check (djot->html (string->djot input))
             => "<table>\n<tr>\n<th>a</th>\n<th style=\"text-align: center;\">b</th>\n</tr>\n<tr>\n<td>c</td>\n<td style=\"text-align: center;\">d</td>\n</tr>\n</table>\n")
           (check ((sxpath '(// th)) (djot->sxml (string->djot input source-locations: #t)))
             => '((th (@) "a") (th (@ (style "text-align: center;")) "b"))))
         (check ((sxpath '(// th))
                 (djot->sxml (string->djot (string-append "|a|b|\n|" padding "---|---|\n|c|d|"))))
           => []))
       [" " "\t"]))

    (test-case "link and image attributes override generated and inherited defaults once"
      (for-each
       (lambda ((example : :list)) => :void
         (let* ((doc (string->djot (car example)))
                (before (document-snapshot doc)))
           (check (djot->html doc) => (cadr example))
           (check ((sxpath '(// p)) (djot->sxml doc)) => (caddr example))
           (check (document-snapshot doc) => before)))
       '(("[x][r]\n\n{href=override}\n[r]: /original"
          "<p><a href=\"override\">x</a></p>\n"
          ((p (@) (a (@ (href "override")) "x"))))
         ("![x][r]\n\n{src=override alt=custom}\n[r]: /original"
          "<p><img alt=\"custom\" src=\"override\"></p>\n"
          ((p (@) (img (@ (alt "custom") (src "override"))))))
         ("[x][r]{href=own}\n\n{href=inherited}\n[r]: /original"
          "<p><a href=\"own\">x</a></p>\n"
          ((p (@) (a (@ (href "own")) "x"))))
         ("![x][r]{src=own alt=mine}\n\n{src=inherited alt=theirs}\n[r]: /original"
          "<p><img src=\"own\" alt=\"mine\"></p>\n"
          ((p (@) (img (@ (src "own") (alt "mine"))))))
         ("[x](/original){href=own}"
          "<p><a href=\"own\">x</a></p>\n"
          ((p (@) (a (@ (href "own")) "x"))))
         ("![x](/original){src=own alt=mine}"
          "<p><img src=\"own\" alt=\"mine\"></p>\n"
          ((p (@) (img (@ (src "own") (alt "mine")))))))))

    (test-case "generated attributes keep their first values without duplicate names"
      (for-each
       (lambda ((example : :list)) => :void
         (for-each
          (lambda ((located? : :boolean)) => :void
            (let* ((doc (string->djot (car example) source-locations: located?))
                   (before (document-snapshot doc)))
              (check (djot->html doc) => (cadr example))
              (check ((sxpath '(// a)) (djot->sxml doc)) => (caddr example))
              (check (djot->html doc) => (cadr example))
              (check (document-snapshot doc) => before)))
          '(#f #t)))
       '(("<https://example.org>{href=\"/override\" HREF=other title=keep .custom}"
          "<p><a href=\"https://example.org\" title=\"keep\" class=\"custom\">https://example.org</a></p>\n"
          ((a (@ (href "https://example.org") (title "keep") (class "custom")) "https://example.org")))
         ("<me@example.org>{href=\"/override\"}"
          "<p><a href=\"mailto:me@example.org\">me@example.org</a></p>\n"
          ((a (@ (href "mailto:me@example.org")) "me@example.org")))
         ("a[^n]{id=custom href=override role=custom ID=other HREF=other ROLE=other title=keep .custom} b[^n]{id=second href=override role=custom}\n\n[^n]: note"
          "<p>a<a id=\"fnref1\" href=\"#fn1\" role=\"doc-noteref\" title=\"keep\" class=\"custom\"><sup>1</sup></a> b<a href=\"#fn1\" role=\"doc-noteref\" id=\"second\"><sup>1</sup></a></p>\n<section role=\"doc-endnotes\">\n<hr>\n<ol>\n<li id=\"fn1\">\n<p>note<a href=\"#fnref1\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n</ol>\n</section>\n"
          ((a (@ (id "fnref1") (href "#fn1") (role "doc-noteref") (title "keep") (class "custom")) (sup "1"))
           (a (@ (href "#fn1") (role "doc-noteref") (id "second")) (sup "1"))
           (a (@ (href "#fnref1") (role "doc-backlink")) "↩︎"))))))

    (test-case "HTML attribute names differing only by ASCII case keep the first value"
      (let* ((doc (string->djot "x{title=first TITLE=second}"))
             (before (document-snapshot doc)))
        (check (djot->html doc) => "<p><span title=\"first\">x</span></p>\n")
        (check ((sxpath '(// span @ *)) (djot->sxml doc)) => '((title "first")))
        (check (document-snapshot doc) => before)))

    (test-case "HTML attribute case folding preserves distinct non-ASCII constructed names"
      (let* ((doc (string->djot "x"))
             (node (car (djot-container-children (car (djot-container-children doc))))))
        (djot-node-attributes-set! node
          [(make-djot-attribute "Ä" "first") (make-djot-attribute "ä" "second")])
        (let (before (document-snapshot doc))
          (check (djot->html doc) => "<p><span Ä=\"first\" ä=\"second\">x</span></p>\n")
          (check ((sxpath '(// span @ *)) (djot->sxml doc)) => '((Ä "first") (ä "second")))
          (check (document-snapshot doc) => before))))

    (test-case "arbitrary-level headings have canonical repeatable SXML tags"
      (for-each
       (lambda ((level : :fixnum)) => :void
         (let* ((input (string-append (make-string level #\#) " high"))
                (doc (string->djot input))
                (before (document-snapshot doc))
                (sxml (djot->sxml doc))
                (tag (string->symbol (string-append "h" (number->string level)))))
           (check (djot->sxml doc) => sxml)
           (check (djot->sxml (string->djot input source-locations: #t)) => sxml)
           (check ((sxpath ['// tag]) sxml) => [[tag ['@] "high"]])
           (check (document-snapshot doc) => before)))
       [8 32]))

    (test-case "SXML attributes support standard ID class and custom-name selectors"
      (let* ((input "{#example .note title=hello data-Custom=value}\ntext")
             (doc (string->djot input))
             (before (document-snapshot doc))
             (sxml (djot->sxml doc))
             (paragraph (car ((sxpath '(// p)) sxml))))
        (check (sxml-attributes paragraph)
          => '((id "example") (class "note") (title "hello") (data-Custom "value")))
        (check (sxml-attribute-e paragraph 'id) => "example")
        (check ((sxml-id? "example") paragraph) => #t)
        (check ((sxml-class? "note") paragraph) => #t)
        (check (sxml-attribute-e paragraph 'data-Custom) => "value")
        (check ((sxpath '(// p @ id)) sxml) => '((id "example")))
        (check ((sxpath '(// p @ data-Custom)) sxml) => '((data-Custom "value")))
        (check (djot->sxml doc) => sxml)
        (check (djot->sxml (string->djot input source-locations: #t)) => sxml)
        (check (djot->html doc)
          => "<p id=\"example\" class=\"note\" title=\"hello\" data-Custom=\"value\">text</p>\n")
        (check (attribute-values (car (djot-container-children doc)))
          => '(("id" "example") ("class" "note") ("title" "hello") ("data-Custom" "value")))
        (check (document-snapshot doc) => before)))

    (test-case "numeric and colon-ending attribute names stay literal and canonical"
      (for-each
       (lambda ((name : :string)) => :void
         (let* ((input (string-append "x{" name "=v}"))
                (doc (string->djot input))
                (located (string->djot input source-locations: #t))
                (before (document-snapshot doc))
                (located-before (document-snapshot located))
                (sxml (djot->sxml doc))
                (key (string->symbol name))
                (span (car ((sxpath '(// span)) sxml)))
                (html (string-append "<p><span " name "=\"v\">x</span></p>\n")))
           (check (sxml-attributes span) => [[key "v"]])
           (check (sxml-attribute-e span key) => "v")
           (check ((sxpath ['// 'span '@ key]) sxml) => [[key "v"]])
           (check (djot->sxml doc) => sxml)
           (check (djot->sxml located) => sxml)
           (check (djot->html doc) => html)
           (check (djot->html doc) => html)
           (check (djot->html located) => html)
           (check (djot->html located) => html)
           (check (attribute-values (car (djot-container-children (car (djot-container-children doc)))))
             => [[name "v"]])
           (check (document-snapshot doc) => before)
           (check (document-snapshot located) => located-before)))
       ["123" "a:"]))

    (test-case "direct task code and note SXML attributes use canonical names"
      (let (sxml (djot->sxml
                 (string->djot "- [x] task\n\n``` scheme\ncode\n```\n\na[^n]\n\n[^n]: note")))
        (check ((sxpath '(// input @ *)) sxml) => '((disabled "") (type "checkbox") (checked "")))
        (check ((sxpath '(// code @ class)) sxml) => '((class "language-scheme")))
        (check ((sxpath '(// section @ role)) sxml) => '((role "doc-endnotes")))
        (check ((sxpath '(// li @ id)) sxml) => '((id "fn1")))
        (check ((sxpath '(// a @ href)) sxml) => '((href "#fn1") (href "#fnref1")))
        (check ((sxpath '(// a @ role)) sxml) => '((role "doc-noteref") (role "doc-backlink")))))

    (test-case "HTML agrees with SXML across nested mixed content and notes"
      (for-each
       (lambda ((prefix : :string)) => :void
         (for-each
          (lambda ((body : :string)) => :void
            (for-each
             (lambda ((notes : :string)) => :void
               (for-each
                (lambda ((located? : :boolean)) => :void
                  (let* ((document (string->djot (string-append prefix body notes)
                                     source-locations: located?))
                         (before (document-snapshot document))
                         (sxml (djot->sxml document))
                         (port (open-output-string)))
                    (write-sxml (cdr sxml) port: port xml?: #f indent: #f)
                    (let (expected (get-output-string port))
                      (check (djot->html document) => expected)
                      (check (djot->html document) => expected))
                    (check (djot->sxml document) => sxml)
                    (check (document-snapshot document) => before)))
                '(#f #t)))
             ["" "\n\na[^a] b[^a] [^missing]\n\n[^a]: para *one*\n\n    para two [^b]\n\n[^b]: nested [^a]\n\n[^unused]: [^c]\n\n[^c]: unused discovery\n"
              "\n\nx[^n]\n\n[^n]: > quote ending\n"]))
          ["'quoted *bold* and _em_' & <tag> `raw <&`{=html}\n"
           "- [x] task *strong*\n- [ ] [link](u){.own}\n"
           "| a | b |\n|:-|--:|\n| é | 🙂 |\n\n^ caption\n"
           "![alt](image) [ref][r]\n\n[r]: /url {.ref title=\"a&b\"}\n"]))
       ["" "# Heading\n\n" "> quote\n\n" "######## unknown heading\n\n"]))

    (test-case "quoted attribute chunks preserve every continuation boundary"
      (for-each
       (lambda ((middle : :string)) => :void
         (let* ((input (string-append "{title=\"alpha " middle " omega\"}"))
                (size (string-length input))
                (whole (new-attribute-parser)))
           (feed-attributes! whole input 0 size)
           (let loop ((split 0 : :fixnum)) => :void
             (when (fx<= split size)
               (let (parts (new-attribute-parser))
                 (feed-attributes! parts input 0 split)
                 (feed-attributes! parts input split size)
                 (check (attribute-parser-state parts) => (attribute-parser-state whole))
                 (check (attribute-parser-attributes parts) => (attribute-parser-attributes whole)))
               (loop (fx+ split 1))))))
       ["beta gamma" " beta  gamma " "\r\n beta \n gamma" "\\\"beta\\\" gamma"
        "beta\\ gamma" "beta\\\r\n gamma" "é 🙂 名" "\tbeta\t gamma"]))

    (test-case "attribute feeds preserve first-unconsumed offsets across three chunks"
      (for-each
       (lambda ((input : :string)) => :void
         (let* ((size (string-length input))
                (whole (new-attribute-parser))
                (end (feed-attributes! whole input 0 size)))
           (let first ((i 0 : :fixnum)) => :void
             (when (fx<= i size)
               (let second ((j i : :fixnum)) => :void
                 (when (fx<= j size)
                   (let* ((parts (new-attribute-parser))
                          (a (feed-attributes! parts input 0 i))
                          (b (feed-attributes! parts input a j))
                          (c (feed-attributes! parts input b size)))
                     (check a => (min i end))
                     (check b => (min j end))
                     (check c => end)
                     (check (attribute-parser-state parts) => (attribute-parser-state whole))
                     (check (attribute-parser-attributes parts) => (attribute-parser-attributes whole)))
                   (second (fx+ j 1))))
               (first (fx+ i 1))))))
       ["{a=\"x y\"}tail" "{a=\"x\" ?}tail" "{a=\"x\\" "{a=\"é🙂\r\n b\\\"c\"}tail"
        "{.one #é a=bare %comment%}tail" "{a=\"x  y\\\r\n z\" b=2}tail"]))

    (test-case "failed attribute replay suppresses nested groups but releases later spans"
      (for-each
       (lambda ((located? : :boolean)) => :void
         (check (djot->html (string->djot "[x]{a=\"bad {.hidden}\" ?} [y]{.good}"
                             source-locations: located?))
           => "<p>[x]{a=“bad {.hidden}” ?} <span class=\"good\">y</span></p>\n")
         (check (djot->html (string->djot "{a=\"bad {.hidden}\" ?} [y]{.good}"
                             source-locations: located?))
           => "<p>{a=“bad {.hidden}” ?} <span class=\"good\">y</span></p>\n")
         (check (djot->html (string->djot "[x]{a=\"bad\r\n {.hidden}\" ?} [y]{.good}"
                             source-locations: located?))
           => "<p>[x]{a=“bad\n{.hidden}” ?} <span class=\"good\">y</span></p>\n")
         (check (djot->html (string->djot "{a=\"bad\n {.hidden}\" ?}\n\n[y]{.good}"
                             source-locations: located?))
           => "<p>{a=“bad\n{.hidden}” ?}</p>\n<p><span class=\"good\">y</span></p>\n"))
       '(#f #t)))

    (test-case "multiline attributes preserve normalized values and Unicode ranges"
      (for-each
       (lambda ((ending : :string)) => :void
         (let* ((input (string-append "> [é 🙂]{title=\"one" ending "> two\\" ending "> three\"}"))
                (document (string->djot input source-locations: #t))
                (port (open-output-string)))
           (write-sxml (cdr (djot->sxml document)) port: port xml?: #f indent: #f)
           (check (djot->html document) => (get-output-string port))
           (check (djot->html document) => (djot->html (string->djot input)))))
       ["\n" "\r\n"]))

    (test-case "heading identifiers reserve parent IDs before children and finalize after children"
      (check (djot->html (string->djot "{#x}\n> # x\n\n# x"))
        => "<blockquote id=\"x\">\n<h1 id=\"x-1\">x</h1>\n</blockquote>\n<section id=\"x-2\">\n<h1>x</h1>\n</section>\n")
      (check (djot->html (string->djot "# [x]{#x}\n\n# x"))
        => "<section id=\"x-1\">\n<h1><span id=\"x\">x</span></h1>\n</section>\n<section id=\"x-2\">\n<h1>x</h1>\n</section>\n")
      (check (generated-id "{id=\"\"}\n# []{id=\"\"}") => "s-1"))

    (test-case "late explicit references suppress automatic references even in overwritten notes"
      (for-each
       (lambda ((input : :string)) => :void
         (let (doc (string->djot input))
           (check (djot-document-auto-references doc) => [])
           (check (map car (djot-document-references doc)) => ["x" "y"])
           (check (map (lambda ((entry : :pair)) => :string
                         (djot-reference-destination (cdr entry)))
                       (djot-document-references doc)) => ["/last" "/y"])))
       ["# x\n\n[x]: /first\n\n[y]: /y\n\n[x]: /last"
        "# x\n\n[^a]: [x]: /first\n\n  [y]: /y\n\n  [x]: /last\n\n[^a]: replacement"]))

    (test-case "winning normalized notes retain first entry order and last heading values"
      (let* ((input "[^ A  B ]: # old\n\n[^z]: # x\n\n[^A B]: # x\n\n# x")
             (doc (string->djot input source-locations: #t))
             (notes (djot-document-footnotes doc)))
        (check (map car notes) => ["A B" "z"])
        (check (map (lambda ((entry : :pair)) => :string
                      (let (heading (car (djot-container-children (cdr entry))))
                        (djot-attribute-value (car (djot-node-auto-attributes heading)))))
                    notes) => ["x-1" "x-2"])
        (check (map (lambda ((entry : :pair)) => :fixnum
                      (djot-source-range-start (djot-node-source (cdr entry)))) notes)
          => [29 18])
        (check (map car (djot-document-auto-references doc)) => ["x"])))

    (test-case "nested note survives overwritten parent without reserving discarded identifiers"
      (let* ((input "{#x-1}\n[^a]: # x\n\n  [^b]: # x\n\n[^a]: replacement\n\n# x")
             (doc (string->djot input))
             (notes (djot-document-footnotes doc))
             (heading (car (djot-container-children (cdar notes)))))
        (check (map car notes) => ["b" "a"])
        (check (djot-attribute-value (car (djot-node-auto-attributes heading))) => "x-1")
        (check (plain-inline-text (car (djot-container-children (cdadr notes)))) => "replacement")
        (check (length (djot-container-children (cdadr notes))) => 1)))

    (test-case "visible headings precede winning footnote root IDs and descendant headings"
      (let* ((input "{#x-1}\n[^a]: # x\n\n# x")
             (doc (string->djot input))
             (note (cdar (djot-document-footnotes doc)))
             (heading (car (djot-container-children note))))
        (check (attribute-values note) => [["id" "x-1"]])
        (check (djot-attribute-value (car (djot-node-auto-attributes heading))) => "x-2")
        (check (generated-id input) => "x")))

    (test-case "definition finalization preserves Unicode ranges and caller-owned AST on reuse"
      (let* ((input "# [é🙂]{#é🙂}\r\n\r\n[^n]: # é🙂\r\n")
             (doc (string->djot input source-locations: #t))
             (before (document-snapshot doc))
             (section (car (djot-container-children doc)))
             (heading (car (djot-container-children section)))
             (span (car (djot-container-children heading)))
             (source (djot-node-source span)))
        (check [(djot-source-range-start source) (djot-source-range-end source)] => [2 6])
        (check (djot-source-range-end (djot-node-source doc)) => (string-length input))
        (check (djot->html doc) => (djot->html (string->djot input)))
        (djot->sxml doc)
        (string->djot input)
        (check (document-snapshot doc) => before)))

    (test-case "removed definitions retain pre-removal depth checks but not section depth"
      (let ((allowed (string-append "# A\n\n[^n]: "
                       (apply string-append (make-list 510 "> ")) "x"))
            (excess (string-append "[^n]: "
                      (apply string-append (make-list 510 "> ")) "_x_\n\n[^n]: replacement")))
        (check (djot-document? (string->djot allowed)) => #t)
        (check (resource-error-details? (lambda () (string->djot excess))
                 "Djot nesting limit exceeded") => #t)))

    (test-case "unknown headings preserve SXML structure and following output"
      (let* ((document (string->djot "_before_\n\n# head\n\n_after_"))
             (section (cadr (djot-container-children document)))
             (heading (car (djot-container-children section)))
             (port (open-output-string)))
        (djot-heading-level-set! heading 9)
        (write-sxml (cdr (djot->sxml document)) port: port xml?: #f indent: #f)
        (check (djot->html document) => (get-output-string port))))

    (test-case "failed rendering does not write a partial document to the caller's port"
      (let* ((document (string->djot "good\n\nbad"))
             (port (open-output-string)))
        (display "prefix" port)
        (djot-container-children-set! document
          (append (djot-container-children document) [(make-djot-reference [] [] #f "x" "y")]))
        (check-exception (write-djot-html port document) error-object?)
        (check (get-output-string port) => "prefix")))

    (test-case "undefined references remain links and images without destinations"
      (check (djot->html (string->djot "[x][missing] ![alt][missing]"))
        => "<p><a>x</a> <img></p>\n"))

    (test-case "notes are indexed by first use with one reference id and immutable backlinks"
      (let* ((doc (string->djot "a[^n] b[^n]\n\n[^n]: note"))
             (before (document-snapshot doc)))
        (check (djot->html doc)
          => "<p>a<a id=\"fnref1\" href=\"#fn1\" role=\"doc-noteref\"><sup>1</sup></a> b<a href=\"#fn1\" role=\"doc-noteref\"><sup>1</sup></a></p>\n<section role=\"doc-endnotes\">\n<hr>\n<ol>\n<li id=\"fn1\">\n<p>note<a href=\"#fnref1\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n</ol>\n</section>\n")
        (check (djot->html doc) => (djot->html doc))
        (check (document-snapshot doc) => before)))

    (test-case "unused footnote references never make notes reachable"
      (for-each
       (lambda ((input : :string)) => :void
         (for-each
          (lambda ((located? : :boolean)) => :void
            (let* ((doc (string->djot input source-locations: located?))
                   (before (document-snapshot doc))
                   (expected "<p>text<a id=\"fnref1\" href=\"#fn1\" role=\"doc-noteref\"><sup>1</sup></a></p>\n<section role=\"doc-endnotes\">\n<hr>\n<ol>\n<li id=\"fn1\">\n<p>used<a href=\"#fnref1\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n</ol>\n</section>\n"))
              (check (djot->html doc) => expected)
              (check ((sxpath '(// li @ id)) (djot->sxml doc)) => '((id "fn1")))
              (check ((sxpath '(// a @ href)) (djot->sxml doc))
                => '((href "#fn1") (href "#fnref1")))
              (check (djot->html doc) => expected)
              (check (document-snapshot doc) => before)))
          '(#f #t)))
       ["text[^used]\n\n[^unused]: hidden[^extra]\n\n[^used]: used\n\n[^extra]: leaked"
        "text[^used]\n\n[^unused]: hidden[^unused]\n\n[^used]: used"
        "text[^used]\n\n[^unused]: hidden[^extra]\n\n[^used]: used\n\n[^extra]: leaked[^unused]"])
      (check (djot->html (string->djot "text\n\n[^a]: [^b]\n\n[^b]: [^a]")) => "<p>text</p>\n"))

    (test-case "reachable nested notes follow first-use order and cycles terminate"
      (for-each
       (lambda ((located? : :boolean)) => :void
         (let* ((input "text[^a] then[^d]\n\n[^b]: nested[^c]\n\n[^c]: leaf[^a]\n\n[^d]: second\n\n[^a]: first[^b]")
                (doc (string->djot input source-locations: located?))
                (before (document-snapshot doc))
                (expected
                 (string-append
                  "<p>text<a id=\"fnref1\" href=\"#fn1\" role=\"doc-noteref\"><sup>1</sup></a> then<a id=\"fnref2\" href=\"#fn2\" role=\"doc-noteref\"><sup>2</sup></a></p>\n<section role=\"doc-endnotes\">\n<hr>\n<ol>\n"
                  "<li id=\"fn1\">\n<p>first<a id=\"fnref3\" href=\"#fn3\" role=\"doc-noteref\"><sup>3</sup></a><a href=\"#fnref1\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n"
                  "<li id=\"fn2\">\n<p>second<a href=\"#fnref2\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n"
                  "<li id=\"fn3\">\n<p>nested<a id=\"fnref4\" href=\"#fn4\" role=\"doc-noteref\"><sup>4</sup></a><a href=\"#fnref3\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n"
                  "<li id=\"fn4\">\n<p>leaf<a href=\"#fn1\" role=\"doc-noteref\"><sup>1</sup></a><a href=\"#fnref4\" role=\"doc-backlink\">↩︎</a></p>\n</li>\n"
                  "</ol>\n</section>\n"))
                (sxml (djot->sxml doc)))
           (check (djot->html doc) => expected)
           (check ((sxpath '(// li @ id)) sxml)
             => '((id "fn1") (id "fn2") (id "fn3") (id "fn4")))
           (check ((sxpath '(// a @ id)) sxml)
             => '((id "fnref1") (id "fnref2") (id "fnref3") (id "fnref4")))
           (check ((sxpath '(// a @ href)) sxml)
             => '((href "#fn1") (href "#fn2") (href "#fn3") (href "#fnref1")
                  (href "#fnref2") (href "#fn4") (href "#fnref3") (href "#fn1") (href "#fnref4")))
           (check (djot->sxml doc) => sxml)
           (check (djot->html doc) => expected)
           (check (document-snapshot doc) => before)))
       '(#f #t)))

    (test-case "reachable undefined notes retain placeholder backlinks"
      (let* ((doc (string->djot "text[^a]\n\n[^a]: missing[^undefined]"))
             (sxml (djot->sxml doc)))
        (check ((sxpath '(// li @ id)) sxml) => '((id "fn1") (id "fn2")))
        (check ((sxpath '(// li)) sxml)
          => '((li (@ (id "fn1")) "\n"
                (p (@) "missing" (a (@ (id "fnref2") (href "#fn2") (role "doc-noteref")) (sup "2"))
                   (a (@ (href "#fnref1") (role "doc-backlink")) "↩︎")) "\n")
               (li (@ (id "fn2")) "\n" (p (a (@ (href "#fnref2") (role "doc-backlink")) "↩︎")) "\n")))))

    (test-case "raw HTML alone bypasses ordinary escaping and rendering is intentionally unsanitized"
      (check (djot->html (string->djot "<b> &amp; `a<&` `ignored`{=latex} `<b>raw</b>`{=html}"))
        => "<p>&lt;b&gt; &amp;amp; <code>a&lt;&amp;</code>  <b>raw</b></p>\n")
      (check (djot->html (string->djot "[x](javascript:alert(1)){onclick=run}"))
        => "<p><a href=\"javascript:alert(1)\" onclick=\"run\">x</a></p>\n"))

    (test-case "formatting math symbols and literal entities render semantically"
      (check (djot->html (string->djot "_e_ *s* {=m=} {+i+} {-d-} x^2^ H~2~O $`x<y` :yes: a\\ b"))
        => "<p><em>e</em> <strong>s</strong> <mark>m</mark> <ins>i</ins> <del>d</del> x<sup>2</sup> H<sub>2</sub>O <span class=\"math inline\">\\(x&lt;y\\)</span> :yes: a&nbsp;b</p>\n"))

    (test-case "all representative render paths are location neutral repeatable and nonmutating"
      (for-each
       (lambda ((input : :string)) => :void
         (let* ((doc (string->djot input source-locations: #t))
                (before (document-snapshot doc))
                (html (djot->html doc)))
           (check html => (djot->html (string->djot input)))
           (check (djot->html doc) => html)
           (check (document-snapshot doc) => before)))
       ["# A\r\n\r\n## B\r\n\r\n- [x] *task*"
        "::: note\n> quote\n\n| a | b |\n|:-|--:|\n| 1 | 2 |\n\n^ cap\n:::"
        "a[^a]\n\n[^a]: [^b]\n\n[^b]: [^a]"
        "[x][constructor] ![alt](x.png) <a@b.c>\n\n[constructor]: /url"
        "```` scheme\n<&\n````\n\n``` =html\n<hr>\n```"
        "######## high\n\ntext"]))

    (test-case "renderer enforces public constructed-AST nesting without rejecting boundary"
      (let* ((doc (string->djot (string-append (apply string-append (make-list 511 "> ")) "x")))
             (children (djot-container-children doc)))
        (check (string? (djot->html doc)) => #t)
        (djot-container-children-set! doc [(make-djot-block-quote [] [] #f children)])
        (check-exception (djot->html doc) DjotResourceError?)))

    (test-case "image alternative text and unreferenced notes obey rendering resource limits"
      (let* ((doc (string->djot "![x](url)"))
             (image (car (djot-container-children (car (djot-container-children doc))))))
        (djot-container-children-set! image [image])
        (check-exception (djot->html doc) DjotResourceError?))
      (let* ((doc (string->djot "[^n]: note"))
             (note (cdar (djot-document-footnotes doc))))
        (djot-container-children-set! note [note])
        (check-exception (djot->html doc) DjotResourceError?)))

    (test-case "standard input and output follow current ports without closing them"
      (let ((input (open-input-string "# stdin"))
            (output (open-output-string)))
        (parameterize ((current-input-port input)
                       (current-output-port output))
          (write-djot-html #t (read-djot #t)))
        (display "tail" output)
        (check (get-output-string output)
          => "<section id=\"stdin\">\n<h1>stdin</h1>\n</section>\ntail")
        (check (eof-object? (read-char input)) => #t)))

    (test-case "generated sections share the document-wide nesting budget"
      (let* ((body (string-append (apply string-append (make-list 510 "> ")) "x"))
             (allowed (string-append "# A\n\n" body))
             (excess (string-append "# A\n\n> " body)))
        (check (string? (djot->html (string->djot allowed))) => #t)
        (check-exception (string->djot excess) DjotResourceError?)))

    (test-case "many duplicate headings and references resolve without suffix rescanning"
      (let* ((input (apply string-append (make-list 200 "# Heading\n\n[Heading][]\n\n")))
             (doc (string->djot input)))
        (check (length (djot-container-children doc)) => 200)
        (check (length (djot-document-auto-references doc)) => 1)
        (check (string? (djot->html doc)) => #t)))))
