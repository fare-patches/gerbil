;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML conformance of :std/text/markup/html against upstream test data,
;;; which is not in this tree: the html5lib tokenizer tests, the WPT tree
;;; construction tests (html5lib format, scripted_*.dat excluded), and the
;;; write-html round trip of those trees, each written and read again in
;;; the same way. Pinned revisions:
;;;   html5lib-tests https://github.com/html5lib/html5lib-tests
;;;     commit c777c408b61078ea2eb4acefc2535f54dbc8b28a
;;;   wpt https://github.com/web-platform-tests/wpt
;;;     commit 260bb4c1d97dd0d582164952bea9b31dbe56a60a
;;; To check them out:
;;;   git clone https://github.com/html5lib/html5lib-tests
;;;   git -C html5lib-tests checkout c777c408b61078ea2eb4acefc2535f54dbc8b28a
;;;   git clone --filter=blob:none --sparse https://github.com/web-platform-tests/wpt
;;;   git -C wpt sparse-checkout set html/syntax/parsing/resources
;;;   git -C wpt checkout 260bb4c1d97dd0d582164952bea9b31dbe56a60a
;;; With this checkout's stdlib built, compile from its root:
;;;   out=$(mktemp -d)
;;;   gxc -O -exe -d "$out" -o "$out/html-conformance" src/std/text/markup/html-conformance.ss
;;; Use ./run.sh gxc instead of gxc in a local build environment.
;;; Usage: "$out/html-conformance" HTML5LIB-TESTS-DIR WPT-DIR
;;; At those revisions it prints:
;;;   html5lib tokenizer tests: 7045 passed, 0 failed, 8 skipped
;;;   tree construction tests: 1963 passed, 0 failed, 4 skipped
;;;   write-html round trip: 1950 passed, 0 failed, 17 skipped
;;; It exits with status 1 when a test fails or when the tests it skips
;;; are not exactly those listed below by case id: FILE#N is the Nth test
;;; of FILE, followed by the initial tokenizer state for a tokenizer test
;;; run in several.
(import :std/error
        :std/encoding/json
        (only-in :std/string/misc string-trim string-trim-prefix)
        ./xml/types
        ./html/types
        ./html/reader
        ./html/writer
        ./html/tokenizer)
(export main)

;;; skipped tests

;;; Tokenizer tests not run, by reason.
(def tokenizer-skips
  '(("xmlViolationTests: they expect the infoset coercion of §13.2.9, not tokens"
     "xmlViolation.test#x1" "xmlViolation.test#x2" "xmlViolation.test#x3"
     "xmlViolation.test#x4")
    ("the input holds a lone surrogate (U+D800, U+DFFF), which no Gerbil string holds"
     "unicodeCharsProblematic.test#1" "unicodeCharsProblematic.test#2"
     "unicodeCharsProblematic.test#3" "unicodeCharsProblematic.test#4")))

;;; Tree construction tests not run, by reason: (id data) entries.
(def tree-skips
  '(("selectedcontent cloning is a DOM element insertion step, not tree construction"
     ("webkit02.dat#45" "<select><button><selectedcontent></button><option>X")
     ("webkit02.dat#46" "<select><button><selectedcontent></button><option>x<i>i<b>ib</i>b")
     ("webkit02.dat#47" "<select><button><selectedcontent></button><option>X<option>Y")
     ("webkit02.dat#48" "<select><button><selectedcontent></button><option>X<option selected>Y"))))

;;; Trees not written and read back, by reason: (id data) entries.
(def round-trip-skips
  (append
   tree-skips
   '(("the adoption agency or foster parenting nests elements as the parser does not from markup (Go renderTestBlacklist)"
      ("adoption02.dat#4" "<a><table><marquee></table><a>")
      ("template.dat#115" "<template><a><table><a>")
      ("tests1.dat#31" "<a><table><td><a><table></table><a></tr><a></table><b>X</b>C<a>Y")
      ("tests1.dat#78" "<a href=\"blah\">aba<table><a href=\"foo\">br<tr><td></td></tr>x</table>aoe")
      ("tests1.dat#91" "<a><table><a></table><p><a><div><a>")
      ("tests1.dat#102" "<a><table><td><a><table></table><a></tr><a></table><a>")
      ("tests20.dat#42" "<p><table></p>")
      ("tests26.dat#3" "<!DOCTYPE html><body><b><nobr>1<table><nobr></b><i><nobr>2<nobr></i>3")
      ("tests16.dat#197" "<!doctype html><form><table></form><form></table></form>"))
     ("CR from a character reference is written raw (Djot parity) and reads back as LF"
      ("plain-text-unsafe.dat#1" "FOO&#x000D;ZOO"))
     ("a fragment in a raw text or PLAINTEXT context: write-html escapes text for an HTML context"
      ("tests4.dat#4" "this is &#x0043;DATA inside a <style> element")
      ("tests4.dat#5" "</plaintext>")
      ("tests4.dat#9" "<!-- inside </script> -->")))))

;;; Trees write-html rejects, by reason: (data context scripting?) entries,
;;; scripting? any for both. Their round trip passes when write-html raises
;;; ContractViolation.
(def writer-rejections
  '(("plaintext is not the last node or has element children: the parser reads everything after <plaintext> as its text"
     ("<!doctype html><table><plaintext></plaintext>" #f any)
     ("<!doctype html><table><tbody><plaintext></plaintext>" #f any)
     ("<!doctype html><table><tbody><tr><plaintext></plaintext>" #f any)
     ("<!doctype html><table><colgroup><plaintext></plaintext>" #f any)
     ("<!doctype html><table><select><plaintext>a<caption>b" #f any)
     ("<!doctype html><template><plaintext>a</template>b" #f any)
     ("<!doctype html><p><a><plaintext>b" #f any)
     ("<table><plaintext><td>" #f any))
    ("scripting off: data inside noscript contains </noscript, which a scripting parser reads as its end"
     ("<head><noscript><noframes>XXX</noscript></noframes></noscript>" #f #f)
     ("<!doctype html><noscript><!--<noscript></noscript>--></noscript>" #f #f)
     ("<!doctype html><noscript><!--</noscript>X<noscript>--></noscript>" #f #f)
     ("<noscript><!--<noscript></noscript>--></noscript>" #f #f)
     ("<noscript><!--</noscript>X<noscript>--></noscript>" #f #f)
     ("<noscript><!--</noscript>--></noscript>" #f #f))))

;;; Script text ending at end of input in the double escaped state: no end
;;; tag written after it ends the script (Go renderTestBlacklist).
(def open-double-escaped-scripts
  (append
   (map (cut string-append "<!doctype html><script><!--<script " <>)
        ["" "<" "<a" "</" "</s" "</script" "</scripta" "-" "-a" "-<" "--" "--a" "--<"])
   (map (cut string-append "<script><!--<script " <>)
        ["" "<" "<a" "</" "</s" "</script" "</scripta" "-" "-a" "--" "--a"])))

;;; The ids of the entries of skips, a list of (reason entry ...), each
;;; entry an id or (id . details).
(def (skip-ids (skips : :list)) => :list
  (apply append (map (lambda (group)
                       (map (lambda (entry) (if (pair? entry) (car entry) entry)) (cdr group)))
                     skips)))

;;; Checks that skipped, the ids of the tests a stage skipped, are those of
;;; skips; prints the differences.
(def (check-skips (label   : :string)
                  (skips   : :list)
                  (skipped : :list)) => :boolean
  (let* ((expected (skip-ids skips))
         (unexpected (filter (lambda (id) (not (member id expected))) skipped))
         (missing (filter (lambda (id) (not (member id skipped))) expected)))
    (for-each (lambda (id) (displayln label ": skipped, but not listed: " id)) unexpected)
    (for-each (lambda (id) (displayln label ": listed, but not skipped: " id)) missing)
    (and (null? unexpected) (null? missing))))

;;; The results of the tests of one file: the count passed, the ids of the
;;; tests skipped and the failures, in test order.
(defstruct FileResults
  ((file     :- :string)
   (passed   :- :fixnum)
   (skipped  :- :list)
   (failures :- :list))
  final: #t)

;;; Prints the counts of results, a list of FileResults, per file and in
;;; total, and the first limit failures; returns the skipped ids and the
;;; failure count.
(def (report (label   : :string)
             (results : :list)
             (limit   : :fixnum)
             (show    : :procedure)) => :values
  (let ((skipped (apply append (map (lambda ((result :- FileResults)) result.skipped) results)))
        (failures (apply append (map (lambda ((result :- FileResults)) result.failures) results))))
    (for-each (lambda ((result :- FileResults))
                (displayln result.file ": " result.passed " passed, "
                           (length result.failures) " failed, "
                           (length result.skipped) " skipped"))
              results)
    (displayln label ": "
               (apply + (map (lambda ((result :- FileResults)) result.passed) results))
               " passed, " (length failures) " failed, " (length skipped) " skipped")
    (let loop ((rest failures) (k 0))
      (when (and (pair? rest) (fx< k limit))
        (show (car rest))
        (loop (cdr rest) (fx+ k 1))))
    (values skipped (length failures))))

(def (sorted-files (dir       : :string)
                   (extension : :string)
                   (keep?     : :procedure)) => :list
  (list-sort string<?
             (filter (lambda (file) (and (equal? (path-extension file) extension) (keep? file)))
                     (directory-files dir))))

;;; tokenizer tests

;;; The tokens of input as html5lib writes them, adjacent characters merged:
;;; ("Character" data) ("StartTag" name ((name . value) ...) [#t])
;;; ("EndTag" name) ("Comment" data) ("ProcessingInstruction" target data)
;;; ("DOCTYPE" name public-id system-id correct?), #f for a missing name or
;;; identifier.
(def (tokens (input          : :string)
             (state          : :fixnum)
             (last-start-tag :? :string)) => :list
  (let (tz (make-html-tokenizer input))
    (html-tokenizer-state-set! tz state)
    (html-tokenizer-last-start-tag-set! tz last-start-tag)
    (let loop ((out '()))
      (def (characters (data : :string)) => :list
        (if (and (pair? out) (equal? (caar out) "Character"))
          (loop (cons ["Character" (string-append (cadar out) data)] (cdr out)))
          (loop (cons ["Character" data] out))))
      (let (kind (html-tokenizer-next! tz))
        (cond
         ((fx= kind html-token-eof) (reverse out))
         ((fx= kind html-token-characters) (characters (html-token-text tz)))
         ((fx= kind html-token-null-character) (characters (string #\nul)))
         ((fx= kind html-token-start-tag)
          (loop (cons (append ["StartTag" (html-token-tag-name tz) (html-token-attributes tz)]
                              (if (html-token-self-closing? tz) [#t] []))
                      out)))
         ((fx= kind html-token-end-tag) (loop (cons ["EndTag" (html-token-tag-name tz)] out)))
         ((fx= kind html-token-comment) (loop (cons ["Comment" (html-token-data tz)] out)))
         ((fx= kind html-token-pi)
          (loop (cons ["ProcessingInstruction" (html-token-target tz) (html-token-data tz)] out)))
         (else
          (loop (cons ["DOCTYPE" (html-token-doctype-name tz)
                       (html-token-doctype-public-id tz) (html-token-doctype-system-id tz)
                       (not (html-token-force-quirks? tz))]
                      out))))))))

;;; str with the \uXXXX escapes of a doubleEscaped test replaced; #f when
;;; one is a lone surrogate, which no string holds.
(def (unescape (str : :string)) => (Maybe :string)
  (let loop ((k 0) (out '()))
    (cond
     ((fx>= k (string-length str)) (list->string (reverse out)))
     ((and (char=? (string-ref str k) #\\)
           (fx<= (fx+ k 6) (string-length str))
           (char=? (string-ref str (fx+ k 1)) #\u))
      (let (code (string->number (substring str (fx+ k 2) (fx+ k 6)) 16))
        (and (not (and (fx>= code #xd800) (fx<= code #xdfff)))
             (loop (fx+ k 6) (cons (integer->char code) out)))))
     (else (loop (fx+ k 1) (cons (string-ref str k) out))))))

;;; The JSON null, read as #!void, as #f.
(def (json-null->false (x : :t)) => :t
  (if (void? x) #f x))

;;; An expected token in the form of tokens; strings unescaped with escape,
;;; to #f for a lone surrogate.
(def (expected-token (token  : :list)
                     (escape : :procedure)) => :list
  (let (kind (car token))
    (cond
     ((equal? kind "StartTag")
      (append ["StartTag" (escape (cadr token))
               (map (lambda (pair) (cons (escape (car pair)) (escape (cdr pair))))
                    (hash->list (caddr token)))]
              (if (and (pair? (cdddr token)) (cadddr token)) [#t] [])))
     ((equal? kind "DOCTYPE")
      ["DOCTYPE" (json-null->false (cadr token))
       (json-null->false (caddr token)) (json-null->false (cadddr token))
       (car (cddddr token))])
     (else (cons kind (map escape (cdr token)))))))

;;; Attributes in name order, so that attribute objects compare.
(def (normalize (tokens : :list)) => :list
  (map (lambda (token)
         (if (equal? (car token) "StartTag")
           (cons* (car token) (cadr token)
                  (list-sort (lambda (a b) (string<? (car a) (car b))) (caddr token))
                  (cdddr token))
           token))
       tokens))

(def (merge-characters (tokens : :list)) => :list
  (let loop ((rest tokens) (out '()))
    (cond
     ((null? rest) (reverse out))
     ((and (equal? (caar rest) "Character") (pair? out) (equal? (caar out) "Character"))
      (loop (cdr rest) (cons ["Character" (string-append (cadar out) (cadar rest))] (cdr out))))
     (else (loop (cdr rest) (cons (car rest) out))))))

;;; What a test reports when the code under test raises.
(def (raised e) => :string
  (string-append "raised: " (call-with-output-string (cut display-exception e <>))))

(def initial-states
  [["Data state" :: html-state-data]
   ["PLAINTEXT state" :: html-state-plaintext]
   ["RCDATA state" :: html-state-rcdata]
   ["RAWTEXT state" :: html-state-rawtext]
   ["Script data state" :: html-state-script-data]
   ["CDATA section state" :: html-state-cdata]])

;;; The results of the tests of one .test file; a failure is the list
;;; (id description input actual expected).
(def (run-tokenizer-file (dir  : :string)
                         (file : :string)) => FileResults
  (let* ((json (parameterize ((current-json-read-options (JSONReadOptions object-as-hash: #t)))
                 (call-with-input-file (path-expand file dir) read-json)))
         (tests (or (hash-get json "tests") '()))
         (passed 0)
         (skipped (let loop ((k 1) (rest (or (hash-get json "xmlViolationTests") '())) (ids '()))
                    (if (null? rest)
                      (reverse ids)
                      (loop (fx+ k 1) (cdr rest)
                            (cons (string-append file "#x" (number->string k)) ids)))))
         (failures '()))
    (let loop ((rest tests) (k 1))
      (when (pair? rest)
        (let* ((test (car rest))
               (escape (if (equal? (hash-get test "doubleEscaped") #t) unescape values))
               (input (escape (hash-ref test "input")))
               (expected (and input
                              (let (expected (map (cut expected-token <> escape)
                                                  (hash-ref test "output")))
                                (and (not (find (lambda (token)
                                                  (and (not (equal? (car token) "DOCTYPE"))
                                                       (member #f token)))
                                                expected))
                                     expected))))
               (states (or (hash-get test "initialStates") ["Data state"]))
               (id (string-append file "#" (number->string k))))
          (for-each
           (lambda (state-name)
             (let (id (if (pair? (cdr states)) (string-append id " " state-name) id))
               (cond
                ((not expected)
                 (set! skipped (append skipped [id])))
                (else
                 (let (fail! (lambda (actual)
                               (set! failures (cons [id (hash-ref test "description") input actual expected]
                                                    failures))))
                   (with-catch
                    (lambda (e) (fail! (raised e)))
                    (lambda ()
                      (let (actual (tokens input (cdr (assoc state-name initial-states))
                                           (hash-get test "lastStartTag")))
                        (if (equal? (normalize actual) (normalize (merge-characters expected)))
                          (set! passed (fx+ passed 1))
                          (fail! actual))))))))))
           states))
        (loop (cdr rest) (fx+ k 1))))
    (make-FileResults file passed skipped (reverse failures))))

(def (run-tokenizer-tests (dir : :string)) => :boolean
  (let* ((dir (path-expand "tokenizer" dir))
         (results (map (cut run-tokenizer-file dir <>)
                       (sorted-files dir ".test" (lambda (file) #t)))))
    (let-values (((skipped failed)
                  (report "html5lib tokenizer tests" results 20
                          (lambda (failure) (write failure) (newline)))))
      (and (check-skips "html5lib tokenizer tests" tokenizer-skips skipped)
           (zero? failed)))))

;;; tree construction tests

(def (namespace-prefix (uri : :string)) => :string
  (cond
   ((string=? uri svg-namespace-uri) "svg ")
   ((string=? uri mathml-namespace-uri) "math ")
   ((string=? uri xlink-namespace-uri) "xlink ")
   ((string=? uri xml-namespace-uri) "xml ")
   ((string=? uri xmlns-namespace-uri) "xmlns ")
   (else "")))

;;; The lines of nodes (with a DOCTYPE among them in a document), as the
;;; tests write them.
(def (html-tree-dump (nodes : :list)) => :string
  (call-with-output-string
   ""
   (lambda (out)
     (def (line (level : :fixnum) . strings) => :void
       (write-string "| " out)
       (write-string (make-string (* 2 level) #\space) out)
       (for-each (cut write-string <> out) strings)
       (newline out))
     (def (dump (node  : :t)
                (level : :fixnum)) => :void
       (cond
        ((XMLElement? node)
         (using (node :- XMLElement)
           (let* ((uri node.name.uri)
                  (attributes
                   (list-sort (lambda (a b) (string<? (car a) (car b)))
                              (map (lambda ((attr :- XMLAttribute))
                                     (cons (string-append (namespace-prefix attr.name.uri)
                                                          attr.name.local)
                                           attr.value))
                                   node.attributes))))
             (line level "<" (namespace-prefix uri) node.name.local ">")
             (for-each (lambda (attr) (line (+ level 1) (car attr) "=\"" (cdr attr) "\""))
                       attributes)
             (if (and (string=? uri "") (string=? node.name.local "template"))
               (begin
                 (line (+ level 1) "content")
                 (for-each (cut dump <> (+ level 2)) node.children))
               (for-each (cut dump <> (+ level 1)) node.children)))))
        ((XMLText? node) (using (node :- XMLText) (line level "\"" node.data "\"")))
        ((XMLComment? node) (using (node :- XMLComment) (line level "<!-- " node.data " -->")))
        ((XMLPI? node) (using (node :- XMLPI) (line level "<?" node.target " " node.data "?>")))
        ((HTMLDoctype? node)
         (using (node :- HTMLDoctype)
           (let ((public (or node.public-id ""))
                 (system (or node.system-id "")))
             (if (and (string-empty? public) (string-empty? system))
               (line level "<!DOCTYPE " node.name ">")
               (line level "<!DOCTYPE " node.name " \"" public "\" \"" system "\">")))))
        (else (line level "?" (object->string node)))))
     (for-each (cut dump <> 0) nodes))))

;;; A test: its id, data, context (#f for a document, or the html5lib
;;; context such as "td" or "svg desc"), scripting? and expected dump.
(defstruct DatTest
  ((id         :- :string)
   (data       :- :string)
   (context    :? :string)
   (scripting? :- :boolean)
   (expected   :- :string))
  final: #t)

;;; The tests of the .dat file file in dir.
(def (read-dat-file (dir  : :string)
                    (file : :string)) => :list
  (let (lines (call-with-input-file [path: (path-expand file dir) char-encoding: 'UTF-8]
                (lambda (port)
                  (let loop ((out '()))
                    (let (line (read-line port))
                      (if (eof-object? line)
                        (reverse out)
                        (loop (cons line out))))))))
    (let loop ((lines lines) (tests '()) (k 1))
      (cond
       ((null? lines) (reverse tests))
       ((not (equal? (car lines) "#data")) (loop (cdr lines) tests k))
       (else
        (let*-values (((data rest) (take-section (cdr lines)))
                      ((context scripting? rest) (read-options rest #f #t))
                      ((expected rest) (take-document rest)))
          (loop rest
                (cons (make-DatTest (string-append file "#" (number->string k))
                                     (string-join data "\n") context scripting? expected)
                      tests)
                (fx+ k 1))))))))

;;; The lines up to the next line starting with #, and the rest.
(def (take-section (lines : :list)) => :values
  (let loop ((lines lines) (out '()))
    (if (or (null? lines)
            (let (line (car lines))
              (and (fx> (string-length line) 0) (char=? (string-ref line 0) #\#))))
      (values (reverse out) lines)
      (loop (cdr lines) (cons (car lines) out)))))

;;; Reads the sections before #document: errors, fragment context, scripting.
(def (read-options (lines      : :list)
                   (context    :? :string)
                   (scripting? : :boolean)) => :values
  (let (head (car lines))
    (cond
     ((equal? head "#document") (values context scripting? (cdr lines)))
     ((equal? head "#document-fragment")
      (read-options (cddr lines) (string-trim (cadr lines)) scripting?))
     ((equal? head "#script-on")
      (let-values (((_ rest) (take-section (cdr lines))))
        (read-options rest context #t)))
     ((equal? head "#script-off")
      (let-values (((_ rest) (take-section (cdr lines))))
        (read-options rest context #f)))
     (else
      (let-values (((_ rest) (take-section (cdr lines))))
        (read-options rest context scripting?))))))

;;; The expected dump: lines up to an empty line outside a quoted text.
(def (take-document (lines : :list)) => :values
  (let loop ((lines lines) (out '()) (quote? #f))
    (if (or (null? lines) (and (not quote?) (string-empty? (car lines))))
      (values (apply string-append (map (lambda (line) (string-append line "\n")) (reverse out)))
              lines)
      (let* ((line (car lines))
             (bar? (and (fx> (string-length line) 0) (char=? (string-ref line 0) #\|)))
             (trimmed (string-trim (string-trim-prefix "|" line)))
             (n (string-length trimmed))
             (quote? (if (fx= n 0)
                       quote?
                       (let (open? (or quote? (and bar? (char=? (string-ref trimmed 0) #\"))))
                         (if (and (char=? (string-ref trimmed (fx- n 1)) #\")
                                  (not (and bar? (fx= n 1))))
                           #f
                           open?)))))
        (loop (cdr lines) (cons line out) quote?)))))

;;; The context element of an html5lib context: "td", "svg desc", "math mi".
(def (context-element (context : :string)) => :t
  (let (space (string-index context #\space))
    (if space
      (make-xml-element (make-xml-name (substring context (fx+ space 1) (string-length context))
                                       (if (equal? (substring context 0 space) "svg")
                                         svg-namespace-uri
                                         mathml-namespace-uri)
                                       "")
                        [] [])
      context)))

;;; The tree of str read as the test reads its data: as a document or a
;;; fragment.
(def (read-test (test : DatTest)
                (str  : :string)) => :t
  (if test.context
    (read-html-fragment str context: (context-element test.context)
                        scripting?: test.scripting?)
    (read-html str scripting?: test.scripting?)))

(def (tree-nodes (tree : :t)) => :list
  (if (HTMLDocument? tree)
    (using (doc tree :- HTMLDocument) doc.children)
    tree))

(def (actual-dump (test : DatTest)) => :string
  (html-tree-dump (tree-nodes (read-test test test.data))))

;;; Why write-html rejects the tree of test, or #f.
(def (rejection-reason (test : DatTest)) => (Maybe :string)
  (or (and (member test.data open-double-escaped-scripts)
           "script ends at end of input in the double escaped state")
      (let loop ((rest writer-rejections))
        (and (pair? rest)
             (if (find (lambda (entry)
                         (and (equal? (car entry) test.data)
                              (equal? (cadr entry) test.context)
                              (or (eq? (caddr entry) 'any)
                                  (eq? (caddr entry) test.scripting?))))
                       (cdar rest))
               (caar rest)
               (loop (cdr rest)))))))

;;; The dump of the test's tree after writing it with write-html and
;;; reading the output again in the same way; for the trees write-html
;;; rejects, the expected dump when it raises ContractViolation.
(def (round-trip-dump (test : DatTest)) => :string
  (if (rejection-reason test)
    (if (with-catch contract-violation-error?
                    (lambda ()
                      (html->string (read-test test test.data) scripting?: test.scripting?)
                      #f))
      test.expected
      "write-html did not raise ContractViolation")
    (html-tree-dump
     (tree-nodes (read-test test (html->string (read-test test test.data)
                                               scripting?: test.scripting?))))))

;;; A tree construction or round trip test that failed: the dump expected and
;;; the actual one.
(defstruct TreeFailure
  ((id       :- :string)
   (data     :- :string)
   (context  :? :string)
   (expected :- :string)
   (actual   :- :string))
  final: #t)

;;; The results of the tests of one .dat file with dump, skipping the tests
;;; in skips; a listed test whose data differs fails.
(def (run-dat-file (tests : :list)
                   (file  : :string)
                   (dump  : :procedure)
                   (skips : :list)) => FileResults
  (let loop ((rest tests) (passed 0) (skipped '()) (failures '()))
    (if (null? rest)
      (make-FileResults file passed (reverse skipped) (reverse failures))
      (using (test (car rest) :- DatTest)
        (let (listed (find (lambda (entry) (equal? (car entry) test.id))
                           (apply append (map cdr skips))))
          (cond
           ((and listed (equal? (cadr listed) test.data))
            (loop (cdr rest) passed (cons test.id skipped) failures))
           (listed
            (loop (cdr rest) passed skipped
                  (cons (make-TreeFailure test.id test.data test.context
                                           "listed as skipped with other data" (cadr listed))
                        failures)))
           (else
            (let (actual (with-catch raised (lambda () (dump test))))
              (if (equal? actual test.expected)
                (loop (cdr rest) (fx+ passed 1) skipped failures)
                (loop (cdr rest) passed skipped
                      (cons (make-TreeFailure test.id test.data test.context test.expected
                                               actual)
                            failures)))))))))))

(def (show-tree-failure (failure : TreeFailure)) => :void
  (displayln "--- " failure.id " context " failure.context)
  (write failure.data)
  (newline)
  (displayln "expected:")
  (display failure.expected)
  (displayln "actual:")
  (display failure.actual)
  (newline))

(def (run-tree-stage (label : :string)
                     (files : :list)
                     (dump  : :procedure)
                     (skips : :list)) => :boolean
  (let-values (((skipped failed)
                (report label
                        (map (lambda (file+tests) (run-dat-file (cdr file+tests) (car file+tests)
                                                                dump skips))
                             files)
                        10 show-tree-failure)))
    (and (check-skips label skips skipped)
         (zero? failed))))

(def (run-tree-tests (wpt : :string)) => :boolean
  (let* ((dir (path-expand "html/syntax/parsing/resources" wpt))
         (files (map (lambda (file) (cons file (read-dat-file dir file)))
                     (sorted-files dir ".dat" (lambda (file) (not (string-prefix? "scripted_" file))))))
         (tree-ok? (run-tree-stage "tree construction tests" files actual-dump tree-skips))
         (round-trip-ok? (run-tree-stage "write-html round trip" files round-trip-dump
                                         round-trip-skips)))
    (and tree-ok? round-trip-ok?)))

(def (main (html5lib-tests : :string)
           (wpt            : :string)) => :void
  (let* ((tokenizer-ok? (run-tokenizer-tests html5lib-tests))
         (tree-ok? (run-tree-tests wpt)))
    (exit (if (and tokenizer-ok? tree-ok?) 0 1))))
