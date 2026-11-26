;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/text/glob tests
(import :std/test
        :std/text/pregexp
        ./glob)
(export glob-test)

(def (check-glob pattern table)
  (for-each
   (lambda (entry)
     (check (glob-match? pattern (car entry)) => (cdr entry)))
   table))

(def glob-test
  (test-suite "test :std/text/glob"
    (test-case "short wildcard patterns agree with pregexp"
      ;; The only literals are a and b, and dot matches every input character.
      (def (visit-strings alphabet limit proc)
        (let walk ((s ""))
          (proc s)
          (when (< (string-length s) limit)
            (for-each (lambda (c) (walk (string-append s (string c)))) alphabet))))
      (visit-strings '(#\a #\b #\* #\?) 4
        (lambda (pattern)
          (let* ((pieces (map (lambda (c)
                                (case c ((#\*) ".*") ((#\?) ".") (else (string c))))
                              (string->list pattern)))
                 (rx (pregexp (string-append "^" (apply string-append pieces) "$"))))
            (visit-strings '(#\a #\b) 4
              (lambda (s)
                (check (list pattern s (glob-match? pattern s))
                       => (list pattern s (and (pregexp-match rx s) #t)))))))))

    (test-case "many ambiguous stars before a missing suffix"
      (check (glob-match? "*a*a*a*a*a*a*a*a*b" (make-string 10000 #\a)) => #f))

    (test-case "empty pattern and lone wildcards"
      (check-glob "" '(("" . #t) ("a" . #f) (" " . #f) ("\n" . #f)))
      (check-glob "*" '(("" . #t) ("a" . #t) ("abc" . #t) ("a/b/c" . #t) (".x" . #t)
                        ("\n" . #t) ("a\nb\n" . #t) ("*" . #t)))
      (check-glob "?" '(("" . #f) ("a" . #t) ("?" . #t) ("\n" . #t) ("/" . #t) ("." . #t)
                        ("ab" . #f)))
      (check-glob "??" '(("" . #f) ("a" . #f) ("ab" . #t) ("abc" . #f)))
      (check-glob "**" '(("" . #t) ("a" . #t) ("abc" . #t) ("a\nb" . #t))))

    (test-case "anchoring: prefix, suffix, infix stars"
      (check-glob "abc" '(("abc" . #t) ("" . #f) ("ab" . #f) ("abcd" . #f)
                          ("xabc" . #f) ("xabcx" . #f)))
      (check-glob "ab*" '(("ab" . #t) ("abc" . #t) ("ab\nc" . #t)
                          ("a" . #f) ("xab" . #f) ("xabc" . #f)))
      (check-glob "*ab" '(("ab" . #t) ("xab" . #t) ("x\nab" . #t)
                          ("abx" . #f) ("b" . #f)))
      (check-glob "*ab*" '(("ab" . #t) ("xaby" . #t) ("xxabyy" . #t)
                           ("aXb" . #f) ("ba" . #f) ("" . #f)))
      (check-glob "a*c" '(("ac" . #t) ("abc" . #t) ("abbbc" . #t) ("a/b/c" . #t)
                          ("ab" . #f) ("abcd" . #f) ("xac" . #f)))
      (check-glob "a**c" '(("ac" . #t) ("abc" . #t) ("abbbc" . #t) ("ab" . #f))))

    (test-case "backtracking and mixed wildcards"
      (check-glob "a*b*c" '(("abc" . #t) ("aXbYbc" . #t) ("abbc" . #t)
                            ("abcbc" . #t) ("aXcb" . #f) ("acb" . #f) ("ab" . #f)))
      (check-glob "?*?" '(("" . #f) ("a" . #f) ("ab" . #t) ("abc" . #t)
                          ("abcdefgh" . #t) ("\n\n" . #t)))
      (check-glob "a?c" '(("abc" . #t) ("a\nc" . #t) ("ac" . #f) ("abbc" . #f)))
      (check-glob "*?" '(("" . #f) ("a" . #t) ("ab" . #t)))
      (check-glob "?*" '(("" . #f) ("a" . #t) ("ab" . #t))))

    (test-case "only star and question mark are wildcards"
      (check-glob "a.c" '(("a.c" . #t) ("abc" . #f) ("a\nc" . #f)))
      (check-glob "1+1" '(("1+1" . #t) ("11" . #f) ("111" . #f)))
      (check-glob "(x)" '(("(x)" . #t) ("x" . #f)))
      (check-glob "a|b" '(("a|b" . #t) ("a" . #f) ("b" . #f)))
      (check-glob "^$" '(("^$" . #t) ("" . #f)))
      (check-glob "\\d" '(("\\d" . #t) ("d" . #f) ("1" . #f)))
      (check-glob "\\" '(("\\" . #t) ("" . #f)))
      (check-glob "a\\*" '(("a\\" . #t) ("a\\xyz" . #t) ("a*" . #f) ("a" . #f)))
      (check-glob "[ab]" '(("[ab]" . #t) ("a" . #f) ("b" . #f)))
      (check-glob "[!a]" '(("[!a]" . #t) ("b" . #f)))
      (check-glob "{a,b}" '(("{a,b}" . #t) ("a" . #f) ("b" . #f)))
      (check-glob "a{2}" '(("a{2}" . #t) ("aa" . #f)))
      (check-glob "x]y}z" '(("x]y}z" . #t)))
      (check-glob "a?b" '(("a?b" . #t) ("aXb" . #t) ("ab" . #f)))
      ;; Match a run of literal punctuation between wildcards.
      (let (meta ".+()^$|[]{}\\")
        (check-glob (string-append "*" meta "*")
                    (list (cons meta #t)
                          (cons (string-append "x" meta "y") #t)
                          (cons ".+()^$|[]{}" #f)
                          (cons "" #f)))))

    (test-case "newlines"
      (check-glob "a\nb" '(("a\nb" . #t) ("ab" . #f) ("a\n\nb" . #f)))
      (check-glob "a*b" '(("a\nb" . #t) ("a\n\n\nb" . #t) ("a\nb\n" . #f)))
      (check-glob "*\n" '(("\n" . #t) ("abc\n" . #t) ("abc" . #f) ("abc\nx" . #f))))

    (test-case "case sensitivity"
      (check-glob "ABC" '(("ABC" . #t) ("abc" . #f) ("Abc" . #f)))
      (check-glob "a*" '(("abc" . #t) ("ABC" . #f))))

    (test-case "non-ASCII characters"
      (check-glob "é*" '(("é" . #t) ("école" . #t) ("café" . #f) ("e" . #f)))
      (check-glob "*é" '(("café" . #t) ("é" . #t) ("école" . #f) ("cafe" . #f)))
      (check-glob "caf?" '(("café" . #t) ("cafe" . #t) ("caf" . #f)))
      (check-glob "λ?λ" '(("λxλ" . #t) ("λλλ" . #t) ("λλ" . #f))))

    (test-case "pathological backtracking terminates"
      (check-function glob-match?
        "*a*a*a*a*b" (make-string 30 #\a) => #f
        "*a*a*a*a*a" (make-string 30 #\a) => #t
        "*a*a*a*a*b" (string-append (make-string 30 #\a) "b") => #t
        "*?*?*?*?*x" (make-string 30 #\y) => #f))))
