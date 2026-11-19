;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Typed keyword arguments combined with rest arguments (interpreted).
;;; The compiled variant of the same fixture runs in compiler-test.ss
;;; (compiler-typed-test, "typed keyword + rest arguments, compiled").
(import :std/test
        "compiler-test-support/typed-keyword-rest")
(export typed-keyword-test)

(def typed-keyword-test
  (test-suite "typed keyword arguments with rest"
    (test-case "untyped control" (check-untyped-control))
    (test-case "typed keyword + rest, keyword first" (check-typed-keyword-rest))
    (test-case "typed keyword + rest, keyword after positional"
      (check-typed-keyword-after-positional))
    (test-case "several typed keywords + rest" (check-typed-keywords-rest))
    (test-case "typed positional + typed keyword + rest"
      (check-typed-positional-keyword-rest))
    (test-case "keyword objects escaped to positionals"
      (check-typed-keyword-escapes))))
