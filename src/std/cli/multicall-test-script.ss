;;; A multicall script run by multicall-test.ss through gxi.
(import :std/cli/multicall :std/cli/getopt :std/source)
(export main)

;; current-program holds invocation components in reverse order.
(current-program [(this-source-file) (car (command-line))])
(register-entry-point void name: "tree" getopt: [(command 'group (command 'leaf))])
(define-multicall-main)
