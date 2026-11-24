;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Test support for :std/cli/multicall tests: a module using define-multicall-main.
;;; Importing it from multicall-test.ss makes a macro that fails to expand
;;; fail the test at load time. Not in build-spec: the test imports it by string path, from source.
(import :std/cli/multicall)
(export main)

(define-multicall-main)
