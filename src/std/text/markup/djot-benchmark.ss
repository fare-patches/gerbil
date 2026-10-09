;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import ./djot)
(export main)
(extern namespace: #f time)

;;; Time only the repeated operation; input preparation happens in main.
(def (benchmark (operation  : :procedure)
                (iterations : :fixnum)) => :void
  (##gc)
  (time
    (let loop ((i 0 : :fixnum)) => :void
      (when (fx< i iterations)
        (operation)
        (loop (fx+ i 1))))))

;;; With this checkout's stdlib built, compile from its root:
;;; gxc -O -exe -o /tmp/djot-benchmark src/std/text/markup/djot-benchmark.ss
;;; Use ./run.sh gxc instead of gxc in a local build environment.
;;; Usage: /tmp/djot-benchmark MODE FILE ITERATIONS (positive fixnum count).
;;; Modes: parse = preloaded text to AST; render = pre-parsed AST to HTML via SXML;
;;; full = preloaded text to HTML; read+parse = read whole file/decode/parse each time.
(def (main (mode       : :string)
           (path       : :string)
           (iterations : :string)) => :void
  (let (count (string->number iterations))
    (unless (and (fixnum? count) (fx> count 0))
      (error "Expected a positive fixnum iteration count" iterations))
    (case mode
      (("read+parse")
       (benchmark
         (lambda () => djot-document
           (string->djot (utf8->string (read-file-u8vector path))))
         count))
      (("parse" "render" "full")
       (let (input (utf8->string (read-file-u8vector path)))
         (case mode
           (("parse")
            (benchmark (lambda () => djot-document (string->djot input)) count))
           (("render")
            (let (document (string->djot input))
              (benchmark (lambda () => :string (djot->html document)) count)))
           (("full")
            (benchmark (lambda () => :string (djot->html (string->djot input))) count)))))
      (else
       (error "Expected parse, render, full or read+parse" mode)))))
